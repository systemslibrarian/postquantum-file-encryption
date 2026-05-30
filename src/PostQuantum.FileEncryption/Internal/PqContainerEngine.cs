using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// The cryptographic core shared by <see cref="PqFileEncryptor"/> and
/// <see cref="PqFileDecryptor"/>. It reads and writes the chunked, authenticated container
/// described in <c>docs/FILE-FORMAT.md</c>, operating on a content key that has already been
/// established (by passphrase KDF or by ML-KEM recipient unwrap — see <see cref="KeyEstablishment"/>).
/// </summary>
/// <remarks>
/// Each chunk is sealed independently with AES-256-GCM. The nonce is the header's random
/// 4-byte prefix concatenated with an 8-byte big-endian chunk counter, which guarantees a
/// unique nonce per chunk under the single per-file key. Each chunk's additional
/// authenticated data is <c>header || counter || frameType</c>, which binds the chunk to its
/// position and to the final-chunk marker — defeating reordering, splicing, and truncation.
/// Decryption is only considered complete once the chunk marked
/// <see cref="ContainerFormat.FrameFinal"/> authenticates.
/// <para>
/// This type is the single seam where a future release will delegate to the lower-level
/// PostQuantum.FileFormat package (see <see cref="IPqContainerCodec"/>); today it is the only
/// implementation.
/// </para>
/// </remarks>
internal static class PqContainerEngine
{
    private static void BuildNonce(ReadOnlySpan<byte> noncePrefix, ulong counter, Span<byte> nonce)
    {
        noncePrefix.CopyTo(nonce);
        BinaryPrimitives.WriteUInt64BigEndian(nonce[ContainerFormat.NoncePrefixLength..], counter);
    }

    private static byte[] BuildAad(byte[] headerBytes, ulong counter, byte frameType)
    {
        var aad = new byte[headerBytes.Length + sizeof(ulong) + 1];
        headerBytes.CopyTo(aad, 0);
        BinaryPrimitives.WriteUInt64BigEndian(aad.AsSpan(headerBytes.Length), counter);
        aad[^1] = frameType;
        return aad;
    }

    /// <summary>
    /// Encrypts <paramref name="source"/> into the container written to <paramref name="destination"/>,
    /// using a content key and header produced by <see cref="KeyEstablishment"/>. The content key
    /// is zeroed before returning.
    /// </summary>
    public static async Task EncryptCoreAsync(
        Stream source,
        Stream destination,
        byte[] contentKey,
        ContainerHeader header,
        long? totalBytes,
        IProgress<PqProgress>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            using var aes = new AesGcm(contentKey, ContainerFormat.TagLength);

            await destination.WriteAsync(header.HeaderBytes, cancellationToken).ConfigureAwait(false);

            // Two plaintext buffers let us read one chunk ahead, so we always know whether the
            // chunk we are about to seal is the final one. ReadAtMostAsync only returns a short
            // count at end-of-stream, so a partial fill reliably means "no more data".
            byte[] current = new byte[header.ChunkSize];
            byte[] next = new byte[header.ChunkSize];
            byte[] ciphertext = new byte[header.ChunkSize];
            byte[] tag = new byte[ContainerFormat.TagLength];
            byte[] nonce = new byte[ContainerFormat.NonceLength];
            byte[] frameHeader = new byte[5]; // 1 byte frame type + 4 byte length

            ulong counter = 0;
            long processed = 0;
            int filled = await ReadAtMostAsync(source, current, cancellationToken).ConfigureAwait(false);

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // A full chunk might still be the last one, so look ahead to be certain.
                int nextFilled = filled == current.Length
                    ? await ReadAtMostAsync(source, next, cancellationToken).ConfigureAwait(false)
                    : 0;
                bool isFinal = nextFilled == 0;
                byte frameType = isFinal ? ContainerFormat.FrameFinal : ContainerFormat.FrameData;

                BuildNonce(header.NoncePrefix, counter, nonce);
                byte[] aad = BuildAad(header.HeaderBytes, counter, frameType);
                aes.Encrypt(nonce, current.AsSpan(0, filled), ciphertext.AsSpan(0, filled), tag, aad);

                frameHeader[0] = frameType;
                BinaryPrimitives.WriteUInt32BigEndian(frameHeader.AsSpan(1), (uint)filled);
                await destination.WriteAsync(frameHeader, cancellationToken).ConfigureAwait(false);
                await destination.WriteAsync(ciphertext.AsMemory(0, filled), cancellationToken).ConfigureAwait(false);
                await destination.WriteAsync(tag, cancellationToken).ConfigureAwait(false);

                processed += filled;
                progress?.Report(new PqProgress(processed, totalBytes));
                counter++;

                if (isFinal)
                {
                    break;
                }

                // Swap buffers: the looked-ahead chunk becomes the current one.
                (current, next) = (next, current);
                filled = nextFilled;
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentKey);
        }
    }

    /// <summary>
    /// Decrypts the body of a container (the caller has already read and parsed
    /// <paramref name="header"/>) into <paramref name="destination"/>, using
    /// <paramref name="contentKey"/>. The content key is zeroed before returning.
    /// </summary>
    public static async Task DecryptCoreAsync(
        Stream source,
        Stream destination,
        byte[] contentKey,
        ContainerHeader header,
        long? totalCiphertextBytes,
        IProgress<PqProgress>? progress,
        CancellationToken cancellationToken)
    {
        try
        {
            using var aes = new AesGcm(contentKey, ContainerFormat.TagLength);

            byte[] ciphertext = new byte[header.ChunkSize];
            byte[] plaintext = new byte[header.ChunkSize];
            byte[] tag = new byte[ContainerFormat.TagLength];
            byte[] nonce = new byte[ContainerFormat.NonceLength];
            byte[] frameHeader = new byte[5];

            ulong counter = 0;
            long processed = 0;
            bool sawFinal = false;

            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();

                int headerRead = await ReadAtMostAsync(source, frameHeader, cancellationToken).ConfigureAwait(false);
                if (headerRead == 0)
                {
                    break; // clean EOF — valid only if we have already authenticated a final frame
                }
                if (headerRead != frameHeader.Length)
                {
                    throw new PqDecryptionException("Container is truncated inside a frame header.");
                }

                byte frameType = frameHeader[0];
                if (frameType is not (ContainerFormat.FrameData or ContainerFormat.FrameFinal))
                {
                    throw new PqDecryptionException("Container contains an unrecognized frame marker.");
                }

                uint length = BinaryPrimitives.ReadUInt32BigEndian(frameHeader.AsSpan(1));
                if (length > (uint)header.ChunkSize)
                {
                    throw new PqDecryptionException("Container declares a frame larger than its chunk size.");
                }

                if (await ReadExactAsync(source, ciphertext.AsMemory(0, (int)length), cancellationToken).ConfigureAwait(false) != length ||
                    await ReadExactAsync(source, tag, cancellationToken).ConfigureAwait(false) != tag.Length)
                {
                    throw new PqDecryptionException("Container is truncated inside a frame body.");
                }

                BuildNonce(header.NoncePrefix, counter, nonce);
                byte[] aad = BuildAad(header.HeaderBytes, counter, frameType);

                try
                {
                    // AES-GCM verifies the tag before producing any plaintext; on mismatch it
                    // throws and writes nothing, so corrupt data never reaches `destination`.
                    aes.Decrypt(nonce, ciphertext.AsSpan(0, (int)length), tag, plaintext.AsSpan(0, (int)length), aad);
                }
                catch (AuthenticationTagMismatchException ex)
                {
                    throw new PqDecryptionException(
                        "Decryption failed: the key is wrong, or the data has been altered or corrupted.", ex);
                }

                await destination.WriteAsync(plaintext.AsMemory(0, (int)length), cancellationToken).ConfigureAwait(false);

                processed += (int)length;
                progress?.Report(new PqProgress(processed, totalCiphertextBytes));
                counter++;

                if (frameType == ContainerFormat.FrameFinal)
                {
                    sawFinal = true;
                    break;
                }
            }

            if (!sawFinal)
            {
                // No authenticated final frame ⇒ the container was truncated. Fail closed.
                throw new PqDecryptionException("Container is incomplete: no authenticated final frame was found.");
            }

            await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(contentKey);
        }
    }

    /// <summary>Reads and validates the container header from <paramref name="source"/>.</summary>
    public static async Task<ContainerHeader> ReadHeaderAsync(Stream source, CancellationToken cancellationToken)
    {
        byte[] fixedPart = new byte[ContainerFormat.FixedHeaderLength];
        if (await ReadExactAsync(source, fixedPart, cancellationToken).ConfigureAwait(false) != fixedPart.Length)
        {
            throw new PqFormatException("Input is too short to be a PostQuantum.FileEncryption container.");
        }

        int keyParamsLength = BinaryPrimitives.ReadUInt16BigEndian(fixedPart.AsSpan(ContainerFormat.OffsetKeyParamsLength));
        byte[] full = new byte[ContainerFormat.FixedHeaderLength + keyParamsLength];
        fixedPart.CopyTo(full, 0);
        if (keyParamsLength > 0 &&
            await ReadExactAsync(source, full.AsMemory(ContainerFormat.FixedHeaderLength), cancellationToken).ConfigureAwait(false) != keyParamsLength)
        {
            throw new PqFormatException("Container header is truncated inside its key-parameters block.");
        }

        return ContainerHeader.Parse(full);
    }

    /// <summary>Reads up to <paramref name="buffer"/>.Length bytes, looping past short reads until full or EOF.</summary>
    private static async Task<int> ReadAtMostAsync(Stream source, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = await source.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total += read;
        }
        return total;
    }

    private static Task<int> ReadExactAsync(Stream source, Memory<byte> buffer, CancellationToken cancellationToken) =>
        ReadAtMostAsync(source, buffer, cancellationToken);
}
