using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// On-disk constants and the extensible header for the PostQuantum.FileEncryption v2 container.
/// See <c>docs/FILE-FORMAT.md</c> for the authoritative specification.
/// </summary>
internal static class ContainerFormat
{
    /// <summary>ASCII "PQFE" — identifies the container and is the first bytes on disk.</summary>
    public static ReadOnlySpan<byte> Magic => "PQFE"u8;

    public const byte FormatVersion = 2;

    public const byte AeadAes256Gcm = 1;

    // How the per-file content key is established. The variable KeyParams block is interpreted
    // according to this value.
    public const byte KeySourcePassphrase = 1;     // KeyParams describe a KDF over a passphrase
    public const byte KeySourceMlKemRecipient = 2;  // KeyParams carry an ML-KEM-wrapped content key

    // KDF identifiers (used inside passphrase KeyParams).
    public const byte KdfPbkdf2HmacSha256 = 1;
    public const byte KdfArgon2id = 2;

    // KEM identifiers (used inside recipient KeyParams).
    public const byte KemMlKem768 = 1;

    public const int NoncePrefixLength = 4; // random per file; the rest of the nonce is a counter
    public const int NonceLength = 12;       // AES-GCM standard nonce length
    public const int TagLength = 16;         // AES-GCM 128-bit authentication tag
    public const int KeyLength = 32;         // AES-256 content key length

    // Frame markers, authenticated as additional data so they cannot be flipped undetected.
    public const byte FrameData = 0;  // a non-final chunk; more frames follow
    public const byte FrameFinal = 1; // the last chunk; decryption is only complete after one is seen

    // Fixed header layout (offsets in bytes). The variable KeyParams block follows.
    public const int OffsetMagic = 0;            // 4 bytes
    public const int OffsetFormatVersion = 4;    // 1 byte
    public const int OffsetAeadId = 5;           // 1 byte
    public const int OffsetKeySource = 6;        // 1 byte
    public const int OffsetFlags = 7;            // 1 byte (reserved, must be 0)
    public const int OffsetChunkSize = 8;        // 4 bytes, big-endian uint32
    public const int OffsetNoncePrefix = 12;     // 4 bytes
    public const int OffsetKeyParamsLength = 16;  // 2 bytes, big-endian uint16
    public const int FixedHeaderLength = 18;     // KeyParams follow immediately

    public const int MaxKeyParamsLength = ushort.MaxValue;
}

/// <summary>
/// The parsed container header. The <em>serialized</em> form (<see cref="HeaderBytes"/>) is
/// bound into every chunk's additional authenticated data, so any change to the key
/// establishment parameters or chunk size is detected as an authentication failure.
/// </summary>
internal sealed record ContainerHeader(
    byte KeySource,
    int ChunkSize,
    byte[] NoncePrefix,
    byte[] KeyParams,
    byte[] HeaderBytes)
{
    /// <summary>
    /// Builds a header for a new container and serializes it. <paramref name="noncePrefixOverride"/>
    /// is for deterministic conformance tests only; production callers pass <see langword="null"/>
    /// to get a fresh random prefix.
    /// </summary>
    public static ContainerHeader Create(byte keySource, int chunkSize, byte[] keyParams, byte[]? noncePrefixOverride = null)
    {
        if (keyParams.Length > ContainerFormat.MaxKeyParamsLength)
        {
            throw new ArgumentException("Key parameters block is too large for the container header.", nameof(keyParams));
        }

        var noncePrefix = noncePrefixOverride ?? RandomNumberGenerator.GetBytes(ContainerFormat.NoncePrefixLength);
        var bytes = new byte[ContainerFormat.FixedHeaderLength + keyParams.Length];
        var span = bytes.AsSpan();

        ContainerFormat.Magic.CopyTo(span[ContainerFormat.OffsetMagic..]);
        span[ContainerFormat.OffsetFormatVersion] = ContainerFormat.FormatVersion;
        span[ContainerFormat.OffsetAeadId] = ContainerFormat.AeadAes256Gcm;
        span[ContainerFormat.OffsetKeySource] = keySource;
        span[ContainerFormat.OffsetFlags] = 0;
        BinaryPrimitives.WriteUInt32BigEndian(span[ContainerFormat.OffsetChunkSize..], (uint)chunkSize);
        noncePrefix.CopyTo(span[ContainerFormat.OffsetNoncePrefix..]);
        BinaryPrimitives.WriteUInt16BigEndian(span[ContainerFormat.OffsetKeyParamsLength..], (ushort)keyParams.Length);
        keyParams.CopyTo(span[ContainerFormat.FixedHeaderLength..]);

        return new ContainerHeader(keySource, chunkSize, noncePrefix, keyParams, bytes);
    }

    /// <summary>
    /// Parses and validates a header already read into <paramref name="fixedAndParams"/>.
    /// Throws <see cref="PqFormatException"/> for anything structurally wrong.
    /// </summary>
    public static ContainerHeader Parse(byte[] fixedAndParams)
    {
        var span = fixedAndParams.AsSpan();

        if (!span[..ContainerFormat.Magic.Length].SequenceEqual(ContainerFormat.Magic))
        {
            throw new PqFormatException("Input is not a PostQuantum.FileEncryption container (bad magic bytes).");
        }

        byte version = span[ContainerFormat.OffsetFormatVersion];
        if (version != ContainerFormat.FormatVersion)
        {
            throw new PqFormatException($"Unsupported container format version {version}; this build understands version {ContainerFormat.FormatVersion}.");
        }

        byte aeadId = span[ContainerFormat.OffsetAeadId];
        if (aeadId != ContainerFormat.AeadAes256Gcm)
        {
            throw new PqFormatException($"Unsupported AEAD identifier {aeadId}.");
        }

        byte keySource = span[ContainerFormat.OffsetKeySource];
        if (keySource is not (ContainerFormat.KeySourcePassphrase or ContainerFormat.KeySourceMlKemRecipient))
        {
            throw new PqFormatException($"Unsupported key-source identifier {keySource}.");
        }

        long chunkSize = BinaryPrimitives.ReadUInt32BigEndian(span[ContainerFormat.OffsetChunkSize..]);
        if (chunkSize < PqEncryptionOptions.MinChunkSizeBytes || chunkSize > PqEncryptionOptions.MaxChunkSizeBytes)
        {
            throw new PqFormatException($"Container declares an out-of-range chunk size of {chunkSize} bytes.");
        }

        var noncePrefix = span.Slice(ContainerFormat.OffsetNoncePrefix, ContainerFormat.NoncePrefixLength).ToArray();
        int keyParamsLength = BinaryPrimitives.ReadUInt16BigEndian(span[ContainerFormat.OffsetKeyParamsLength..]);
        if (ContainerFormat.FixedHeaderLength + keyParamsLength != fixedAndParams.Length)
        {
            throw new PqFormatException("Container header length does not match its declared key-parameters length.");
        }

        var keyParams = span[ContainerFormat.FixedHeaderLength..].ToArray();
        return new ContainerHeader(keySource, (int)chunkSize, noncePrefix, keyParams, fixedAndParams);
    }
}
