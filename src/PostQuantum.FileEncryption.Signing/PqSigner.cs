using System.Security.Cryptography;
using PostQuantum.FileEncryption.Internal;
using PostQuantum.FileEncryption.Signing.Internal;

namespace PostQuantum.FileEncryption.Signing;

/// <summary>
/// Produces detached Ed25519 + ML-DSA-65 hybrid signatures over files, streams, and in-memory
/// buffers — typically over a finished <c>.pqfe</c> container, adding sender authenticity on
/// top of the container's tamper protection. The content is pre-hashed with streaming SHA-512,
/// so signing runs in constant memory for inputs of any size. Instances are immutable and
/// thread-safe.
/// </summary>
/// <remarks>
/// A detached signature proves <em>who signed the bytes</em>; it does not bind the signature to
/// the file's name or location, and anyone able to read the bytes could discard the signature
/// and sign them with their own key. Distribute the verification public key over a trusted
/// channel. See docs/SIGNATURE-FORMAT.md and KNOWN-GAPS.md.
/// </remarks>
public sealed class PqSigner
{
    /// <summary>
    /// Signs the file at <paramref name="inputPath"/> and writes the detached signature to
    /// <paramref name="signaturePath"/> (conventionally <c>inputPath + ".sig"</c>). The
    /// signature file is written atomically via a sibling temp file.
    /// </summary>
    public async Task SignFileAsync(
        string inputPath, string signaturePath, PqSigningPrivateKey privateKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(signaturePath);
        ArgumentNullException.ThrowIfNull(privateKey);

        byte[] signature;
        await using (var input = FileIo.OpenRead(inputPath))
        {
            signature = await SignAsync(input, privateKey, cancellationToken).ConfigureAwait(false);
        }

        await FileIo.WriteViaTempAsync(signaturePath, output =>
            output.WriteAsync(signature, 0, signature.Length, cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>Signs <paramref name="input"/> (read to its end) and returns the detached signature bytes.</summary>
    public async Task<byte[]> SignAsync(
        Stream input, PqSigningPrivateKey privateKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(privateKey);

        byte[] digest = await SHA512.HashDataAsync(input, cancellationToken).ConfigureAwait(false);
        return HybridSigning.Sign(digest, privateKey);
    }

    /// <summary>Signs an in-memory buffer and returns the detached signature bytes.</summary>
    public byte[] SignBytes(ReadOnlySpan<byte> data, PqSigningPrivateKey privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);

        byte[] digest = SHA512.HashData(data);
        return HybridSigning.Sign(digest, privateKey);
    }
}
