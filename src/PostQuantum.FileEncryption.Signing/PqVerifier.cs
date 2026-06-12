using System.Security.Cryptography;
using PostQuantum.FileEncryption.Internal;
using PostQuantum.FileEncryption.Signing.Internal;

namespace PostQuantum.FileEncryption.Signing;

/// <summary>
/// Verifies detached Ed25519 + ML-DSA-65 hybrid signatures produced by <see cref="PqSigner"/>.
/// Fail-closed: every method either returns on full success or throws — a structurally invalid
/// signature raises <see cref="PqFormatException"/>, and any cryptographic mismatch raises
/// <see cref="PqSignatureException"/> with one generic message (no oracle for which component
/// failed, or why). Instances are immutable and thread-safe.
/// </summary>
public sealed class PqVerifier
{
    /// <summary>
    /// Verifies the file at <paramref name="inputPath"/> against the detached signature at
    /// <paramref name="signaturePath"/>.
    /// </summary>
    /// <exception cref="PqFormatException">The signature file is not a recognizable detached signature.</exception>
    /// <exception cref="PqSignatureException">The signature does not verify.</exception>
    public async Task VerifyFileAsync(
        string inputPath, string signaturePath, PqSigningPublicKey publicKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(signaturePath);
        ArgumentNullException.ThrowIfNull(publicKey);

        // The length check bounds the read before any allocation sized by untrusted input.
        byte[] signature;
        await using (var sigStream = FileIo.OpenRead(signaturePath))
        {
            if (sigStream.Length != HybridSigning.SignatureLength)
            {
                throw new PqFormatException("Not a recognizable detached signature (wrong length).");
            }
            signature = new byte[HybridSigning.SignatureLength];
            await sigStream.ReadExactlyAsync(signature, cancellationToken).ConfigureAwait(false);
        }

        await using var input = FileIo.OpenRead(inputPath);
        await VerifyAsync(input, signature, publicKey, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Verifies <paramref name="input"/> (read to its end) against a detached signature.</summary>
    /// <exception cref="PqFormatException">The signature is not a recognizable detached signature.</exception>
    /// <exception cref="PqSignatureException">The signature does not verify.</exception>
    public async Task VerifyAsync(
        Stream input, ReadOnlyMemory<byte> signature, PqSigningPublicKey publicKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(publicKey);

        byte[] digest = await SHA512.HashDataAsync(input, cancellationToken).ConfigureAwait(false);
        HybridSigning.Verify(digest, signature.Span, publicKey);
    }

    /// <summary>Verifies an in-memory buffer against a detached signature.</summary>
    /// <exception cref="PqFormatException">The signature is not a recognizable detached signature.</exception>
    /// <exception cref="PqSignatureException">The signature does not verify.</exception>
    public void VerifyBytes(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, PqSigningPublicKey publicKey)
    {
        ArgumentNullException.ThrowIfNull(publicKey);

        byte[] digest = SHA512.HashData(data);
        HybridSigning.Verify(digest, signature, publicKey);
    }
}
