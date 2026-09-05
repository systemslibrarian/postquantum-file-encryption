using System.Security.Cryptography;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// Canonical public-key fingerprints: <c>pqfp1:</c> followed by the URL-safe, unpadded Base64
/// of SHA-256 over a domain prefix, a one-byte purpose tag, and the exported key bytes. The
/// purpose tag (mirroring the PQKF key types) domain-separates recipient keys from signing
/// keys, so keys with related bytes can never share a fingerprint across purposes. The
/// rendering is a compatibility surface — people write these down, pin them in configuration,
/// and read them to each other over the phone — so it must never change within a version
/// prefix; a different construction gets a new <c>pqfpN:</c> prefix.
/// </summary>
internal static class Fingerprint
{
    /// <summary>Hybrid recipient public key (X25519 ‖ ML-KEM-768) — PQKF KeyType 1.</summary>
    internal const byte PurposeHybridRecipient = 1;

    /// <summary>Hybrid signing public key (Ed25519 ‖ ML-DSA-65) — PQKF KeyType 2.</summary>
    internal const byte PurposeSigning = 2;

    private static ReadOnlySpan<byte> DomainPrefix => "PostQuantum.FileEncryption/fingerprint v1\0"u8;

    internal static string Compute(byte purpose, ReadOnlySpan<byte> publicKeyBytes)
    {
        byte[] preimage = new byte[DomainPrefix.Length + 1 + publicKeyBytes.Length];
        DomainPrefix.CopyTo(preimage);
        preimage[DomainPrefix.Length] = purpose;
        publicKeyBytes.CopyTo(preimage.AsSpan(DomainPrefix.Length + 1));

        Span<byte> hash = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(preimage, hash);

        // URL-safe Base64, no padding (public keys are not secrets; nothing here needs zeroing).
        return "pqfp1:" + Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
