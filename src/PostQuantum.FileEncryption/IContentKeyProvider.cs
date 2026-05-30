namespace PostQuantum.FileEncryption;

/// <summary>
/// An external provider of <b>envelope-encryption</b> keys — the seam for KMS, HSM, or any
/// system that holds a master key and never hands it out. The library generates and encrypts
/// each file under a fresh per-file content key (CEK); the provider produces that CEK and the
/// opaque bytes needed to recover it later, so the master key never enters this process beyond
/// the provider's own boundary.
/// </summary>
/// <remarks>
/// Implement this over AWS KMS, Azure Key Vault, HashiCorp Vault, a PKCS#11 HSM, etc. — the
/// pattern mirrors KMS "generate data key" (returns a plaintext CEK and an encrypted CEK).
/// <see cref="LocalKekContentKeyProvider"/> is a built-in, dependency-free implementation that
/// wraps under a local key-encryption key, useful for testing and on-box scenarios.
/// </remarks>
public interface IContentKeyProvider
{
    /// <summary>
    /// A short, stable identifier for this provider (e.g. <c>"local-kek"</c>, <c>"aws-kms"</c>).
    /// Stored in the container header and checked on decryption so a mismatched provider fails
    /// fast with a clear error. Must be ≤ 255 UTF-8 bytes.
    /// </summary>
    string ProviderId { get; }

    /// <summary>
    /// Generates a fresh 32-byte content key and the opaque <c>wrapInfo</c> bytes required to
    /// recover it. The caller owns the returned content key and will zero it after use.
    /// </summary>
    Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Recovers the content key from <paramref name="wrapInfo"/> produced by an earlier
    /// <see cref="WrapNewKeyAsync"/>. Must fail closed (throw) if the wrap is invalid, tampered,
    /// or not for this key.
    /// </summary>
    Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken cancellationToken = default);
}
