using System.Security.Cryptography;

namespace PostQuantum.FileEncryption;

/// <summary>The post-quantum key-encapsulation algorithm used for recipient encryption.</summary>
public enum PqKemAlgorithm
{
    /// <summary>ML-KEM-768 (FIPS 203), NIST security category 3.</summary>
    MlKem768 = 1,
}

/// <summary>
/// Fixed sizes (in bytes) for the supported KEM algorithms, per FIPS 203.
/// </summary>
internal static class KemSizes
{
    public const int MlKem768EncapsulationKey = 1184;
    public const int MlKem768DecapsulationKey = 2400;
    public const int MlKem768Ciphertext = 1088;
    public const int SharedSecret = 32;
}

/// <summary>
/// A recipient's public (encapsulation) key. Share this freely; anyone holding it can encrypt
/// a file that only the matching <see cref="PqRecipientPrivateKey"/> can open.
/// </summary>
public sealed class PqRecipientPublicKey
{
    internal byte[] KeyBytes { get; }

    /// <summary>The KEM algorithm this key belongs to.</summary>
    public PqKemAlgorithm Algorithm { get; }

    internal PqRecipientPublicKey(PqKemAlgorithm algorithm, byte[] keyBytes)
    {
        Algorithm = algorithm;
        KeyBytes = keyBytes;
    }

    /// <summary>Returns a copy of the raw encapsulation-key bytes for storage or transport.</summary>
    public byte[] Export() => (byte[])KeyBytes.Clone();

    /// <summary>Imports a public key from raw encapsulation-key bytes.</summary>
    /// <exception cref="ArgumentException">The byte length does not match the algorithm.</exception>
    public static PqRecipientPublicKey Import(byte[] bytes, PqKemAlgorithm algorithm = PqKemAlgorithm.MlKem768)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (algorithm != PqKemAlgorithm.MlKem768 || bytes.Length != KemSizes.MlKem768EncapsulationKey)
        {
            throw new ArgumentException($"Not a valid {algorithm} encapsulation key.", nameof(bytes));
        }
        return new PqRecipientPublicKey(algorithm, (byte[])bytes.Clone());
    }
}

/// <summary>
/// A recipient's private (decapsulation) key. Keep this secret. Dispose it when done so its
/// bytes are zeroed from memory.
/// </summary>
public sealed class PqRecipientPrivateKey : IDisposable
{
    private readonly byte[] _decapsulationKey;
    private bool _disposed;

    /// <summary>The KEM algorithm this key belongs to.</summary>
    public PqKemAlgorithm Algorithm { get; }

    internal PqRecipientPrivateKey(PqKemAlgorithm algorithm, byte[] decapsulationKey)
    {
        Algorithm = algorithm;
        _decapsulationKey = decapsulationKey;
    }

    internal ReadOnlySpan<byte> DecapsulationKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _decapsulationKey;
        }
    }

    /// <summary>
    /// Returns a copy of the raw decapsulation-key bytes. Handle the result as a secret and
    /// zero it when done.
    /// </summary>
    public byte[] Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_decapsulationKey.Clone();
    }

    /// <summary>Imports a private key from raw decapsulation-key bytes.</summary>
    /// <exception cref="ArgumentException">The byte length does not match the algorithm.</exception>
    public static PqRecipientPrivateKey Import(byte[] bytes, PqKemAlgorithm algorithm = PqKemAlgorithm.MlKem768)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (algorithm != PqKemAlgorithm.MlKem768 || bytes.Length != KemSizes.MlKem768DecapsulationKey)
        {
            throw new ArgumentException($"Not a valid {algorithm} decapsulation key.", nameof(bytes));
        }
        return new PqRecipientPrivateKey(algorithm, (byte[])bytes.Clone());
    }

    /// <summary>Zeroes the key bytes from memory.</summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_decapsulationKey);
            _disposed = true;
        }
    }
}

/// <summary>
/// A post-quantum recipient key pair. Generate one per recipient, publish
/// <see cref="PublicKey"/>, and keep <see cref="PrivateKey"/> secret.
/// </summary>
/// <example>
/// <code>
/// using var keyPair = PqKeyPair.Generate();
/// byte[] shareThis = keyPair.PublicKey.Export();
/// // ... store keyPair.PrivateKey.Export() somewhere safe ...
/// </code>
/// </example>
public sealed class PqKeyPair : IDisposable
{
    /// <summary>The public (encapsulation) key — safe to share.</summary>
    public PqRecipientPublicKey PublicKey { get; }

    /// <summary>The private (decapsulation) key — keep secret.</summary>
    public PqRecipientPrivateKey PrivateKey { get; }

    private PqKeyPair(PqRecipientPublicKey publicKey, PqRecipientPrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>
    /// Generates a fresh recipient key pair.
    /// </summary>
    /// <exception cref="PlatformNotSupportedException">
    /// The platform does not provide ML-KEM (it requires .NET 10 on a host with OpenSSL 3.5+
    /// or Windows CNG support). Check <see cref="IsSupported"/> first to fail gracefully.
    /// </exception>
    public static PqKeyPair Generate(PqKemAlgorithm algorithm = PqKemAlgorithm.MlKem768)
    {
        if (algorithm != PqKemAlgorithm.MlKem768)
        {
            throw new ArgumentOutOfRangeException(nameof(algorithm));
        }
        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not available on this platform. Recipient (public-key) encryption requires .NET 10 with platform PQC support (OpenSSL 3.5+ or Windows CNG).");
        }

        using MLKem kem = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var publicKey = new PqRecipientPublicKey(algorithm, kem.ExportEncapsulationKey());
        var privateKey = new PqRecipientPrivateKey(algorithm, kem.ExportDecapsulationKey());
        return new PqKeyPair(publicKey, privateKey);
    }

    /// <summary>
    /// Whether recipient (public-key) encryption is available on this platform. When
    /// <see langword="false"/>, use passphrase-based encryption instead.
    /// </summary>
    public static bool IsSupported => MLKem.IsSupported;

    /// <summary>Disposes the private key, zeroing it from memory.</summary>
    public void Dispose() => PrivateKey.Dispose();
}
