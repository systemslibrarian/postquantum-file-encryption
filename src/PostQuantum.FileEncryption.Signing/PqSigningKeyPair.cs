using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PostQuantum.FileEncryption.Signing;

/// <summary>Fixed key and signature sizes (bytes) for the Ed25519 + ML-DSA-65 hybrid, per RFC 8032 / FIPS 204.</summary>
internal static class SigningSizes
{
    public const int Ed25519PublicKey = 32;
    public const int Ed25519PrivateKey = 32;   // the RFC 8032 seed
    public const int Ed25519Signature = 64;
    public const int MlDsa65PublicKey = 1952;
    public const int MlDsa65PrivateKey = 4032;
    public const int MlDsa65Signature = 3309;

    public const int PublicKey = Ed25519PublicKey + MlDsa65PublicKey;     // 1984
    public const int PrivateKey = Ed25519PrivateKey + MlDsa65PrivateKey;  // 4064
}

/// <summary>
/// A signer's hybrid <b>public</b> (verification) key: an Ed25519 public key concatenated with an
/// ML-DSA-65 public key. Share this freely; anyone holding it can verify signatures produced by
/// the matching <see cref="PqSigningPrivateKey"/>. Encoding is <c>Ed25519(32) ‖ ML-DSA-pk(1952)</c>.
/// </summary>
public sealed class PqSigningPublicKey
{
    internal byte[] Ed25519PublicKey { get; }
    internal byte[] MlDsaPublicKey { get; }

    internal PqSigningPublicKey(byte[] ed25519PublicKey, byte[] mlDsaPublicKey)
    {
        Ed25519PublicKey = ed25519PublicKey;
        MlDsaPublicKey = mlDsaPublicKey;
    }

    /// <summary>Returns a copy of the raw key bytes for storage or transport.</summary>
    public byte[] Export()
    {
        var bytes = new byte[SigningSizes.PublicKey];
        Ed25519PublicKey.CopyTo(bytes, 0);
        MlDsaPublicKey.CopyTo(bytes, SigningSizes.Ed25519PublicKey);
        return bytes;
    }

    /// <summary>Imports a public key previously produced by <see cref="Export"/>.</summary>
    /// <exception cref="ArgumentException">The byte length does not match the hybrid encoding.</exception>
    public static PqSigningPublicKey Import(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != SigningSizes.PublicKey)
        {
            throw new ArgumentException(
                $"Not a valid hybrid signing public key (expected {SigningSizes.PublicKey} bytes).", nameof(bytes));
        }
        return new PqSigningPublicKey(
            bytes[..SigningSizes.Ed25519PublicKey],
            bytes[SigningSizes.Ed25519PublicKey..]);
    }
}

/// <summary>
/// A signer's hybrid <b>private</b> (signing) key: an Ed25519 private key concatenated with an
/// ML-DSA-65 private key. Keep this secret; dispose it when done so its bytes are zeroed.
/// Encoding is <c>Ed25519-seed(32) ‖ ML-DSA-sk(4032)</c>.
/// </summary>
public sealed class PqSigningPrivateKey : IDisposable
{
    private readonly byte[] _ed25519PrivateKey;
    private readonly byte[] _mlDsaPrivateKey;
    private bool _disposed;

    internal PqSigningPrivateKey(byte[] ed25519PrivateKey, byte[] mlDsaPrivateKey)
    {
        _ed25519PrivateKey = ed25519PrivateKey;
        _mlDsaPrivateKey = mlDsaPrivateKey;
    }

    internal ReadOnlySpan<byte> Ed25519PrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ed25519PrivateKey;
        }
    }

    internal ReadOnlySpan<byte> MlDsaPrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _mlDsaPrivateKey;
        }
    }

    /// <summary>
    /// Returns a copy of the raw key bytes. Handle the result as a secret and zero it when done.
    /// </summary>
    public byte[] Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var bytes = new byte[SigningSizes.PrivateKey];
        _ed25519PrivateKey.CopyTo(bytes, 0);
        _mlDsaPrivateKey.CopyTo(bytes, SigningSizes.Ed25519PrivateKey);
        return bytes;
    }

    /// <summary>Imports a private key previously produced by <see cref="Export"/>.</summary>
    /// <exception cref="ArgumentException">The byte length does not match the hybrid encoding.</exception>
    public static PqSigningPrivateKey Import(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != SigningSizes.PrivateKey)
        {
            throw new ArgumentException(
                $"Not a valid hybrid signing private key (expected {SigningSizes.PrivateKey} bytes).", nameof(bytes));
        }
        return new PqSigningPrivateKey(
            bytes[..SigningSizes.Ed25519PrivateKey],
            bytes[SigningSizes.Ed25519PrivateKey..]);
    }

    /// <summary>Zeroes the key bytes from memory.</summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_ed25519PrivateKey);
            CryptographicOperations.ZeroMemory(_mlDsaPrivateKey);
            _disposed = true;
        }
    }
}

/// <summary>
/// A hybrid signing key pair: Ed25519 (classical) combined with ML-DSA-65 (post-quantum,
/// FIPS 204). A signature verifies only when <b>both</b> components verify, so signatures
/// remain unforgeable if either primitive is later broken.
/// </summary>
/// <example>
/// <code>
/// using var keyPair = PqSigningKeyPair.Generate();
/// byte[] shareThis = keyPair.PublicKey.Export();
/// // ... store keyPair.PrivateKey.Export() somewhere safe ...
/// </code>
/// </example>
public sealed class PqSigningKeyPair : IDisposable
{
    /// <summary>The public (verification) key — safe to share.</summary>
    public PqSigningPublicKey PublicKey { get; }

    /// <summary>The private (signing) key — keep secret.</summary>
    public PqSigningPrivateKey PrivateKey { get; }

    private PqSigningKeyPair(PqSigningPublicKey publicKey, PqSigningPrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>Generates a fresh hybrid signing key pair.</summary>
    public static PqSigningKeyPair Generate()
    {
        var random = new SecureRandom();

        var edGen = new Ed25519KeyPairGenerator();
        edGen.Init(new Ed25519KeyGenerationParameters(random));
        var ed = edGen.GenerateKeyPair();
        byte[] edPub = ((Ed25519PublicKeyParameters)ed.Public).GetEncoded();
        byte[] edPriv = ((Ed25519PrivateKeyParameters)ed.Private).GetEncoded();

        var mlDsaGen = new MLDsaKeyPairGenerator();
        mlDsaGen.Init(new MLDsaKeyGenerationParameters(random, MLDsaParameters.ml_dsa_65));
        var mlDsa = mlDsaGen.GenerateKeyPair();
        byte[] mlPub = ((MLDsaPublicKeyParameters)mlDsa.Public).GetEncoded();
        byte[] mlPriv = ((MLDsaPrivateKeyParameters)mlDsa.Private).GetEncoded();

        return new PqSigningKeyPair(
            new PqSigningPublicKey(edPub, mlPub),
            new PqSigningPrivateKey(edPriv, mlPriv));
    }

    /// <summary>Disposes the private key, zeroing it from memory.</summary>
    public void Dispose() => PrivateKey.Dispose();
}
