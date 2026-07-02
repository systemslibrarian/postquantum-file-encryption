using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption.Hybrid;

/// <summary>Fixed key sizes (bytes) for the X25519 + ML-KEM-768 hybrid, per FIPS 203 / RFC 7748.</summary>
internal static class HybridSizes
{
    public const int X25519Key = 32;
    public const int MlKemEncapsulationKey = 1184;
    public const int MlKemDecapsulationKey = 2400;
    public const int PublicKey = X25519Key + MlKemEncapsulationKey;   // 1216
    public const int PrivateKey = X25519Key + MlKemDecapsulationKey;  // 2432
}

/// <summary>
/// A recipient's hybrid <b>public</b> key: an X25519 public key concatenated with an ML-KEM-768
/// encapsulation key. Share it freely; only the matching <see cref="PqHybridPrivateKey"/> can open
/// files encrypted to it. Encoding is <c>X25519(32) ‖ ML-KEM-ek(1184)</c>.
/// </summary>
public sealed class PqHybridPublicKey
{
    internal byte[] X25519PublicKey { get; }
    internal byte[] MlKemEncapsulationKey { get; }

    internal PqHybridPublicKey(byte[] x25519PublicKey, byte[] mlKemEncapsulationKey)
    {
        X25519PublicKey = x25519PublicKey;
        MlKemEncapsulationKey = mlKemEncapsulationKey;
    }

    /// <summary>Returns the concatenated public-key bytes for storage or transport.</summary>
    public byte[] Export()
    {
        var bytes = new byte[HybridSizes.PublicKey];
        X25519PublicKey.CopyTo(bytes, 0);
        MlKemEncapsulationKey.CopyTo(bytes, HybridSizes.X25519Key);
        return bytes;
    }

    /// <summary>Imports a hybrid public key from <see cref="Export"/> bytes.</summary>
    /// <exception cref="ArgumentException">The byte length is not <c>1216</c>.</exception>
    public static PqHybridPublicKey Import(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != HybridSizes.PublicKey)
        {
            throw new ArgumentException($"A hybrid public key must be {HybridSizes.PublicKey} bytes.", nameof(bytes));
        }
        return new PqHybridPublicKey(
            bytes[..HybridSizes.X25519Key],
            bytes[HybridSizes.X25519Key..]);
    }
}

/// <summary>
/// A recipient's hybrid <b>private</b> key: an X25519 private key concatenated with an ML-KEM-768
/// decapsulation key. Keep it secret; dispose it to zero the bytes. Encoding is
/// <c>X25519(32) ‖ ML-KEM-dk(2400)</c>.
/// </summary>
public sealed class PqHybridPrivateKey : IDisposable
{
    private readonly byte[] _x25519PrivateKey;
    private readonly byte[] _mlKemDecapsulationKey;
    private bool _disposed;

    internal PqHybridPrivateKey(byte[] x25519PrivateKey, byte[] mlKemDecapsulationKey)
    {
        _x25519PrivateKey = x25519PrivateKey;
        _mlKemDecapsulationKey = mlKemDecapsulationKey;
    }

    internal ReadOnlySpan<byte> X25519PrivateKey
    {
        get { ObjectDisposedException.ThrowIf(_disposed, this); return _x25519PrivateKey; }
    }

    internal ReadOnlySpan<byte> MlKemDecapsulationKey
    {
        get { ObjectDisposedException.ThrowIf(_disposed, this); return _mlKemDecapsulationKey; }
    }

    /// <summary>Returns the concatenated private-key bytes. Handle as a secret and zero when done.</summary>
    public byte[] Export()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var bytes = new byte[HybridSizes.PrivateKey];
        _x25519PrivateKey.CopyTo(bytes, 0);
        _mlKemDecapsulationKey.CopyTo(bytes, HybridSizes.X25519Key);
        return bytes;
    }

    /// <summary>
    /// Exports this private key as a passphrase-encrypted <c>PQKF</c> key file — the safe way
    /// to store a private key at rest. The key bytes are protected by the same authenticated
    /// container the library uses for data (Argon2id key derivation by default), so a wrong
    /// passphrase or any tampering fails closed on import.
    /// See <c>docs/KEY-FILE-FORMAT.md</c> for the byte-exact format.
    /// </summary>
    /// <param name="passphrase">The passphrase protecting the key file. Must not be empty.</param>
    /// <param name="options">
    /// Optional KDF tuning for the key file. Defaults to the Argon2id preset — key files are
    /// tiny and long-lived, so a memory-hard KDF is the right default.
    /// </param>
    /// <exception cref="ArgumentException">The passphrase is empty.</exception>
    public byte[] ExportEncrypted(ReadOnlySpan<char> passphrase, PqEncryptionOptions? options = null)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        byte[] raw = Export();
        try
        {
            return PqKeyFileFormat.Encrypt(PqKeyFileFormat.KeyTypeHybridPrivate, raw, passphrase, options);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>
    /// Returns whether <paramref name="data"/> is a passphrase-encrypted key file (the
    /// <c>PQKF</c> framing written by <see cref="ExportEncrypted"/>) as opposed to raw
    /// <see cref="Export"/> bytes — use it to route a key file to the right import method.
    /// </summary>
    /// <remarks>
    /// The check reads the file's magic and version bytes. Raw <see cref="Export"/> bytes begin
    /// with random key material, so an accidental match is possible but astronomically unlikely
    /// (~2⁻⁴⁰ per key); store the two forms under distinct names if you must rule it out.
    /// </remarks>
    public static bool IsEncryptedKeyFile(ReadOnlySpan<byte> data) => PqKeyFileFormat.IsEncryptedKeyFile(data);

    /// <summary>Imports a private key from a passphrase-encrypted key file produced by <see cref="ExportEncrypted"/>.</summary>
    /// <param name="keyFile">The encrypted key file bytes.</param>
    /// <param name="passphrase">The passphrase the key file was exported under.</param>
    /// <param name="limits">
    /// Optional decrypt-time resource ceilings applied to the key file's KDF cost parameters —
    /// pass <see cref="PqDecryptionLimits.Untrusted"/> (or your own) when the key file comes
    /// from an untrusted source, so a hostile header cannot demand gibibytes of Argon2id memory
    /// before anything authenticates. The default honors the permissive format maxima, so every
    /// legal key file opens.
    /// </param>
    /// <exception cref="PqFormatException">
    /// The bytes are not a recognizable encrypted key file, the file holds a different kind
    /// of key (e.g. a signing key), or the KDF parameters exceed <paramref name="limits"/>.
    /// </exception>
    /// <exception cref="PqDecryptionException">The passphrase is wrong, or the key file was altered.</exception>
    public static PqHybridPrivateKey ImportEncrypted(
        ReadOnlySpan<byte> keyFile, ReadOnlySpan<char> passphrase, PqDecryptionLimits? limits = null)
    {
        byte[] raw = PqKeyFileFormat.Decrypt(
            PqKeyFileFormat.KeyTypeHybridPrivate, "hybrid recipient private key", HybridSizes.PrivateKey,
            keyFile, passphrase, limits);
        try
        {
            return Import(raw);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    /// <summary>Imports a hybrid private key from <see cref="Export"/> bytes.</summary>
    /// <exception cref="ArgumentException">The byte length is not <c>2432</c>.</exception>
    public static PqHybridPrivateKey Import(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        if (bytes.Length != HybridSizes.PrivateKey)
        {
            throw new ArgumentException($"A hybrid private key must be {HybridSizes.PrivateKey} bytes.", nameof(bytes));
        }
        return new PqHybridPrivateKey(
            bytes[..HybridSizes.X25519Key],
            bytes[HybridSizes.X25519Key..]);
    }

    /// <summary>Zeroes the key bytes from memory.</summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_x25519PrivateKey);
            CryptographicOperations.ZeroMemory(_mlKemDecapsulationKey);
            _disposed = true;
        }
    }
}

/// <summary>
/// A post-quantum <b>hybrid</b> recipient key pair: X25519 (classical) combined with ML-KEM-768
/// (post-quantum). The content key stays protected even if <em>either</em> primitive is later
/// broken. Implemented with BouncyCastle, so it works on any platform — no native ML-KEM required.
/// </summary>
/// <example>
/// <code>
/// using var keyPair = PqHybridKeyPair.Generate();
/// byte[] share = keyPair.PublicKey.Export();         // give this to senders
/// byte[] keep  = keyPair.PrivateKey.Export();        // store securely
/// </code>
/// </example>
public sealed class PqHybridKeyPair : IDisposable
{
    /// <summary>The public (X25519 + ML-KEM encapsulation) key — safe to share.</summary>
    public PqHybridPublicKey PublicKey { get; }

    /// <summary>The private (X25519 + ML-KEM decapsulation) key — keep secret.</summary>
    public PqHybridPrivateKey PrivateKey { get; }

    private PqHybridKeyPair(PqHybridPublicKey publicKey, PqHybridPrivateKey privateKey)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
    }

    /// <summary>Generates a fresh hybrid recipient key pair.</summary>
    public static PqHybridKeyPair Generate()
    {
        var random = new SecureRandom();

        var mlkemGen = new MLKemKeyPairGenerator();
        mlkemGen.Init(new MLKemKeyGenerationParameters(random, MLKemParameters.ml_kem_768));
        var mlkem = mlkemGen.GenerateKeyPair();
        byte[] ek = ((MLKemPublicKeyParameters)mlkem.Public).GetEncoded();
        byte[] dk = ((MLKemPrivateKeyParameters)mlkem.Private).GetEncoded();

        var x25519Gen = new X25519KeyPairGenerator();
        x25519Gen.Init(new X25519KeyGenerationParameters(random));
        var x25519 = x25519Gen.GenerateKeyPair();
        byte[] xPub = ((X25519PublicKeyParameters)x25519.Public).GetEncoded();
        byte[] xPriv = ((X25519PrivateKeyParameters)x25519.Private).GetEncoded();

        return new PqHybridKeyPair(
            new PqHybridPublicKey(xPub, ek),
            new PqHybridPrivateKey(xPriv, dk));
    }

    /// <summary>Disposes the private key, zeroing it from memory.</summary>
    public void Dispose() => PrivateKey.Dispose();
}
