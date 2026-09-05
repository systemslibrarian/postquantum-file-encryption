using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PostQuantum.FileEncryption.Internal;

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

    /// <summary>
    /// A stable, domain-separated fingerprint of this public key: <c>pqfp1:</c> followed by
    /// the URL-safe Base64 SHA-256 of the key bytes with a purpose tag (a recipient key and a
    /// signing key can never share a fingerprint). Compare the whole string over a channel
    /// you already trust — a call, a video chat, an existing authenticated system — before
    /// first use of a key you received: two parties reading the same fingerprint hold the
    /// same key, which is the defense against a swapped-in attacker key. Safe to log,
    /// publish, and pin in configuration; it reveals nothing secret. The rendering is a
    /// compatibility surface and will not change for the <c>pqfp1:</c> prefix.
    /// </summary>
    public string GetFingerprint() => Fingerprint.Compute(Fingerprint.PurposeSigning, Export());

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

    /// <summary>
    /// Exports this private key as a passphrase-encrypted <c>PQKF</c> key file — the safe way
    /// to store a signing key at rest. The key bytes are protected by the same authenticated
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
            return PqKeyFileFormat.Encrypt(PqKeyFileFormat.KeyTypeSigningPrivate, raw, passphrase, options);
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
    /// of key (e.g. a hybrid recipient key), or the KDF parameters exceed <paramref name="limits"/>.
    /// </exception>
    /// <exception cref="PqDecryptionException">The passphrase is wrong, or the key file was altered.</exception>
    public static PqSigningPrivateKey ImportEncrypted(
        ReadOnlySpan<byte> keyFile, ReadOnlySpan<char> passphrase, PqDecryptionLimits? limits = null)
    {
        byte[] raw = PqKeyFileFormat.Decrypt(
            PqKeyFileFormat.KeyTypeSigningPrivate, "hybrid signing private key", SigningSizes.PrivateKey,
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
