using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace PostQuantum.FileEncryption.Signing.Internal;

/// <summary>
/// The Ed25519 + ML-DSA-65 hybrid detached-signature core. The content is pre-hashed with
/// streaming SHA-512 (constant memory for any input size); both algorithms then sign the same
/// short, domain-separated message <c>Context ‖ SHA-512(content)</c>. Verification requires
/// <b>both</b> signatures to verify — an attacker must break Ed25519 <em>and</em> ML-DSA-65 to
/// forge. See docs/SIGNATURE-FORMAT.md for the byte-exact sidecar specification.
/// </summary>
/// <remarks>No novel cryptography: SHA-512 pre-hashing of detached-signature input is the
/// standard construction (minisign/signify, Ed25519ph, HashML-DSA all pre-hash). Ed25519 and
/// ML-DSA come from BouncyCastle; SHA-512 from .NET.</remarks>
internal static class HybridSigning
{
    // Sidecar layout: Magic(4) | FormatVersion(1) | AlgorithmId(1) | Ed25519Sig(64) | MlDsaSig(3309)
    public const byte FormatVersion = 1;
    public const byte AlgHybridEd25519MlDsa65 = 1;
    public const int HeaderLength = 6;
    public const int SignatureLength =
        HeaderLength + SigningSizes.Ed25519Signature + SigningSizes.MlDsa65Signature; // 3379

    private static ReadOnlySpan<byte> Magic => "PQSG"u8;

    /// <summary>Domain separation: both algorithms sign Context ‖ SHA-512(content).</summary>
    private static ReadOnlySpan<byte> Context => "PostQuantum.FileEncryption.Signing/v1 ed25519+ml-dsa-65 sha-512"u8;

    private const string VerifyFailedMessage =
        "Signature verification failed: the data or the signature has been altered, or the " +
        "signature was produced by a different key.";

    /// <summary>Signs a SHA-512 content digest and returns the serialized sidecar bytes.</summary>
    public static byte[] Sign(byte[] contentDigest, PqSigningPrivateKey privateKey)
    {
        byte[] message = BuildSignedMessage(contentDigest);

        var signature = new byte[SignatureLength];
        Magic.CopyTo(signature);
        signature[4] = FormatVersion;
        signature[5] = AlgHybridEd25519MlDsa65;

        // BouncyCastle key parameter objects copy and retain the key bytes; the temporary
        // copies handed to them are zeroed here, the BC-internal copies cannot be (KNOWN-GAPS).
        byte[] edKeyCopy = privateKey.Ed25519PrivateKey.ToArray();
        try
        {
            var ed = new Ed25519Signer();
            ed.Init(forSigning: true, new Ed25519PrivateKeyParameters(edKeyCopy));
            ed.BlockUpdate(message, 0, message.Length);
            byte[] edSig = ed.GenerateSignature();
            edSig.CopyTo(signature, HeaderLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(edKeyCopy);
        }

        byte[] mlKeyCopy = privateKey.MlDsaPrivateKey.ToArray();
        try
        {
            // Hedged (randomized) signing per FIPS 204 — the default recommendation.
            var mlDsa = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
            mlDsa.Init(forSigning: true, new ParametersWithRandom(
                MLDsaPrivateKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, mlKeyCopy),
                new SecureRandom()));
            mlDsa.BlockUpdate(message, 0, message.Length);
            byte[] mlSig = mlDsa.GenerateSignature();
            mlSig.CopyTo(signature, HeaderLength + SigningSizes.Ed25519Signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(mlKeyCopy);
        }

        return signature;
    }

    /// <summary>
    /// Validates the sidecar's structural framing (length, magic, version, algorithm) and
    /// throws <see cref="PqFormatException"/> if it is not a recognizable detached signature.
    /// Per docs/SIGNATURE-FORMAT.md a verifier MUST clear these checks <em>before</em> hashing
    /// the content, so this runs at the public boundary ahead of the (possibly large) SHA-512
    /// pass — a garbage sidecar is rejected without reading the input.
    /// </summary>
    public static void ValidateSidecar(ReadOnlySpan<byte> signature)
    {
        if (signature.Length != SignatureLength)
        {
            throw new PqFormatException("Not a recognizable detached signature (wrong length).");
        }
        if (!signature[..4].SequenceEqual(Magic))
        {
            throw new PqFormatException("Not a recognizable detached signature (bad magic bytes).");
        }
        if (signature[4] != FormatVersion)
        {
            throw new PqFormatException("Unsupported detached-signature format version.");
        }
        if (signature[5] != AlgHybridEd25519MlDsa65)
        {
            throw new PqFormatException("Unsupported detached-signature algorithm.");
        }
    }

    /// <summary>
    /// Verifies a serialized sidecar against a SHA-512 content digest. Fail-closed: returns
    /// only on full success; structural problems raise <see cref="PqFormatException"/>, any
    /// cryptographic mismatch raises <see cref="PqSignatureException"/>.
    /// </summary>
    public static void Verify(byte[] contentDigest, ReadOnlySpan<byte> signature, PqSigningPublicKey publicKey)
    {
        // Idempotent with the boundary call in PqVerifier — kept here so Verify is safe on its
        // own (four byte comparisons; negligible).
        ValidateSidecar(signature);

        byte[] message = BuildSignedMessage(contentDigest);
        byte[] edSig = signature.Slice(HeaderLength, SigningSizes.Ed25519Signature).ToArray();
        byte[] mlSig = signature.Slice(HeaderLength + SigningSizes.Ed25519Signature, SigningSizes.MlDsa65Signature).ToArray();

        // Each component is evaluated in its own guarded step so that an unexpected throw from
        // one half cannot skip the other — the two verifications always both run, and either a
        // false result or a caught fault yields the same generic failure below. BouncyCastle
        // returns false (not throws) for every hostile-content case we know of; this makes the
        // fail-closed, single-message contract independent of that. Process-level faults (OOM,
        // cancellation, thread interrupt) are NOT caught — they signal infrastructure, not a
        // hostile signature, and must not be reported to a caller as a forgery.
        Exception? fault = null;
        bool edOk = TryVerifyComponent(() =>
        {
            var ed = new Ed25519Signer();
            ed.Init(forSigning: false, new Ed25519PublicKeyParameters(publicKey.Ed25519PublicKey));
            ed.BlockUpdate(message, 0, message.Length);
            return ed.VerifySignature(edSig);
        }, ref fault);
        bool mlOk = TryVerifyComponent(() =>
        {
            var mlDsa = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
            mlDsa.Init(forSigning: false, MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, publicKey.MlDsaPublicKey));
            mlDsa.BlockUpdate(message, 0, message.Length);
            return mlDsa.VerifySignature(mlSig);
        }, ref fault);

        // Non-short-circuit: both components are always evaluated, and either failing yields
        // the same generic error — no oracle for which half failed. A captured fault (if any)
        // rides along only as diagnostics; the message is identical either way.
        if (!(edOk & mlOk))
        {
            throw fault is null
                ? new PqSignatureException(VerifyFailedMessage)
                : new PqSignatureException(VerifyFailedMessage, fault);
        }
    }

    /// <summary>
    /// Runs one component verification, mapping an unexpected (non-infrastructure) throw to a
    /// <c>false</c> result so the caller can still evaluate the other component. The first such
    /// fault is captured for diagnostics; infrastructure faults propagate untouched.
    /// </summary>
    private static bool TryVerifyComponent(Func<bool> verify, ref Exception? fault)
    {
        try
        {
            return verify();
        }
        catch (Exception ex) when (ex is not (OutOfMemoryException or OperationCanceledException or ThreadInterruptedException))
        {
            fault ??= ex;
            return false;
        }
    }

    private static byte[] BuildSignedMessage(byte[] contentDigest)
    {
        var message = new byte[Context.Length + contentDigest.Length];
        Context.CopyTo(message);
        contentDigest.CopyTo(message, Context.Length);
        return message;
    }
}
