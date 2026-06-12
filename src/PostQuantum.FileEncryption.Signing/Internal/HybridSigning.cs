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
    /// Verifies a serialized sidecar against a SHA-512 content digest. Fail-closed: returns
    /// only on full success; structural problems raise <see cref="PqFormatException"/>, any
    /// cryptographic mismatch raises <see cref="PqSignatureException"/>.
    /// </summary>
    public static void Verify(byte[] contentDigest, ReadOnlySpan<byte> signature, PqSigningPublicKey publicKey)
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

        byte[] message = BuildSignedMessage(contentDigest);
        byte[] edSig = signature.Slice(HeaderLength, SigningSizes.Ed25519Signature).ToArray();
        byte[] mlSig = signature.Slice(HeaderLength + SigningSizes.Ed25519Signature, SigningSizes.MlDsa65Signature).ToArray();

        var ed = new Ed25519Signer();
        ed.Init(forSigning: false, new Ed25519PublicKeyParameters(publicKey.Ed25519PublicKey));
        ed.BlockUpdate(message, 0, message.Length);
        bool edOk = ed.VerifySignature(edSig);

        var mlDsa = new MLDsaSigner(MLDsaParameters.ml_dsa_65, deterministic: false);
        mlDsa.Init(forSigning: false, MLDsaPublicKeyParameters.FromEncoding(MLDsaParameters.ml_dsa_65, publicKey.MlDsaPublicKey));
        mlDsa.BlockUpdate(message, 0, message.Length);
        bool mlOk = mlDsa.VerifySignature(mlSig);

        // Non-short-circuit: both components are always evaluated, and either failing yields
        // the same generic error — no oracle for which half failed.
        if (!(edOk & mlOk))
        {
            throw new PqSignatureException(VerifyFailedMessage);
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
