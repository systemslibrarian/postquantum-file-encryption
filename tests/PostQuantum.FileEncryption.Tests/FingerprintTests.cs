using PostQuantum.FileEncryption.Hybrid;
using PostQuantum.FileEncryption.Signing;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pins the public-key fingerprint construction (<c>pqfp1:</c> + URL-safe Base64 SHA-256 over
/// the domain prefix, purpose tag, and exported key bytes). The rendering is a compatibility
/// surface — people write these down, pin them in configuration, and compare them over the
/// phone — so any change here is breaking even though no on-disk format is involved: a
/// different construction must use a new <c>pqfpN:</c> prefix, never alter <c>pqfp1</c>.
/// </summary>
public sealed class FingerprintTests
{
    [Fact]
    public void Hybrid_recipient_fingerprint_is_pinned()
    {
        byte[] bytes = new byte[1216];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(i % 251);
        }

        Assert.Equal(
            "pqfp1:6JCYeiCLnoUrunV1IsnrIjkhWgpSTgr9SH1hcsQaGWo",
            PqHybridPublicKey.Import(bytes).GetFingerprint());
    }

    [Fact]
    public void Signing_fingerprint_is_pinned()
    {
        byte[] bytes = new byte[1984];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = (byte)(i * 7 % 251);
        }

        Assert.Equal(
            "pqfp1:T7uANXro-2NKH3ywDyBnzX4zaGpNDx3OMSQrBExS-LM",
            PqSigningPublicKey.Import(bytes).GetFingerprint());
    }

    [Fact]
    public void Fingerprint_is_stable_across_export_import_round_trips()
    {
        using var recipient = PqHybridKeyPair.Generate();
        Assert.Equal(
            recipient.PublicKey.GetFingerprint(),
            PqHybridPublicKey.Import(recipient.PublicKey.Export()).GetFingerprint());

        using var signer = PqSigningKeyPair.Generate();
        Assert.Equal(
            signer.PublicKey.GetFingerprint(),
            PqSigningPublicKey.Import(signer.PublicKey.Export()).GetFingerprint());
    }

    [Fact]
    public void Fingerprints_are_canonical_url_safe_tokens()
    {
        using var recipient = PqHybridKeyPair.Generate();
        string fp = recipient.PublicKey.GetFingerprint();

        Assert.StartsWith("pqfp1:", fp, StringComparison.Ordinal);
        Assert.Equal(6 + 43, fp.Length); // prefix + unpadded Base64 of 32 bytes
        Assert.DoesNotContain('+', fp);
        Assert.DoesNotContain('/', fp);
        Assert.DoesNotContain('=', fp);
    }
}
