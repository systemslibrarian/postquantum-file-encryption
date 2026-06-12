using PostQuantum.FileEncryption.Signing;
using PostQuantum.FileEncryption.Signing.Internal;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// The Ed25519 + ML-DSA-65 hybrid detached-signature package. Fully exercised here
/// (BouncyCastle provides managed ML-DSA, so no native platform support is needed).
/// The tamper matrix is as important as the round trips: verification must fail closed
/// for every alteration of the data or of either signature component.
/// </summary>
public sealed class SigningTests
{
    // ---------------------------------------------------------------- round trips

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5000)]
    [InlineData(70000)]
    public void Bytes_round_trip(int size)
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(size);

        byte[] signature = new PqSigner().SignBytes(data, keyPair.PrivateKey);
        new PqVerifier().VerifyBytes(data, signature, keyPair.PublicKey); // throws on failure
    }

    [Fact]
    public async Task Stream_round_trip()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(100_000);

        using var signInput = new MemoryStream(data, writable: false);
        byte[] signature = await new PqSigner().SignAsync(signInput, keyPair.PrivateKey);

        using var verifyInput = new MemoryStream(data, writable: false);
        await new PqVerifier().VerifyAsync(verifyInput, signature, keyPair.PublicKey);
    }

    [Fact]
    public async Task File_round_trip_and_sidecar_shape()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        string dir = Directory.CreateTempSubdirectory("pqfe-sig-").FullName;
        try
        {
            string dataPath = Path.Combine(dir, "data.bin");
            string sigPath = dataPath + ".sig";
            await File.WriteAllBytesAsync(dataPath, RandomBytes(50_000));

            await new PqSigner().SignFileAsync(dataPath, sigPath, keyPair.PrivateKey);
            await new PqVerifier().VerifyFileAsync(dataPath, sigPath, keyPair.PublicKey);

            byte[] sidecar = await File.ReadAllBytesAsync(sigPath);
            Assert.Equal(HybridSigning.SignatureLength, sidecar.Length);
            Assert.Equal("PQSG"u8.ToArray(), sidecar[..4]);
            Assert.Equal(HybridSigning.FormatVersion, sidecar[4]);
            Assert.Equal(HybridSigning.AlgHybridEd25519MlDsa65, sidecar[5]);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void Keys_round_trip_through_export_import()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] publicBytes = keyPair.PublicKey.Export();
        byte[] privateBytes = keyPair.PrivateKey.Export();
        Assert.Equal(SigningSizes.PublicKey, publicBytes.Length);
        Assert.Equal(SigningSizes.PrivateKey, privateBytes.Length);

        var pub = PqSigningPublicKey.Import(publicBytes);
        using var priv = PqSigningPrivateKey.Import(privateBytes);

        byte[] data = RandomBytes(1000);
        byte[] signature = new PqSigner().SignBytes(data, priv);
        new PqVerifier().VerifyBytes(data, signature, pub);
    }

    [Fact]
    public void Hedged_signing_randomizes_but_both_signatures_verify()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(1000);

        byte[] first = new PqSigner().SignBytes(data, keyPair.PrivateKey);
        byte[] second = new PqSigner().SignBytes(data, keyPair.PrivateKey);

        Assert.NotEqual(first, second); // FIPS 204 hedged signing draws fresh randomness
        new PqVerifier().VerifyBytes(data, first, keyPair.PublicKey);
        new PqVerifier().VerifyBytes(data, second, keyPair.PublicKey);
    }

    // ---------------------------------------------------------------- fail closed

    [Fact]
    public void Wrong_public_key_fails_closed()
    {
        using var alice = PqSigningKeyPair.Generate();
        using var mallory = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(2000);

        byte[] signature = new PqSigner().SignBytes(data, alice.PrivateKey);
        Assert.Throws<PqSignatureException>(() =>
            new PqVerifier().VerifyBytes(data, signature, mallory.PublicKey));
    }

    [Fact]
    public void Tampered_data_is_rejected()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(2000);
        byte[] signature = new PqSigner().SignBytes(data, keyPair.PrivateKey);

        data[1000] ^= 0x01;
        Assert.Throws<PqSignatureException>(() =>
            new PqVerifier().VerifyBytes(data, signature, keyPair.PublicKey));
    }

    [Fact]
    public void Tampering_either_signature_component_is_rejected_with_no_oracle()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(2000);
        byte[] signature = new PqSigner().SignBytes(data, keyPair.PrivateKey);

        // Flip one bit inside the Ed25519 component, then inside the ML-DSA component.
        byte[] brokenEd = (byte[])signature.Clone();
        brokenEd[HybridSigning.HeaderLength + 10] ^= 0x01;
        byte[] brokenMl = (byte[])signature.Clone();
        brokenMl[HybridSigning.HeaderLength + SigningSizes.Ed25519Signature + 10] ^= 0x01;

        var edFailure = Assert.Throws<PqSignatureException>(() =>
            new PqVerifier().VerifyBytes(data, brokenEd, keyPair.PublicKey));
        var mlFailure = Assert.Throws<PqSignatureException>(() =>
            new PqVerifier().VerifyBytes(data, brokenMl, keyPair.PublicKey));

        // A hybrid is only as strong as its error discipline: both halves must be required,
        // and the failures must be indistinguishable.
        Assert.Equal(edFailure.Message, mlFailure.Message);
    }

    [Theory]
    [InlineData(0)] // magic
    [InlineData(4)] // format version
    [InlineData(5)] // algorithm id
    public void Corrupted_header_is_a_format_error(int offset)
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(100);
        byte[] signature = new PqSigner().SignBytes(data, keyPair.PrivateKey);

        signature[offset] ^= 0x01;
        Assert.Throws<PqFormatException>(() =>
            new PqVerifier().VerifyBytes(data, signature, keyPair.PublicKey));
    }

    [Fact]
    public void Truncated_or_padded_signature_is_a_format_error()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] data = RandomBytes(100);
        byte[] signature = new PqSigner().SignBytes(data, keyPair.PrivateKey);

        Assert.Throws<PqFormatException>(() =>
            new PqVerifier().VerifyBytes(data, signature.AsSpan(..^1), keyPair.PublicKey));
        Assert.Throws<PqFormatException>(() =>
            new PqVerifier().VerifyBytes(data, [.. signature, 0x00], keyPair.PublicKey));
        Assert.Throws<PqFormatException>(() =>
            new PqVerifier().VerifyBytes(data, [], keyPair.PublicKey));
    }

    [Fact]
    public async Task Wrong_length_signature_file_is_a_format_error()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        string dir = Directory.CreateTempSubdirectory("pqfe-sig-").FullName;
        try
        {
            string dataPath = Path.Combine(dir, "data.bin");
            string sigPath = dataPath + ".sig";
            await File.WriteAllBytesAsync(dataPath, RandomBytes(100));
            await File.WriteAllBytesAsync(sigPath, RandomBytes(10));

            await Assert.ThrowsAsync<PqFormatException>(() =>
                new PqVerifier().VerifyFileAsync(dataPath, sigPath, keyPair.PublicKey));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    // ---------------------------------------------------------------- key hygiene

    [Fact]
    public void Disposed_private_key_throws_and_cannot_sign()
    {
        var keyPair = PqSigningKeyPair.Generate();
        keyPair.Dispose();

        Assert.Throws<ObjectDisposedException>(() => keyPair.PrivateKey.Export());
        Assert.Throws<ObjectDisposedException>(() =>
            new PqSigner().SignBytes(RandomBytes(10), keyPair.PrivateKey));
    }

    [Fact]
    public void Malformed_key_imports_are_rejected()
    {
        Assert.Throws<ArgumentException>(() => PqSigningPublicKey.Import(new byte[10]));
        Assert.Throws<ArgumentException>(() => PqSigningPrivateKey.Import(new byte[10]));
        Assert.Throws<ArgumentNullException>(() => PqSigningPublicKey.Import(null!));
        Assert.Throws<ArgumentNullException>(() => PqSigningPrivateKey.Import(null!));
    }
}
