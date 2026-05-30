using PostQuantum.FileEncryption.Hybrid;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// The X25519 + ML-KEM-768 hybrid recipient package. Fully exercised here (BouncyCastle provides
/// managed ML-KEM, so no native platform support is needed).
/// </summary>
public sealed class HybridTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5000)]
    [InlineData(70000)]
    public async Task Single_recipient_round_trip(int size)
    {
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] original = RandomBytes(size);

        byte[] container = await new PqHybridEncryptor(Fast()).EncryptBytesAsync(original, keyPair.PublicKey);
        byte[] restored = await new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey);

        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Public_and_private_keys_round_trip_through_export_import()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        var pub = PqHybridPublicKey.Import(keyPair.PublicKey.Export());
        using var priv = PqHybridPrivateKey.Import(keyPair.PrivateKey.Export());

        byte[] original = RandomBytes(1000);
        byte[] container = await new PqHybridEncryptor(Fast()).EncryptBytesAsync(original, pub);
        Assert.Equal(original, await new PqHybridDecryptor().DecryptBytesAsync(container, priv));
    }

    [Fact]
    public async Task Wrong_private_key_fails_closed()
    {
        using var alice = PqHybridKeyPair.Generate();
        using var mallory = PqHybridKeyPair.Generate();

        byte[] container = await new PqHybridEncryptor(Fast()).EncryptBytesAsync(RandomBytes(2000), alice.PublicKey);
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqHybridDecryptor().DecryptBytesAsync(container, mallory.PrivateKey));
    }

    [Fact]
    public async Task Tampered_hybrid_container_is_rejected()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] container = await new PqHybridEncryptor(Fast()).EncryptBytesAsync(RandomBytes(2000), keyPair.PublicKey);
        container[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqHybridDecryptor().DecryptBytesAsync(container, keyPair.PrivateKey));
    }

    [Fact]
    public async Task Multi_recipient_any_one_can_open()
    {
        using var alice = PqHybridKeyPair.Generate();
        using var bob = PqHybridKeyPair.Generate();
        using var carol = PqHybridKeyPair.Generate();
        using var outsider = PqHybridKeyPair.Generate();

        byte[] original = RandomBytes(4000);
        var recipients = new[] { alice.PublicKey, bob.PublicKey, carol.PublicKey };
        byte[] container = await new PqHybridEncryptor(Fast()).EncryptBytesToAsync(original, recipients);

        // Each listed recipient recovers the plaintext...
        foreach (var key in new[] { alice.PrivateKey, bob.PrivateKey, carol.PrivateKey })
        {
            Assert.Equal(original, await new PqHybridDecryptor().DecryptBytesAsync(container, key));
        }
        // ...an outsider cannot.
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqHybridDecryptor().DecryptBytesAsync(container, outsider.PrivateKey));
    }

    [Fact]
    public async Task Stream_and_file_apis_round_trip()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] original = RandomBytes(6000);

        // stream
        using var cipher = new MemoryStream();
        await new PqHybridEncryptor(Fast()).EncryptAsync(new MemoryStream(original), cipher, keyPair.PublicKey);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqHybridDecryptor().DecryptAsync(cipher, restored, keyPair.PrivateKey);
        Assert.Equal(original, restored.ToArray());

        // file
        string dir = Path.Combine(Path.GetTempPath(), "pqfe-hybrid-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            string plain = Path.Combine(dir, "p.bin"), ct = Path.Combine(dir, "c.pqfe"), outp = Path.Combine(dir, "o.bin");
            await File.WriteAllBytesAsync(plain, original);
            await new PqHybridEncryptor(Fast()).EncryptFileAsync(plain, ct, keyPair.PublicKey);
            await new PqHybridDecryptor().DecryptFileAsync(ct, outp, keyPair.PrivateKey);
            Assert.Equal(original, await File.ReadAllBytesAsync(outp));
        }
        finally { Directory.Delete(dir, true); }
    }

    // Pinned decrypt known-answer vector (encryption is randomized — ML-KEM coins aren't
    // injectable — so this pins the decrypt path / format, not byte-exact output).
    private const string KatPrivateKey =
        "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";
    private const string KatContainer =
        "UFFGRQIBAwAAAAQA2g2ZigSfAQRAZ4AWIQX6Z4DWWmftkB2KGoxtf6RhLs8geuuRT2pj/2QikuNdAnP6l847oCtSveHsgL1V975wX1pZqE21O3fYgNjPxVVsgECjxh0/jRl3L/iToUQ1hysWlHneJaK3L4WEAd6RZbM20//cjj4zvodHrcWzNBTx3rVEzdpvIgYn53OwSPvjiUs/3T+1G/4aIhDgU6nInvqsKdxSMDB3MVXCWg6L3+97duTccyHkztlq+c/a3x519fIsPx/3RHVLXXmb9GCy7A8inSWjHo/zvSUaXLLc1p6Cm4+XOBB0VrRHQttUAJ4JdSQS5BqThNeR0pLbrNTBWUT2bZxqk/G+k5sZWvpGln+jYhenGkaOxraOzLXp5X298bk2uO3ItDyICMbg7eQyPsuf6wFAY+a+8/1CE4JKJzMPHZZ74tdlIUu1nF3VsEAxmQlQReatml1yc7k0k8dWqhoRjRSkqdWwvZKYT8tJHUZvkv8EVTrPB2UqV5nvR0RG0w7xHNkurfwSPIXovV/4ALkZ2/xno13peOR4zpjhRlaRVA0Y28SETygV5Mk1yhBdHkHUmxJAOteJ95V1Rab2WXgy01XWsnlksP29xOUoqqy0BCN4G5CKTU8so381ZYAT4ety6ZdVkEn1mIXKorimivrUcn50ClzNOHWC0H7FqfbQZDFoaCpVvIkVLjpJPU5TY6VytxuxvTbAapMdj1oVDF4HzWLQJBPv/pqb0nfDNhUteZZzDwTDTgVfiJdSEI2aBY60iZ7QnVghm/Yrp1+Z492ZSB0FOVvfyNcafrsaYLnfFPpfJWVNDqCx1wcteDja0C19dL3K83mL32rCM8487U47QCV7ML5wpn/ubfK0xEMl21WvmMynPmZZnNiYZXzb9AEL450uSNHVXh041sclFsusJi8ebv7/OuClAvMOc7PMlj5V2a91hdXfbCKZE13s8pB8ziMeFSNzNMpivI7F2lnJKbzQ5jhClxa9L+Fu+onSowbDgUDEBmjpvD10sBHn2RccX/OGDY8hIaeqt4q6q7isJ13hi/nn6P6pfh4s4OX7ikausvkecEUrGnlG/0izg/L1jRUNrCVCwROBw3QzhDetH4v/+NB3XvKN/Ohsk8vwwJYFz5T0Oz82EUs/ZXRe8HXBiwpmVZoW5ZfSvjMcTSJKli5XcwF7RkCdr8oUvuJszkE2i4OAbt9wwHMb4Ue/mkhjbMQKdprCQqmxYZ0K7h6ed2BX4I3i9jVTdpGaNqDQEZ3ryxYx86WGkvm8gGSOe4wlZ4xpOuc+nazvaO9EcLH6/xrbB0Z27J4ZI/ZxC3Xqd967WoD+hgLBN1GSzEJXs+19bJEyp/YIlQZcUhKmu6Kvhe8FynDXqZtZe6v/YYMAQGJoe49SJwRs112iKUeS9W+XCZUTUgsATUVhaxkpBBOBq2xwa6N+lHoyqveeQ2mVbUL6WIHe/YC2TL5fHPbw8DthZhCDIovnh6kKKNY2xMxnHRLt2lBkZdzrQ0jzOJcHAoSdx5aTUiPSnAuqPt9nrAyN37hZXpkIhDsxLLPdQVTcG2qUHacjxWlPs9rUF8ldUWcGhMpxhQEAAAAlLx9o/hRYAan41QMded3/QAknOanyOtR+V7Dh2rNdO0eiHonVS7KQCAvrIrUKhG6AQlC6ntQ=";

    [Fact]
    public async Task Pinned_hybrid_container_decrypts()
    {
        using var key = PqHybridPrivateKey.Import(Convert.FromBase64String(KatPrivateKey));
        byte[] restored = await new PqHybridDecryptor().DecryptBytesAsync(Convert.FromBase64String(KatContainer), key);
        Assert.Equal("Hybrid X25519+ML-KEM-768 decrypt KAT.", System.Text.Encoding.ASCII.GetString(restored));
    }

    [Fact]
    public async Task Core_passphrase_decryptor_rejects_a_hybrid_container()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] container = await new PqHybridEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), keyPair.PublicKey);

        // The symmetric decryptor must not silently mishandle a recipient container.
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, "any passphrase"));
    }
}
