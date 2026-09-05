using System.Text;
using System.Text.Json;
using PostQuantum.FileEncryption.Hybrid;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// <see cref="PqContainerInfo"/> must report exactly what the header declares, for every key
/// source, without any key derivation — and its structural acceptance must mirror the real
/// reader's exactly, which the conformance-corpus consistency test pins: anything the frozen
/// reader rejects structurally, Read rejects; anything it accepts (or rejects only at
/// authentication), Read inspects.
/// </summary>
public sealed class PqContainerInfoTests
{
    [Fact]
    public async Task Reports_pbkdf2_passphrase_facts_and_exact_plaintext_bound()
    {
        byte[] plaintext = RandomBytes(4096);
        byte[] container = await new PqFileEncryptor(Fast(1024)).EncryptBytesAsync(plaintext, Passphrase);

        var info = PqContainerInfo.Read(container);

        Assert.Equal(2, info.FormatVersion);
        Assert.Equal(PqKeySource.Passphrase, info.KeySource);
        Assert.Equal(1024, info.ChunkSizeBytes);
        Assert.Equal(PqKdf.Pbkdf2HmacSha256, info.Kdf);
        Assert.Equal(PqEncryptionOptions.MinPbkdf2Iterations, info.Pbkdf2Iterations);
        Assert.Equal(16, info.SaltSizeBytes);
        Assert.Null(info.Argon2MemoryKiB);
        Assert.Null(info.RecipientCount);
        Assert.Null(info.KeyProviderId);
        Assert.Equal(4096, info.PlaintextSizeUpperBoundBytes);
    }

    [Fact]
    public async Task Reports_argon2id_work_factors()
    {
        var options = new PqEncryptionOptions
        {
            Kdf = PqKdf.Argon2id,
            Argon2MemoryKiB = 8 * 1024,
            Argon2Iterations = 2,
            Argon2Parallelism = 3,
            ChunkSizeBytes = 1024,
        };
        byte[] container = await new PqFileEncryptor(options).EncryptBytesAsync(RandomBytes(100), Passphrase);

        var info = PqContainerInfo.Read(container);

        Assert.Equal(PqKdf.Argon2id, info.Kdf);
        Assert.Equal(8 * 1024, info.Argon2MemoryKiB);
        Assert.Equal(2, info.Argon2Iterations);
        Assert.Equal(3, info.Argon2Parallelism);
        Assert.Null(info.Pbkdf2Iterations);
    }

    [Fact]
    public async Task Reports_hybrid_recipient_counts()
    {
        using var alice = PqHybridKeyPair.Generate();
        using var bob = PqHybridKeyPair.Generate();

        byte[] single = await new PqHybridEncryptor(Fast()).EncryptBytesAsync(RandomBytes(64), alice.PublicKey);
        var singleInfo = PqContainerInfo.Read(single);
        Assert.Equal(PqKeySource.HybridRecipient, singleInfo.KeySource);
        Assert.Equal(1, singleInfo.RecipientCount);
        Assert.Null(singleInfo.Kdf);

        byte[] multi = await new PqHybridEncryptor(Fast()).EncryptBytesToAsync(RandomBytes(64), [alice.PublicKey, bob.PublicKey]);
        var multiInfo = PqContainerInfo.Read(multi);
        Assert.Equal(PqKeySource.HybridMultiRecipient, multiInfo.KeySource);
        Assert.Equal(2, multiInfo.RecipientCount);
    }

    [Fact]
    public async Task Reports_and_sanitizes_the_key_provider_id()
    {
        using var provider = LocalKekContentKeyProvider.Generate();
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(64), provider);

        var info = PqContainerInfo.Read(container);
        Assert.Equal(PqKeySource.KeyProvider, info.KeySource);
        Assert.Equal("local-kek", info.KeyProviderId);

        // The provider id is attacker-controlled header text: a control character must never
        // pass through to logs/terminals. Patch one into the id in place (the header is AAD,
        // so decryption would reject this container — inspection still reads it, by design).
        byte[] hostile = (byte[])container.Clone();
        hostile[19] = 0x1B; // first provider-id byte (KeyParams start at 18: len byte, then id)
        Assert.True(PqContainerInfo.TryRead(hostile, out var hostileInfo));
        Assert.Contains('?', hostileInfo!.KeyProviderId!);
        Assert.DoesNotContain('\x1B', hostileInfo.KeyProviderId!);
    }

    [Fact]
    public async Task Read_file_reads_only_the_header()
    {
        string path = Path.Combine(Path.GetTempPath(), $"pqfe-info-{Guid.NewGuid():N}.pqfe");
        try
        {
            byte[] plaintext = RandomBytes(3000);
            byte[] container = await new PqFileEncryptor(Fast(1024)).EncryptBytesAsync(plaintext, Passphrase);
            await File.WriteAllBytesAsync(path, container);

            var info = await PqContainerInfo.ReadFileAsync(path);
            Assert.Equal(PqKeySource.Passphrase, info.KeySource);
            Assert.Equal(3000, info.PlaintextSizeUpperBoundBytes);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void Truncated_and_garbage_input_fail_closed()
    {
        Assert.Throws<PqFormatException>(() => PqContainerInfo.Read(new byte[4]));
        Assert.False(PqContainerInfo.TryRead(RandomBytes(64), out _));
        Assert.False(PqContainerInfo.TryRead([], out _));
    }

    [Fact]
    public void Structural_acceptance_mirrors_the_frozen_reader_across_the_conformance_corpus()
    {
        string dir = Path.Combine(ConformanceManifestTests.FindRepositoryRoot(), "test-vectors");
        using var manifest = JsonDocument.Parse(File.ReadAllText(Path.Combine(dir, "manifest.json")));

        foreach (JsonElement v in manifest.RootElement.GetProperty("vectors").EnumerateArray())
        {
            string id = v.GetProperty("id").GetString()!;
            string file = v.GetProperty("file").GetString()!;
            string expect = v.GetProperty("expect").GetString()!;
            byte[] bytes = File.ReadAllBytes(Path.Combine(dir, file));

            bool readable = PqContainerInfo.TryRead(bytes, out var info);
            if (expect == "reject-format")
            {
                Assert.False(readable, $"{id}: inspection must reject what the reader rejects structurally");
            }
            else
            {
                // accept, lenient, and reject-decryption (auth-stage) vectors all carry a
                // structurally valid header, so inspection must succeed and agree on the mode.
                Assert.True(readable, $"{id}: inspection must read a structurally valid header");
                if (v.TryGetProperty("keySource", out JsonElement ks))
                {
                    Assert.Equal(ks.GetInt32(), (int)info!.KeySource);
                }
            }
        }
    }
}
