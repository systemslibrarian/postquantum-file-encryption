using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Streaming behavior: large files, chunk boundaries, non-seekable sources, progress.</summary>
public sealed class StreamingTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pqfe-stream-" + Guid.NewGuid().ToString("N"));

    public StreamingTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { /* best effort */ } }
    private string P(string name) => Path.Combine(_dir, name);

    [Fact]
    public async Task Large_file_round_trips_through_the_file_api()
    {
        // ~2 MiB spread over many default-sized (64 KiB) chunks.
        byte[] original = RandomBytes(2 * 1024 * 1024 + 123);
        string plain = P("plain.bin"), cipher = P("cipher.pqfe"), restored = P("restored.bin");
        await File.WriteAllBytesAsync(plain, original);

        await new PqFileEncryptor(Fast(64 * 1024)).EncryptFileAsync(plain, cipher, Passphrase);
        await new PqFileDecryptor().DecryptFileAsync(cipher, restored, Passphrase);

        Assert.Equal(original, await File.ReadAllBytesAsync(restored));
    }

    [Theory]
    [InlineData(1024)]
    [InlineData(4096)]
    [InlineData(65536)]
    public async Task Round_trips_across_chunk_sizes(int chunkSize)
    {
        // Sizes around exact multiples of the chunk exercise the final-frame logic.
        foreach (int size in new[] { 0, chunkSize, chunkSize * 2, chunkSize * 3, chunkSize * 2 + 1 })
        {
            byte[] original = RandomBytes(size);
            using var cipher = new MemoryStream();
            await new PqFileEncryptor(Fast(chunkSize)).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
            cipher.Position = 0;
            using var restored = new MemoryStream();
            await new PqFileDecryptor().DecryptAsync(cipher, restored, Passphrase);
            Assert.Equal(original, restored.ToArray());
        }
    }

    [Fact]
    public async Task Encrypts_a_non_seekable_source()
    {
        byte[] original = RandomBytes(5000);
        using var cipher = new MemoryStream();
        // CanSeek == false, no explicit length: the engine must still stream it correctly.
        await new PqFileEncryptor(Fast()).EncryptAsync(new ForwardOnlyStream(original), cipher, Passphrase);
        cipher.Position = 0;
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(cipher, restored, Passphrase);
        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task Decrypts_a_non_seekable_container_source()
    {
        byte[] original = RandomBytes(5000);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Fast()).EncryptAsync(new MemoryStream(original), cipher, Passphrase);

        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(new ForwardOnlyStream(cipher.ToArray()), restored, Passphrase);
        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task Progress_is_monotonic_and_reaches_the_total()
    {
        byte[] original = RandomBytes(10_000);
        var progress = new RecordingProgress();
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Fast(1024)).EncryptAsync(
            new MemoryStream(original), cipher, Passphrase, original.Length, progress);

        Assert.NotEmpty(progress.Reports);
        long previous = 0;
        foreach (var p in progress.Reports)
        {
            Assert.True(p.BytesProcessed >= previous, "progress must not go backwards");
            previous = p.BytesProcessed;
        }
        Assert.Equal(original.Length, progress.Reports[^1].BytesProcessed);
        Assert.Equal(1.0, progress.Reports[^1].Fraction);
    }

    [Fact]
    public async Task Progress_fraction_is_null_when_total_unknown()
    {
        byte[] original = RandomBytes(3000);
        var progress = new RecordingProgress();
        using var cipher = new MemoryStream();
        // Non-seekable source, no explicit total ⇒ TotalBytes unknown ⇒ Fraction null.
        await new PqFileEncryptor(Fast()).EncryptAsync(new ForwardOnlyStream(original), cipher, Passphrase, progress: progress);

        Assert.NotEmpty(progress.Reports);
        Assert.All(progress.Reports, p => Assert.Null(p.Fraction));
    }
}
