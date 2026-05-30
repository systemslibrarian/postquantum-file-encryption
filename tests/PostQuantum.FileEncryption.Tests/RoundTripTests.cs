using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Core round-trip and fail-closed behavior: plaintext that goes in must come back out
/// byte-for-byte, and anything wrong (passphrase, tampering, truncation, bad format) must
/// be rejected rather than silently mishandled.
/// </summary>
public sealed class RoundTripTests : IDisposable
{
    private const string Passphrase = "correct horse battery staple";

    // Fast KDF + small chunks keep the suite quick while still exercising multi-chunk paths.
    private static readonly PqEncryptionOptions FastOptions = new()
    {
        Pbkdf2Iterations = PqEncryptionOptions.MinPbkdf2Iterations,
        ChunkSizeBytes = 1024,
    };

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pqfe-tests-" + Guid.NewGuid().ToString("N"));

    public RoundTripTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private string Path2(string name) => Path.Combine(_dir, name);

    private static byte[] RandomBytes(int length)
    {
        var data = new byte[length];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    [Theory]
    [InlineData(0)]       // empty
    [InlineData(1)]       // single byte
    [InlineData(1024)]    // exactly one chunk
    [InlineData(2048)]    // exactly two chunks (boundary case for the final-frame logic)
    [InlineData(5000)]    // several chunks, ragged last one
    public async Task File_round_trip_recovers_original_bytes(int size)
    {
        byte[] original = RandomBytes(size);
        string plain = Path2("plain.bin");
        string cipher = Path2("cipher.pqfe");
        string restored = Path2("restored.bin");
        await File.WriteAllBytesAsync(plain, original);

        await new PqFileEncryptor(FastOptions).EncryptFileAsync(plain, cipher, Passphrase);
        await new PqFileDecryptor().DecryptFileAsync(cipher, restored, Passphrase);

        Assert.Equal(original, await File.ReadAllBytesAsync(restored));
    }

    [Fact]
    public async Task File_round_trip_with_default_options_recovers_original_bytes()
    {
        byte[] original = RandomBytes(64 * 1024 + 7);
        string plain = Path2("plain.bin");
        string cipher = Path2("cipher.pqfe");
        string restored = Path2("restored.bin");
        await File.WriteAllBytesAsync(plain, original);

        await new PqFileEncryptor().EncryptFileAsync(plain, cipher, Passphrase);
        await new PqFileDecryptor().DecryptFileAsync(cipher, restored, Passphrase);

        Assert.Equal(original, await File.ReadAllBytesAsync(restored));
    }

    [Fact]
    public async Task Stream_round_trip_recovers_original_bytes()
    {
        byte[] original = RandomBytes(5000);
        using var cipher = new MemoryStream();
        using var restored = new MemoryStream();

        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        cipher.Position = 0;
        await new PqFileDecryptor().DecryptAsync(cipher, restored, Passphrase);

        Assert.Equal(original, restored.ToArray());
    }

    [Fact]
    public async Task Ciphertext_is_not_the_plaintext()
    {
        byte[] original = RandomBytes(2048);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), cipher, Passphrase);

        Assert.False(cipher.ToArray().AsSpan().IndexOf(original.AsSpan()) >= 0,
            "Plaintext must not appear verbatim in the container.");
    }

    [Fact]
    public async Task Encrypting_the_same_input_twice_yields_different_containers()
    {
        byte[] original = RandomBytes(2048);
        using var a = new MemoryStream();
        using var b = new MemoryStream();
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), a, Passphrase);
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), b, Passphrase);

        // Random salt + nonce prefix per file ⇒ ciphertexts differ even for identical input.
        Assert.NotEqual(a.ToArray(), b.ToArray());
    }

    [Fact]
    public async Task Progress_reaches_completion()
    {
        byte[] original = RandomBytes(5000);
        string plain = Path2("plain.bin");
        string cipher = Path2("cipher.pqfe");
        await File.WriteAllBytesAsync(plain, original);

        var reports = new List<PqProgress>();
        var progress = new SynchronousProgress(reports.Add);
        await new PqFileEncryptor(FastOptions).EncryptFileAsync(plain, cipher, Passphrase, progress);

        Assert.NotEmpty(reports);
        Assert.Equal(original.Length, reports[^1].BytesProcessed);
        Assert.Equal(1.0, reports[^1].Fraction);
    }

    [Fact]
    public async Task Wrong_passphrase_fails_closed_and_leaves_no_output()
    {
        byte[] original = RandomBytes(2048);
        string plain = Path2("plain.bin");
        string cipher = Path2("cipher.pqfe");
        string restored = Path2("restored.bin");
        await File.WriteAllBytesAsync(plain, original);
        await new PqFileEncryptor(FastOptions).EncryptFileAsync(plain, cipher, Passphrase);

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptFileAsync(cipher, restored, "wrong passphrase"));

        Assert.False(File.Exists(restored), "No plaintext must be left behind on a failed decryption.");
    }

    [Fact]
    public async Task Tampered_ciphertext_is_rejected()
    {
        byte[] original = RandomBytes(2048);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), cipher, Passphrase);

        byte[] tampered = cipher.ToArray();
        tampered[^1] ^= 0xFF; // flip a bit in the final authentication tag

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(tampered), restored, Passphrase));
    }

    [Fact]
    public async Task Truncated_container_is_rejected()
    {
        byte[] original = RandomBytes(5000); // multiple chunks
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(FastOptions).EncryptAsync(new MemoryStream(original), cipher, Passphrase);

        // Drop the final frame entirely; an attacker who truncates must not get partial plaintext accepted.
        byte[] truncated = cipher.ToArray()[..1500];

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(truncated), restored, Passphrase));
    }

    [Fact]
    public async Task Non_container_input_is_rejected_as_format_error()
    {
        using var garbage = new MemoryStream(RandomBytes(512));
        using var restored = new MemoryStream();

        await Assert.ThrowsAsync<PqFormatException>(() =>
            new PqFileDecryptor().DecryptAsync(garbage, restored, Passphrase));
    }

    /// <summary>An <see cref="IProgress{T}"/> that invokes its callback inline, for deterministic assertions.</summary>
    private sealed class SynchronousProgress(Action<PqProgress> onReport) : IProgress<PqProgress>
    {
        public void Report(PqProgress value) => onReport(value);
    }
}
