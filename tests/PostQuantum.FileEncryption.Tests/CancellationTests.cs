using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Cancellation honors the token and leaves no partial output behind.</summary>
public sealed class CancellationTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pqfe-cancel-" + Guid.NewGuid().ToString("N"));

    public CancellationTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { /* best effort */ } }
    private string P(string name) => Path.Combine(_dir, name);

    [Fact]
    public async Task Cancelled_token_cancels_stream_encryption()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PqFileEncryptor(Fast()).EncryptAsync(
                new MemoryStream(RandomBytes(50_000)), new MemoryStream(), Passphrase, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task Cancelled_token_cancels_stream_decryption()
    {
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(50_000), Passphrase);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(container), new MemoryStream(), Passphrase, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task Cancelled_file_encryption_leaves_no_output()
    {
        string plain = P("plain.bin"), cipher = P("cipher.pqfe");
        await File.WriteAllBytesAsync(plain, RandomBytes(50_000));

        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PqFileEncryptor(Fast()).EncryptFileAsync(plain, cipher, Passphrase, cancellationToken: cts.Token));

        Assert.False(File.Exists(cipher), "no output file should remain after a cancelled encryption");
    }

    [Fact]
    public async Task Cancellation_mid_operation_leaves_no_output_or_temp_file()
    {
        // The tests above pre-cancel the token, which only proves the entry check. Cancelling
        // from a progress callback lands mid-stream, after real chunks have been written to the
        // temp file — the per-chunk token check and the temp-file cleanup both have to work.
        string plain = P("plain.bin"), cipher = P("cipher.pqfe");
        await File.WriteAllBytesAsync(plain, RandomBytes(50_000));

        using var cts = new CancellationTokenSource();
        var cancelMidway = new CancelAfterFirstReport(cts);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PqFileEncryptor(Fast()).EncryptFileAsync(plain, cipher, Passphrase, cancelMidway, cts.Token));

        Assert.True(cancelMidway.Reports > 0, "the operation should have made progress before cancelling");
        Assert.False(File.Exists(cipher), "no output file should remain after a mid-stream cancellation");
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp-*"));
    }

    /// <summary>Reports synchronously (unlike <see cref="Progress{T}"/>) and cancels on the first chunk.</summary>
    private sealed class CancelAfterFirstReport(CancellationTokenSource cts) : IProgress<PqProgress>
    {
        public int Reports { get; private set; }
        public void Report(PqProgress value) { Reports++; cts.Cancel(); }
    }
}
