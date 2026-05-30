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
}
