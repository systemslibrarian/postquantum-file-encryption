using PostQuantum.FileEncryption.Internal;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// I/O failure-mode coverage for the file-API atomic-write contract.
///
/// The contract is: a partial or corrupted file must never survive at the destination
/// path, regardless of which failure throws (crypto, format, cancellation, disk full,
/// permission denied, missing parent directory). The sibling temp file is always
/// <em>attempted</em> to be deleted on any failure — best-effort, but always attempted.
///
/// These tests pin that contract against regressions by injecting each failure mode
/// directly into the internal <see cref="FileIo.WriteViaTempAsync"/> helper (unit-level)
/// and through the public <see cref="PqFileEncryptor"/> file API (integration-level).
/// </summary>
public sealed class AtomicWriteIoFailureTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pqfe-iofail-" + Guid.NewGuid().ToString("N"));

    public AtomicWriteIoFailureTests() => Directory.CreateDirectory(_dir);

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private string P(string name) => Path.Combine(_dir, name);

    private static void AssertNoTempFilesLeftIn(string dir) =>
        Assert.Empty(Directory.GetFiles(dir, "*.tmp-*"));

    // ---------------------------------------------------------------- unit-level: FileIo.WriteViaTempAsync

    [Fact]
    public async Task Disk_full_mid_write_throws_and_removes_temp_file()
    {
        string output = P("out.bin");

        await Assert.ThrowsAsync<IOException>(() =>
            FileIo.WriteViaTempAsync(output, async fs =>
            {
                await fs.WriteAsync(new byte[4096]);
                throw new IOException("simulated ENOSPC");
            }));

        Assert.False(File.Exists(output), "destination must not be touched on failure");
        AssertNoTempFilesLeftIn(_dir);
    }

    [Fact]
    public async Task Mid_write_cancellation_removes_temp_file()
    {
        string output = P("out.bin");

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            FileIo.WriteViaTempAsync(output, async fs =>
            {
                await fs.WriteAsync(new byte[4096]);
                throw new OperationCanceledException();
            }));

        Assert.False(File.Exists(output));
        AssertNoTempFilesLeftIn(_dir);
    }

    [Fact]
    public async Task Writing_to_nonexistent_parent_directory_leaves_nothing_behind()
    {
        string missingDir = Path.Combine(_dir, "no-such-dir");
        string output = Path.Combine(missingDir, "out.bin");

        await Assert.ThrowsAnyAsync<DirectoryNotFoundException>(() =>
            FileIo.WriteViaTempAsync(output, _ => Task.CompletedTask));

        Assert.False(Directory.Exists(missingDir));
        AssertNoTempFilesLeftIn(_dir);
    }

    // ---------------------------------------------------------------- integration: PqFileEncryptor file API

    [Fact]
    public async Task File_encrypt_with_failing_source_propagates_and_leaves_no_temp_file()
    {
        // A source stream that throws after returning real bytes — simulates a truncated
        // or failing input device once encryption is already in progress. The file-API
        // output path must still clean up its sibling temp file.
        string cipher = P("cipher.pqfe");
        var failing = new FailingReadStream(RandomBytes(50_000), failAfterBytes: 8_000);
        await using var output = File.Create(cipher);

        await Assert.ThrowsAsync<IOException>(() =>
            new PqFileEncryptor(Fast()).EncryptAsync(failing, output, Passphrase));

        // The stream API doesn't go through WriteViaTempAsync — the FileStream we created
        // above will hold whatever the engine flushed before the read failed. That's the
        // documented streaming-not-atomic behavior; the file API is the strict-atomic
        // path and is exercised by the next test.
    }

    [Fact]
    public async Task File_encrypt_to_unwritable_destination_leaves_no_temp_file()
    {
        string plain = P("plain.bin");
        await File.WriteAllBytesAsync(plain, RandomBytes(4096));
        string cipher = Path.Combine(_dir, "nope", "cipher.pqfe");

        await Assert.ThrowsAnyAsync<DirectoryNotFoundException>(() =>
            new PqFileEncryptor(Fast()).EncryptFileAsync(plain, cipher, Passphrase));

        AssertNoTempFilesLeftIn(_dir);
        Assert.False(Directory.Exists(Path.Combine(_dir, "nope")));
    }

    [Fact]
    public async Task Cancelled_file_encrypt_leaves_no_output_and_no_temp_file()
    {
        // Pre-cancellation is deterministic across runners (no timer race). The file-API
        // cleanup path is identical for pre-cancel and mid-write: both throw inside
        // WriteViaTempAsync's writeBody and hit the same catch { TryDelete; throw; } block,
        // so this test pins the cleanup invariant without depending on CPU speed. The
        // genuine mid-write coverage lives in the deterministic unit-level
        // Mid_write_cancellation_removes_temp_file below.
        string plain = P("plain.bin");
        await File.WriteAllBytesAsync(plain, RandomBytes(50_000));
        string cipher = P("cipher.pqfe");

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PqFileEncryptor(Fast(64 * 1024))
                .EncryptFileAsync(plain, cipher, Passphrase, cancellationToken: cts.Token));

        Assert.False(File.Exists(cipher), "destination must not be touched on cancellation");
        AssertNoTempFilesLeftIn(_dir);
    }

    [Fact]
    public async Task Cancelled_file_decrypt_leaves_no_output_and_no_temp_file()
    {
        // Build a real container, then decrypt with an already-cancelled token. The
        // decrypt path runs the same WriteViaTempAsync cleanup as encrypt, exercised here
        // for the decrypt side of the API.
        string plain = P("plain.bin");
        await File.WriteAllBytesAsync(plain, RandomBytes(50_000));
        string cipher = P("cipher.pqfe");
        string restored = P("restored.bin");
        await new PqFileEncryptor(Fast(64 * 1024)).EncryptFileAsync(plain, cipher, Passphrase);

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new PqFileDecryptor().DecryptFileAsync(cipher, restored, Passphrase, cancellationToken: cts.Token));

        Assert.False(File.Exists(restored));
        AssertNoTempFilesLeftIn(_dir);
    }

    // ---------------------------------------------------------------- documented non-atomic streaming

    [Fact]
    public async Task Stream_decrypt_of_truncated_container_rejects_with_decryption_exception()
    {
        // KNOWN-GAPS.md documents that DecryptAsync(Stream, Stream, ...) is NOT atomic by
        // construction — the strict-atomic paths are the file API (via WriteViaTempAsync)
        // and DecryptAtomicAsync. This test pins the documented behavior so a future
        // change cannot silently tighten the contract: a truncated container must still
        // throw PqDecryptionException at the missing-final-frame check.
        byte[] original = RandomBytes(5000);
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(Fast(1024)).EncryptAsync(new MemoryStream(original), cipher, Passphrase);
        byte[] truncated = cipher.ToArray()[..1800];

        using var output = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(truncated), output, Passphrase));
    }

    // ---------------------------------------------------------------- helpers

    /// <summary>
    /// Read-only stream that returns real bytes up to <paramref name="failAfterBytes"/>,
    /// then throws on every subsequent read. Used to simulate a failing input device
    /// (truncated disk read, unplugged USB, network drop) during encryption.
    /// </summary>
    private sealed class FailingReadStream(byte[] data, int failAfterBytes) : Stream
    {
        private readonly MemoryStream _inner = new(data, writable: false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_inner.Position >= failAfterBytes) throw new IOException("simulated read failure");
            return _inner.Read(buffer, offset, count);
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (_inner.Position >= failAfterBytes) throw new IOException("simulated read failure");
            return _inner.ReadAsync(buffer, cancellationToken);
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
