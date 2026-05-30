using System.Security.Cryptography;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Shared helpers and fixtures for the symmetric-engine tests.</summary>
internal static class TestSupport
{
    public const string Passphrase = "a solid test passphrase";

    /// <summary>Fast options (minimum PBKDF2 cost) so the suite stays quick.</summary>
    public static PqEncryptionOptions Fast(int chunkSize = 1024) => new()
    {
        Pbkdf2Iterations = PqEncryptionOptions.MinPbkdf2Iterations,
        ChunkSizeBytes = chunkSize,
    };

    public static byte[] RandomBytes(int count)
    {
        var bytes = new byte[count];
        RandomNumberGenerator.Fill(bytes);
        return bytes;
    }

    /// <summary>An <see cref="IProgress{T}"/> that records every report synchronously.</summary>
    public sealed class RecordingProgress : IProgress<PqProgress>
    {
        public List<PqProgress> Reports { get; } = new();
        public void Report(PqProgress value) => Reports.Add(value);
    }
}

/// <summary>
/// A read-only, <b>non-seekable</b> stream over a byte buffer — used to exercise the engine's
/// behavior when it cannot know the input length up front (e.g. network or pipe sources).
/// </summary>
internal sealed class ForwardOnlyStream(byte[] data) : Stream
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

    public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
        _inner.ReadAsync(buffer, cancellationToken);

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
