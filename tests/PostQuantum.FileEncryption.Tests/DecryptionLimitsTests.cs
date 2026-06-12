using System.Security.Cryptography;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// <see cref="PqDecryptionLimits"/> must cap the work a hostile container header can demand
/// (KDF cost, chunk-buffer size) and reject over-limit headers fail-closed — with a
/// <see cref="PqFormatException"/>, before any derivation work — while leaving every
/// legitimately produced container decryptable under the defaults.
/// </summary>
public sealed class DecryptionLimitsTests
{
    private const string Passphrase = "a fairly long and reasonable passphrase";

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    private static async Task<byte[]> EncryptAsync(byte[] plaintext, PqEncryptionOptions options) =>
        await new PqFileEncryptor(options).EncryptBytesAsync(plaintext, Passphrase);

    // ---------------------------------------------------------------- KDF cost ceilings

    [Fact]
    public async Task Pbkdf2_iterations_above_the_limit_are_rejected_before_derivation()
    {
        var options = new PqEncryptionOptions { Pbkdf2Iterations = 150_000, ChunkSizeBytes = 1024 };
        byte[] container = await EncryptAsync(RandomBytes(64), options);

        var strict = new PqFileDecryptor(new PqDecryptionLimits { MaxPbkdf2Iterations = 100_000 });
        await Assert.ThrowsAsync<PqFormatException>(() => strict.DecryptBytesAsync(container, Passphrase));

        // The same container opens fine under the defaults — the limit, not the container, is strict.
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, Passphrase);
        Assert.Equal(64, restored.Length);
    }

    [Fact]
    public async Task Argon2id_memory_above_the_limit_is_rejected_before_derivation()
    {
        var options = new PqEncryptionOptions
        {
            Kdf = PqKdf.Argon2id,
            Argon2MemoryKiB = 16 * 1024, // 16 MiB — cheap enough for the suite
            Argon2Iterations = 1,
            ChunkSizeBytes = 1024,
        };
        byte[] container = await EncryptAsync(RandomBytes(64), options);

        var strict = new PqFileDecryptor(new PqDecryptionLimits { MaxArgon2MemoryKiB = 8 * 1024 });
        await Assert.ThrowsAsync<PqFormatException>(() => strict.DecryptBytesAsync(container, Passphrase));
    }

    [Fact]
    public async Task Argon2id_iterations_above_the_limit_are_rejected_before_derivation()
    {
        var options = new PqEncryptionOptions
        {
            Kdf = PqKdf.Argon2id,
            Argon2MemoryKiB = PqEncryptionOptions.MinArgon2MemoryKiB,
            Argon2Iterations = 2,
            ChunkSizeBytes = 1024,
        };
        byte[] container = await EncryptAsync(RandomBytes(64), options);

        var strict = new PqFileDecryptor(new PqDecryptionLimits { MaxArgon2Iterations = 1 });
        await Assert.ThrowsAsync<PqFormatException>(() => strict.DecryptBytesAsync(container, Passphrase));
    }

    // ---------------------------------------------------------------- chunk-size ceiling

    [Fact]
    public async Task Chunk_size_above_the_limit_is_rejected_before_key_derivation()
    {
        var options = new PqEncryptionOptions { ChunkSizeBytes = 2 * 1024 * 1024 };
        byte[] container = await EncryptAsync(RandomBytes(64), options);

        var strict = new PqFileDecryptor(new PqDecryptionLimits { MaxChunkSizeBytes = 1024 * 1024 });
        // Wrong passphrase on purpose: the chunk limit is key-independent and must fire first,
        // as PqFormatException — never as a key-dependent decryption failure.
        await Assert.ThrowsAsync<PqFormatException>(
            () => strict.DecryptBytesAsync(container, "not even the right passphrase"));
    }

    // ---------------------------------------------------------------- presets & validation

    [Fact]
    public async Task Untrusted_preset_accepts_containers_produced_with_default_options()
    {
        byte[] original = RandomBytes(5000);
        byte[] container = await EncryptAsync(original, PqEncryptionOptions.Default);

        byte[] restored = await new PqFileDecryptor(PqDecryptionLimits.Untrusted)
            .DecryptBytesAsync(container, Passphrase);

        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Untrusted_preset_accepts_argon2id_containers_produced_with_the_preset()
    {
        byte[] original = RandomBytes(2000);
        byte[] container = await EncryptAsync(original, PqEncryptionOptions.Argon2id);

        byte[] restored = await new PqFileDecryptor(PqDecryptionLimits.Untrusted)
            .DecryptBytesAsync(container, Passphrase);

        Assert.Equal(original, restored);
    }

    [Fact]
    public void Limits_outside_the_format_range_throw_at_construction()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PqFileDecryptor(new PqDecryptionLimits { MaxPbkdf2Iterations = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PqFileDecryptor(new PqDecryptionLimits { MaxArgon2MemoryKiB = 1 }));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PqFileDecryptor(new PqDecryptionLimits { MaxChunkSizeBytes = 16 }));
        Assert.Throws<ArgumentNullException>(() => new PqFileDecryptor(null!));
    }

    // ---------------------------------------------------------------- allocation cap (PQFE-002)

    [Fact]
    public async Task Tiny_container_with_a_huge_declared_chunk_still_round_trips()
    {
        // The engine caps its chunk buffers to what the container's known length can hold;
        // this guards the cap arithmetic across the awkward edges (1-byte and empty payloads
        // under the maximum declarable chunk size).
        var options = new PqEncryptionOptions { ChunkSizeBytes = 16 * 1024 * 1024 };

        foreach (int size in new[] { 0, 1, 17 })
        {
            byte[] original = RandomBytes(size);
            byte[] container = await EncryptAsync(original, options);
            byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, Passphrase);
            Assert.Equal(original, restored);
        }
    }

    [Fact]
    public async Task Non_seekable_stream_decryption_still_round_trips()
    {
        // Unknown-length input takes the uncapped buffer path; make sure it stays correct.
        byte[] original = RandomBytes(3000);
        var options = new PqEncryptionOptions { ChunkSizeBytes = 1024 };
        using var cipher = new MemoryStream();
        await new PqFileEncryptor(options).EncryptAsync(new MemoryStream(original), cipher, Passphrase);

        using var nonSeekable = new NonSeekableReadStream(cipher.ToArray());
        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(nonSeekable, restored, Passphrase);

        Assert.Equal(original, restored.ToArray());
    }

    private sealed class NonSeekableReadStream(byte[] data) : Stream
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
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
