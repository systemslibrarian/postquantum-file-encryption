using System.Buffers.Binary;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>Argument validation, options validation, and structural-attack rejection.</summary>
public sealed class ErrorHandlingTests
{
    // ---- argument validation ----

    [Fact]
    public async Task File_api_rejects_null_or_empty_arguments()
    {
        var enc = new PqFileEncryptor(Fast());
        await Assert.ThrowsAnyAsync<ArgumentException>(() => enc.EncryptFileAsync("", "out.pqfe", Passphrase));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => enc.EncryptFileAsync("in", "", Passphrase));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => enc.EncryptFileAsync("in", "out.pqfe", ""));
    }

    [Fact]
    public async Task Stream_api_rejects_null_streams()
    {
        var enc = new PqFileEncryptor(Fast());
        await Assert.ThrowsAnyAsync<ArgumentNullException>(() => enc.EncryptAsync(null!, new MemoryStream(), Passphrase));
        await Assert.ThrowsAnyAsync<ArgumentNullException>(() => enc.EncryptAsync(new MemoryStream(), null!, Passphrase));
    }

    // ---- options validation ----

    [Theory]
    [InlineData(0)]                                         // far below min chunk
    [InlineData(PqEncryptionOptions.MinChunkSizeBytes - 1)]
    [InlineData(PqEncryptionOptions.MaxChunkSizeBytes + 1)]
    public void Invalid_chunk_size_is_rejected(int chunkSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PqFileEncryptor(new PqEncryptionOptions { ChunkSizeBytes = chunkSize }));
    }

    [Fact]
    public void Invalid_salt_size_is_rejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new PqFileEncryptor(new PqEncryptionOptions { SaltSizeBytes = 1 }));
    }

    // ---- structural attacks ----

    [Fact]
    public async Task Reordered_chunks_are_rejected()
    {
        // Two full 1024-byte chunks ⇒ two equal-size frames we can swap on disk.
        byte[] original = RandomBytes(2048);
        using var cipherStream = new MemoryStream();
        await new PqFileEncryptor(Fast(1024)).EncryptAsync(new MemoryStream(original), cipherStream, Passphrase);
        byte[] container = cipherStream.ToArray();

        int keyParamsLen = BinaryPrimitives.ReadUInt16BigEndian(container.AsSpan(16, 2));
        int headerLen = 18 + keyParamsLen;
        int frameLen = 1 + 4 + 1024 + 16; // type + length + ciphertext + tag

        // Swap the two frame bodies — each chunk's position is authenticated, so this must fail.
        var swapped = (byte[])container.Clone();
        Array.Copy(container, headerLen + frameLen, swapped, headerLen, frameLen);
        Array.Copy(container, headerLen, swapped, headerLen + frameLen, frameLen);

        using var output = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(swapped), output, Passphrase));
    }

    [Fact]
    public async Task Unsupported_format_version_is_a_format_error()
    {
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(100), Passphrase);
        container[4] = 99; // FormatVersion byte

        using var output = new MemoryStream();
        await Assert.ThrowsAsync<PqFormatException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(container), output, Passphrase));
    }

    [Fact]
    public async Task Empty_input_is_not_a_container()
    {
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<PqFormatException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(Array.Empty<byte>()), output, Passphrase));
    }
}
