using System.Text;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>The in-memory <c>EncryptBytesAsync</c> / <c>DecryptBytesAsync</c> convenience API.</summary>
public sealed class BytesApiTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(4096)]
    public async Task Bytes_round_trip(int size)
    {
        byte[] original = RandomBytes(size);
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, Passphrase);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, Passphrase);
        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Bytes_round_trip_with_byte_passphrase()
    {
        byte[] original = RandomBytes(2000);
        byte[] pass = Encoding.UTF8.GetBytes("byte-passphrase");
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, pass);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, pass);
        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Wrong_passphrase_throws()
    {
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), Passphrase);
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, "the wrong passphrase"));
    }

    [Fact]
    public async Task Tampered_bytes_throw()
    {
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), Passphrase);
        container[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, Passphrase));
    }

    [Fact]
    public async Task Bytes_api_interoperates_with_stream_api()
    {
        // Encrypt with the bytes API, decrypt with the stream API — same container format.
        byte[] original = RandomBytes(5000);
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, Passphrase);

        using var output = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(new MemoryStream(container), output, Passphrase);
        Assert.Equal(original, output.ToArray());
    }
}
