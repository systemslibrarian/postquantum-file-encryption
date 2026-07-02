using System.Buffers.Binary;
using System.Text;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pinned known-answer vectors. These fixed containers were produced by an earlier build and
/// must keep decrypting to the same plaintext. If a change to the format or the cryptography
/// breaks them, that is a deliberate, breaking change — bump the format version and regenerate
/// the vectors on purpose.
/// </summary>
public sealed class KnownAnswerVectorTests
{
    private const string Passphrase = "test-vector-passphrase";
    private static readonly byte[] ExpectedPlaintext =
        Encoding.UTF8.GetBytes("PostQuantum.FileEncryption known-answer vector v2.");

    // KeySource = passphrase, KDF = PBKDF2-HMAC-SHA256 (100,000 iters), 16-byte salt, 1 KiB chunks.
    private const string Pbkdf2Vector =
        "UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj";

    // KeySource = passphrase, KDF = Argon2id (8 MiB, 1 pass, 1 lane), 16-byte salt, 1 KiB chunks.
    private const string Argon2Vector =
        "UFFGRQIBAQAAAAQAS7aXNQAbAhCZBPTffR0AgJ7we1bozxQOAAAgAAAAAAEBAQAAADJOzagbj5vUN9WHVWy1t7KN/pG9O5ab04z0IO4xyV5vRMxDN2TsXQGStrNyW5eC77skRpx0WhB0BC6SxsnfnwherIM=";

    [Theory]
    [InlineData(Pbkdf2Vector)]
    [InlineData(Argon2Vector)]
    public async Task Pinned_container_decrypts_to_known_plaintext(string base64Container)
    {
        byte[] container = Convert.FromBase64String(base64Container);

        using var restored = new MemoryStream();
        await new PqFileDecryptor().DecryptAsync(new MemoryStream(container), restored, Passphrase);

        Assert.Equal(ExpectedPlaintext, restored.ToArray());
    }

    [Fact]
    public async Task Pinned_container_rejects_a_wrong_passphrase()
    {
        byte[] container = Convert.FromBase64String(Pbkdf2Vector);

        using var restored = new MemoryStream();
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptAsync(new MemoryStream(container), restored, "wrong"));
    }

    // ------------------------------------------------------------------ multi-chunk vector

    // 3,000 bytes at 1 KiB chunks (PBKDF2, 100,000 iters): two full data frames + a final
    // frame. The single-chunk vectors above never exercise the per-chunk nonce counter or the
    // AAD chaining — this one pins both (a broken counter decrypts its own output fine but
    // can never decrypt this fixed container). Plaintext byte i is (i * 31 + 7) & 0xFF.
    private const string MultiChunkVector =
        "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";

    private static byte[] MultiChunkPlaintext()
    {
        byte[] expected = new byte[3000];
        for (int i = 0; i < expected.Length; i++) expected[i] = (byte)(i * 31 + 7);
        return expected;
    }

    [Fact]
    public async Task Pinned_multichunk_container_decrypts_to_known_plaintext()
    {
        byte[] container = Convert.FromBase64String(MultiChunkVector);

        byte[] plaintext = await new PqFileDecryptor().DecryptBytesAsync(container, Passphrase);

        Assert.Equal(MultiChunkPlaintext(), plaintext);
    }

    [Fact]
    public async Task Reordering_two_chunks_of_the_pinned_container_fails_closed()
    {
        // Invariant 2 of the audit guide: each chunk's AAD binds its counter, so swapping two
        // equal-size ciphertext frames must fail authentication — a decryptor that lost the
        // counter binding would silently return reordered plaintext instead.
        byte[] container = Convert.FromBase64String(MultiChunkVector);

        int keyParamsLength = BinaryPrimitives.ReadUInt16BigEndian(container.AsSpan(16));
        int headerLength = 18 + keyParamsLength;
        // Frame layout: FrameType(1) ‖ Length(4, BE) ‖ Ciphertext ‖ Tag(16).
        int chunk1Length = BinaryPrimitives.ReadInt32BigEndian(container.AsSpan(headerLength + 1));
        int frameLength = 1 + 4 + chunk1Length + 16;
        int chunk2Length = BinaryPrimitives.ReadInt32BigEndian(container.AsSpan(headerLength + frameLength + 1));
        Assert.Equal(chunk1Length, chunk2Length); // both full 1 KiB frames — a clean swap

        byte[] swapped = (byte[])container.Clone();
        Array.Copy(container, headerLength + frameLength, swapped, headerLength, frameLength);
        Array.Copy(container, headerLength, swapped, headerLength + frameLength, frameLength);

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(swapped, Passphrase));
    }
}
