using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pins the no-decryption-oracle property: every authentication-related failure must surface
/// as the same <see cref="PqDecryptionException"/> with the same message, regardless of
/// whether the actual cause was a wrong passphrase, a bit-flipped ciphertext byte, a
/// bit-flipped tag, or a bit-flipped header byte. Distinguishing those cases at the public
/// surface would tell an attacker <em>why</em> their candidate failed and is exactly what we
/// must never do.
/// </summary>
/// <remarks>
/// Pre-AEAD structural errors (unknown magic, unsupported version, truncated header) are
/// intentionally distinct because they fire before any key work — they cannot reveal
/// anything about the key material. This test pins only the post-key-establishment auth
/// boundary.
/// </remarks>
public sealed class NoOracleTests
{
    [Fact]
    public async Task Wrong_passphrase_and_tamper_paths_throw_identical_messages()
    {
        byte[] plaintext = RandomBytes(2048);
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(plaintext, Passphrase);

        string wrongKeyMessage = await CaptureAsync(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, "definitely not the right passphrase"));

        // Bit-flip in the final AEAD tag.
        byte[] flippedTag = (byte[])container.Clone();
        flippedTag[^1] ^= 0xFF;
        string flippedTagMessage = await CaptureAsync(() =>
            new PqFileDecryptor().DecryptBytesAsync(flippedTag, Passphrase));

        // Bit-flip in the ciphertext body (some byte well inside the first frame's body).
        byte[] flippedBody = (byte[])container.Clone();
        int bodyOffset = container.Length / 2;
        flippedBody[bodyOffset] ^= 0xFF;
        string flippedBodyMessage = await CaptureAsync(() =>
            new PqFileDecryptor().DecryptBytesAsync(flippedBody, Passphrase));

        // Bit-flip in the random NoncePrefix (offset 12, inside the authenticated header).
        // The header is bound into every frame's AAD, so this must also fail authentication
        // with the unified message — never a distinct "header looks weird" oracle.
        byte[] flippedHeader = (byte[])container.Clone();
        flippedHeader[12] ^= 0xFF;
        string flippedHeaderMessage = await CaptureAsync(() =>
            new PqFileDecryptor().DecryptBytesAsync(flippedHeader, Passphrase));

        Assert.Equal(wrongKeyMessage, flippedTagMessage);
        Assert.Equal(wrongKeyMessage, flippedBodyMessage);
        Assert.Equal(wrongKeyMessage, flippedHeaderMessage);
    }

    private static async Task<string> CaptureAsync(Func<Task> body)
    {
        var ex = await Assert.ThrowsAsync<PqDecryptionException>(body);
        return ex.Message;
    }
}
