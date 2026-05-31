using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// The synchronous in-memory API (<see cref="PqFileEncryptor.EncryptBytes"/> /
/// <see cref="PqFileDecryptor.DecryptBytes"/>). These overloads exist for callers that never
/// want to deal with <see cref="Task"/>; behavior must match the async path byte-for-byte.
/// </summary>
public sealed class SyncApiTests
{
    private const string PassphraseChars = "correct horse battery staple";

    [Fact]
    public void Sync_round_trip_recovers_original_bytes()
    {
        byte[] original = RandomBytes(4_096);

        byte[] cipher = new PqFileEncryptor(Fast()).EncryptBytes(original, PassphraseChars);
        byte[] restored = new PqFileDecryptor().DecryptBytes(cipher, PassphraseChars);

        Assert.Equal(original, restored);
    }

    [Fact]
    public void Sync_round_trip_with_argon2id_recovers_original_bytes()
    {
        byte[] original = RandomBytes(2_048);
        var opts = PqEncryptionOptions.Argon2id.WithArgon2id(
            memoryKiB: PqEncryptionOptions.MinArgon2MemoryKiB,
            iterations: PqEncryptionOptions.MinArgon2Iterations,
            parallelism: 1);

        byte[] cipher = new PqFileEncryptor(opts).EncryptBytes(original, PassphraseChars);
        byte[] restored = new PqFileDecryptor().DecryptBytes(cipher, PassphraseChars);

        Assert.Equal(original, restored);
    }

    [Fact]
    public void Sync_wrong_passphrase_fails_closed()
    {
        byte[] cipher = new PqFileEncryptor(Fast()).EncryptBytes(RandomBytes(1_024), PassphraseChars);

        Assert.Throws<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytes(cipher, "wrong"));
    }

    [Fact]
    public void Sync_tampered_container_is_rejected()
    {
        byte[] cipher = new PqFileEncryptor(Fast()).EncryptBytes(RandomBytes(1_024), PassphraseChars);
        cipher[^1] ^= 0xFF; // flip a bit in the final tag

        Assert.Throws<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytes(cipher, PassphraseChars));
    }

    [Fact]
    public async Task Sync_output_matches_async_when_round_tripped_across_APIs()
    {
        // The two APIs share an implementation — encrypting with sync and decrypting with
        // async (and vice versa) must round-trip identically.
        byte[] original = RandomBytes(3_000);

        byte[] syncCipher = new PqFileEncryptor(Fast()).EncryptBytes(original, PassphraseChars);
        byte[] asyncRestored = await new PqFileDecryptor().DecryptBytesAsync(syncCipher, PassphraseChars);
        Assert.Equal(original, asyncRestored);

        byte[] asyncCipher = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, PassphraseChars);
        byte[] syncRestored = new PqFileDecryptor().DecryptBytes(asyncCipher, PassphraseChars);
        Assert.Equal(original, syncRestored);
    }

    [Fact]
    public void Sync_handles_empty_plaintext()
    {
        byte[] cipher = new PqFileEncryptor(Fast()).EncryptBytes([], PassphraseChars);
        byte[] restored = new PqFileDecryptor().DecryptBytes(cipher, PassphraseChars);
        Assert.Empty(restored);
    }

    [Fact]
    public void Sync_handles_unicode_passphrase()
    {
        // BMP + supplementary plane characters in the passphrase should round-trip via UTF-8.
        const string passphrase = "café-密码-🔐-naïve";
        byte[] original = RandomBytes(512);

        byte[] cipher = new PqFileEncryptor(Fast()).EncryptBytes(original, passphrase);
        byte[] restored = new PqFileDecryptor().DecryptBytes(cipher, passphrase);

        Assert.Equal(original, restored);
    }
}
