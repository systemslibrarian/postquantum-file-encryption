using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pins hardening behavior at the public API's edges: in-place file operation, the frozen
/// trailing-data acceptance, and empty-passphrase rejection across every overload family.
/// </summary>
public sealed class HardeningTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "pqfe-hardening-" + Guid.NewGuid().ToString("N"));

    public HardeningTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch { /* best effort */ } }
    private string P(string name) => Path.Combine(_dir, name);

    // ------------------------------------------------------------------ in-place file APIs

    [Fact]
    public async Task Encrypt_and_decrypt_in_place_round_trip()
    {
        // input == output is a natural thing to attempt, and used to fail on Windows with a
        // sharing violation at the final rename (the input handle was still open). The input
        // must be fully read and closed before the atomic move replaces it.
        string path = P("inplace.bin");
        byte[] original = RandomBytes(20_000);
        await File.WriteAllBytesAsync(path, original);

        await new PqFileEncryptor(Fast()).EncryptFileAsync(path, path, Passphrase);
        Assert.NotEqual(original, await File.ReadAllBytesAsync(path));

        await new PqFileDecryptor().DecryptFileAsync(path, path, Passphrase);
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
        Assert.Empty(Directory.GetFiles(_dir, "*.tmp-*"));
    }

    [Fact]
    public async Task Failed_in_place_decryption_preserves_the_source()
    {
        // Fail-safe composition of in-place + fail-closed: a wrong passphrase must leave the
        // original container untouched at its own path.
        string path = P("inplace.pqfe");
        byte[] original = RandomBytes(5_000);
        await File.WriteAllBytesAsync(path, original);
        await new PqFileEncryptor(Fast()).EncryptFileAsync(path, path, Passphrase);
        byte[] container = await File.ReadAllBytesAsync(path);

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptFileAsync(path, path, "not the passphrase"));

        Assert.Equal(container, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task Missing_input_file_fails_before_any_destination_side_effect()
    {
        // The input is opened before the temporary output file is created (FileIo owns the
        // ordering): a typo'd input path must surface as FileNotFoundException — the
        // missing-input signal scripts branch on — with nothing created, even transiently,
        // at the destination.
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            new PqFileEncryptor(Fast()).EncryptFileAsync(P("missing.bin"), P("out.pqfe"), Passphrase));
        await Assert.ThrowsAsync<FileNotFoundException>(() =>
            new PqFileDecryptor().DecryptFileAsync(P("missing.pqfe"), P("out.bin"), Passphrase));
        Assert.Empty(Directory.GetFiles(_dir));
    }

    // ------------------------------------------------------------------ frozen v2 reader behavior

    [Fact]
    public async Task Trailing_bytes_after_the_final_frame_are_ignored()
    {
        // Frozen v2 behavior, documented in KNOWN-GAPS.md and mirrored by the Rust/WASM
        // implementation: decryption stops at the authenticated final frame, so appended
        // garbage is accepted and the recovered plaintext is exactly the original. Pinned so
        // neither a "reject trailing data" change nor an accidental read-past-final-frame
        // regression can ship silently.
        byte[] original = RandomBytes(3_000);
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, Passphrase);
        byte[] padded = [.. container, .. RandomBytes(64)];

        Assert.Equal(original, await new PqFileDecryptor().DecryptBytesAsync(padded, Passphrase));
    }

    // ------------------------------------------------------------------ empty passphrases

    [Fact]
    public async Task Empty_byte_passphrases_are_rejected_on_encrypt()
    {
        var encryptor = new PqFileEncryptor(Fast());
        byte[] data = RandomBytes(100);

        await Assert.ThrowsAsync<ArgumentException>(() =>
            encryptor.EncryptBytesAsync(data, ReadOnlyMemory<byte>.Empty));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            encryptor.EncryptAsync(new MemoryStream(data), new MemoryStream(), ReadOnlyMemory<byte>.Empty));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            encryptor.EncryptFileAsync(P("in.bin"), P("out.pqfe"), ReadOnlyMemory<byte>.Empty));
    }

    [Fact]
    public void Empty_char_span_passphrases_are_rejected_by_the_sync_encrypt_api()
    {
        // The sync span overload is documented as the mirror of the string overloads, which
        // have always rejected "" — an empty textbox bound to a UI must not silently produce
        // a trivially decryptable container.
        Assert.Throws<ArgumentException>(() =>
            new PqFileEncryptor(Fast()).EncryptBytes(RandomBytes(100), ReadOnlySpan<char>.Empty));
    }

    // Produced by a pre-gate build via the byte overloads (PBKDF2 100,000 iters, 1 KiB chunks,
    // empty passphrase) — the compat contract below is that such containers stay openable.
    private const string EmptyPassphraseContainer =
        "UFFGRQIBAQAAAAQAbafjRgAWARCMhjn2x0CH4ZNc6wy/sAuLAAGGoAEAAABNY5Mmt3gFKRrkpETissNDs2XqD3Gw2PnaQBZI8dfKG33tJ60oRQYu1II9b5IcrWBq5hmNCO1hwW1W9b4cDgVN/DUa9Rvt5fgV+gEEmKYLp85qFnP+hWJQfCl7sV4i";

    [Fact]
    public async Task Empty_passphrase_containers_from_older_releases_still_decrypt()
    {
        // Before the encrypt-side gate existed, the byte overloads could legitimately encrypt
        // under an empty passphrase. Decrypt therefore accepts an empty passphrase forever —
        // rejecting it would lock callers out of their own data.
        byte[] container = Convert.FromBase64String(EmptyPassphraseContainer);

        byte[] plaintext = await new PqFileDecryptor().DecryptBytesAsync(container, ReadOnlyMemory<byte>.Empty);

        Assert.Equal(
            "Backward-compat: encrypted by a 1.4.x byte overload with an empty passphrase.",
            System.Text.Encoding.UTF8.GetString(plaintext));

        // The sync char-span mirror takes the same path.
        Assert.Equal(plaintext, new PqFileDecryptor().DecryptBytes(container, ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public async Task Wrong_passphrase_and_tampered_container_are_byte_identical_to_the_caller()
    {
        // The no-oracle contract, pinned as message *equality*: an attacker observing the
        // failure must not learn whether the passphrase was wrong or the bytes were altered.
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(500), Passphrase);
        byte[] tampered = (byte[])container.Clone();
        tampered[^1] ^= 0x01;

        var wrongPass = await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, "not the passphrase"));
        var altered = await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(tampered, Passphrase));

        Assert.Equal(wrongPass.Message, altered.Message);
    }

    [Fact]
    public async Task Empty_passphrase_against_a_real_container_fails_closed_not_as_caller_error()
    {
        // An empty passphrase on decrypt is treated like any other candidate passphrase: it
        // runs the KDF and fails authentication with the generic fail-closed exception, not
        // an ArgumentException — no oracle distinguishes "empty" from "wrong".
        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(RandomBytes(100), Passphrase);

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqFileDecryptor().DecryptBytesAsync(container, ReadOnlyMemory<byte>.Empty));
    }
}
