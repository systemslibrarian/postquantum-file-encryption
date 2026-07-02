using System.Security.Cryptography;
using System.Text;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// The <c>PQKF</c> v1 passphrase-encrypted key-file format, shared by the Hybrid and Signing
/// packages' <c>ExportEncrypted</c> / <c>ImportEncrypted</c> APIs. The body is a standard
/// <c>.pqfe</c> v2 passphrase container whose plaintext is <c>KeyType(1) ‖ KeyBytes</c>, so all
/// confidentiality, authenticity, and KDF-hardening properties are inherited from the container
/// engine — no new cryptography. The key type lives <em>inside</em> the authenticated plaintext,
/// so it cannot be flipped by an attacker to confuse one key kind for another.
/// See docs/KEY-FILE-FORMAT.md for the byte-exact specification.
/// </summary>
/// <remarks>
/// This type drives <see cref="PqContainer"/> directly over in-memory streams it owns rather
/// than going through the public bytes convenience APIs, so that every buffer holding the
/// key-bearing plaintext is one this type can (and does) zero. In-memory only — completing the
/// async engine inline is deadlock-free (no real I/O, no <c>SynchronizationContext</c> capture).
/// </remarks>
internal static class PqKeyFileFormat
{
    public const byte KeyTypeHybridPrivate = 1;
    public const byte KeyTypeSigningPrivate = 2;

    private const byte FormatVersion = 1;
    private const int HeaderLength = 5;

    private static ReadOnlySpan<byte> Magic => "PQKF"u8;

    /// <summary>
    /// Key files default to Argon2id (memory-hard): they protect long-lived secrets and are
    /// tiny, so the KDF is the entire cost of opening one — exactly the profile Argon2id is for.
    /// </summary>
    public static PqEncryptionOptions DefaultOptions => PqEncryptionOptions.Argon2id;

    /// <summary>
    /// Returns whether <paramref name="data"/> carries the <c>PQKF</c> framing (magic and a
    /// known version) — the check consumers use to route a key file between the raw and
    /// encrypted import paths without duplicating format knowledge.
    /// </summary>
    public static bool IsEncryptedKeyFile(ReadOnlySpan<byte> data) =>
        data.Length >= HeaderLength + 1 && data[..4].SequenceEqual(Magic) && data[4] == FormatVersion;

    public static byte[] Encrypt(
        byte keyType, ReadOnlySpan<byte> keyBytes, ReadOnlySpan<char> passphrase, PqEncryptionOptions? options)
    {
        ThrowIfEmptyPassphrase(passphrase);
        byte[] passphraseBytes = new byte[Encoding.UTF8.GetByteCount(passphrase)];
        byte[] plaintext = new byte[1 + keyBytes.Length];
        try
        {
            Encoding.UTF8.GetBytes(passphrase, passphraseBytes);
            plaintext[0] = keyType;
            keyBytes.CopyTo(plaintext.AsSpan(1));

            using var input = new MemoryStream(plaintext, writable: false);
            using var output = new MemoryStream(HeaderLength + plaintext.Length + 512);
            output.Write(Magic);
            output.WriteByte(FormatVersion);
            PqContainer.EncryptPassphraseAsync(
                    input, output, passphraseBytes, options ?? DefaultOptions,
                    plaintext.Length, progress: null, CancellationToken.None)
                .GetAwaiter().GetResult();
            return output.ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>
    /// Decrypts a key file and returns the raw key bytes (the caller zeroes them after import).
    /// Fail-closed: a wrong passphrase or any tampering surfaces as the container engine's
    /// generic <see cref="PqDecryptionException"/>; structural problems (including a key file
    /// that holds a different kind of key) surface as <see cref="PqFormatException"/>.
    /// </summary>
    public static byte[] Decrypt(
        byte expectedKeyType, string expectedTypeName, int expectedKeyLength,
        ReadOnlySpan<byte> keyFile, ReadOnlySpan<char> passphrase, PqDecryptionLimits? limits)
    {
        if (keyFile.Length < HeaderLength + 1 || !keyFile[..4].SequenceEqual(Magic))
        {
            throw new PqFormatException("Not a recognizable encrypted key file (bad magic bytes).");
        }
        if (keyFile[4] != FormatVersion)
        {
            throw new PqFormatException("Unsupported encrypted key file version.");
        }
        ThrowIfEmptyPassphrase(passphrase);

        byte[] passphraseBytes = new byte[Encoding.UTF8.GetByteCount(passphrase)];
        // Sized so the backing buffer never reallocates (the plaintext is always smaller than
        // the container), leaving exactly one key-bearing buffer for the finally to zero.
        using var output = new MemoryStream(keyFile.Length);
        try
        {
            Encoding.UTF8.GetBytes(passphrase, passphraseBytes);
            using var input = new MemoryStream(keyFile[HeaderLength..].ToArray(), writable: false);
            PqContainer.DecryptPassphraseAsync(
                    input, output, passphraseBytes, limits ?? PqDecryptionLimits.Default,
                    input.Length, progress: null, CancellationToken.None)
                .GetAwaiter().GetResult();

            // The type byte was authenticated as part of the container plaintext, so this is a
            // caller-error signal (right passphrase, wrong kind of key file), not an oracle.
            if (output.Length != 1 + expectedKeyLength || output.GetBuffer()[0] != expectedKeyType)
            {
                throw new PqFormatException($"This encrypted key file does not hold a {expectedTypeName}.");
            }
            return output.GetBuffer().AsSpan(1, expectedKeyLength).ToArray();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(output.GetBuffer());
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    private static void ThrowIfEmptyPassphrase(ReadOnlySpan<char> passphrase)
    {
        if (passphrase.IsEmpty)
        {
            throw new ArgumentException("Passphrase must not be empty.", nameof(passphrase));
        }
    }
}
