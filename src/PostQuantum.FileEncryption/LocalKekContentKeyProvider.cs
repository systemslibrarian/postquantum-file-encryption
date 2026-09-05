using System.Security.Cryptography;

namespace PostQuantum.FileEncryption;

/// <summary>
/// A built-in <see cref="IContentKeyProvider"/> that wraps each per-file content key under a
/// local 256-bit <b>key-encryption key (KEK)</b> using AES-256-GCM. Dependency-free and fully
/// testable; suitable for on-box envelope encryption or as a reference for cloud-KMS providers.
/// </summary>
/// <remarks>
/// The KEK never leaves the process — protect it like any master key (store it in an HSM/KMS in
/// production, or use a real KMS-backed provider instead). Dispose this provider to zero the KEK.
/// </remarks>
public sealed class LocalKekContentKeyProvider : IContentKeyProvider, IDisposable
{
    private const int KekLength = 32;
    private const int ContentKeyLength = 32;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    // wrapInfo layout: Nonce(12) ‖ Tag(16) ‖ WrappedKey(32)
    private const int WrapInfoLength = NonceLength + TagLength + ContentKeyLength;

    private static readonly byte[] WrapAad = "PostQuantum.FileEncryption/local-kek cek-wrap"u8.ToArray();

    private readonly byte[] _kek;
    // Created once: the AES key schedule / platform key import is the expensive part of a
    // wrap, and re-deriving it per operation would put that cost inside the lock below.
    private readonly AesGcm _kekGcm;
    // Every KEK use is serialized with Dispose. Without this, a Dispose racing an in-flight
    // wrap could tear down the key mid-operation and the content key would be silently
    // wrapped under a destroyed KEK — a confidentiality loss, not a crash. The lock turns
    // that race into ObjectDisposedException. A GCM pass over 32 bytes is microseconds, so
    // contention is negligible.
    private readonly object _kekLock = new();
    private volatile bool _disposed;

    /// <inheritdoc/>
    public string ProviderId => "local-kek";

    /// <summary>Creates a provider over an existing 256-bit KEK.</summary>
    /// <exception cref="ArgumentException">The KEK is not 32 bytes.</exception>
    public LocalKekContentKeyProvider(ReadOnlySpan<byte> kek)
    {
        if (kek.Length != KekLength)
        {
            throw new ArgumentException($"The key-encryption key must be {KekLength} bytes (256 bits).", nameof(kek));
        }
        _kek = kek.ToArray();
        try
        {
            _kekGcm = new AesGcm(_kek, TagLength);
        }
        catch
        {
            // AesGcm can throw (e.g. PlatformNotSupportedException) after the KEK was cloned;
            // the half-constructed object can never be disposed, so zero the clone here.
            CryptographicOperations.ZeroMemory(_kek);
            throw;
        }
    }

    /// <summary>Creates a provider over a fresh random 256-bit KEK (e.g. for tests).</summary>
    public static LocalKekContentKeyProvider Generate()
    {
        // The constructor clones the KEK into _kek; zero this intermediate copy so disposing
        // the provider really does remove every copy this type created.
        byte[] kek = RandomNumberGenerator.GetBytes(KekLength);
        try
        {
            return new LocalKekContentKeyProvider(kek);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    /// <summary>Returns a copy of the KEK. Handle it as a secret and zero it when done.</summary>
    public byte[] ExportKek()
    {
        lock (_kekLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (byte[])_kek.Clone();
        }
    }

    /// <inheritdoc/>
    public Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ObjectDisposedException.ThrowIf(_disposed, this);

        byte[] contentKey = RandomNumberGenerator.GetBytes(ContentKeyLength);
        try
        {
            byte[] wrapInfo = new byte[WrapInfoLength];
            Span<byte> nonce = wrapInfo.AsSpan(0, NonceLength);
            Span<byte> tag = wrapInfo.AsSpan(NonceLength, TagLength);
            Span<byte> wrapped = wrapInfo.AsSpan(NonceLength + TagLength, ContentKeyLength);

            RandomNumberGenerator.Fill(nonce);
            lock (_kekLock)
            {
                // The authoritative dispose check: the entry check above is a fast fail for
                // lifetime bugs; only this one is race-free against Dispose.
                ObjectDisposedException.ThrowIf(_disposed, this);
                _kekGcm.Encrypt(nonce, contentKey, wrapped, tag, WrapAad);
            }

            return Task.FromResult((contentKey, wrapInfo));
        }
        catch
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw;
        }
    }

    /// <inheritdoc/>
    public Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Before input validation, so a use-after-dispose surfaces as the lifetime bug it is
        // even when the wrapped blob is also malformed.
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (wrapInfo.Length != WrapInfoLength)
        {
            // Structural problem, not an authentication failure: match the taxonomy used by
            // every other parser (UnwrapRecipientKey, ParseKeyProviderParams, the hybrid block
            // parser) and keep PqDecryptionException reserved for one generic auth-failure
            // message, with no second distinguishable message under that type.
            throw new PqFormatException("The wrapped key is malformed (wrong length).");
        }

        ReadOnlySpan<byte> span = wrapInfo.Span;
        ReadOnlySpan<byte> nonce = span[..NonceLength];
        ReadOnlySpan<byte> tag = span.Slice(NonceLength, TagLength);
        ReadOnlySpan<byte> wrapped = span.Slice(NonceLength + TagLength, ContentKeyLength);

        byte[] contentKey = new byte[ContentKeyLength];
        try
        {
            lock (_kekLock)
            {
                // The authoritative dispose check: the entry check above is a fast fail for
                // lifetime bugs; only this one is race-free against Dispose.
                ObjectDisposedException.ThrowIf(_disposed, this);
                _kekGcm.Decrypt(nonce, wrapped, tag, contentKey, WrapAad);
            }
            return Task.FromResult(contentKey);
        }
        catch (AuthenticationTagMismatchException)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            // Same generic literal as the engine: a wrong KEK and a tampered body must be
            // indistinguishable to the caller — message and exception shape alike.
            throw new PqDecryptionException(
                "Decryption failed — the passphrase (or key) is wrong, or the file has been altered, truncated, or corrupted.");
        }
    }

    /// <summary>Zeroes the KEK from memory and releases the platform key object.</summary>
    public void Dispose()
    {
        lock (_kekLock)
        {
            if (!_disposed)
            {
                _kekGcm.Dispose();
                CryptographicOperations.ZeroMemory(_kek);
                _disposed = true;
            }
        }
    }
}
