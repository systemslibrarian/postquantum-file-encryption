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
    private bool _disposed;

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
    }

    /// <summary>Creates a provider over a fresh random 256-bit KEK (e.g. for tests).</summary>
    public static LocalKekContentKeyProvider Generate() => new(RandomNumberGenerator.GetBytes(KekLength));

    /// <summary>Returns a copy of the KEK. Handle it as a secret and zero it when done.</summary>
    public byte[] ExportKek()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return (byte[])_kek.Clone();
    }

    /// <inheritdoc/>
    public Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        byte[] contentKey = RandomNumberGenerator.GetBytes(ContentKeyLength);
        byte[] wrapInfo = new byte[WrapInfoLength];
        Span<byte> nonce = wrapInfo.AsSpan(0, NonceLength);
        Span<byte> tag = wrapInfo.AsSpan(NonceLength, TagLength);
        Span<byte> wrapped = wrapInfo.AsSpan(NonceLength + TagLength, ContentKeyLength);

        RandomNumberGenerator.Fill(nonce);
        using (var gcm = new AesGcm(_kek, TagLength))
        {
            gcm.Encrypt(nonce, contentKey, wrapped, tag, WrapAad);
        }

        return Task.FromResult((contentKey, wrapInfo));
    }

    /// <inheritdoc/>
    public Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();

        if (wrapInfo.Length != WrapInfoLength)
        {
            throw new PqDecryptionException("The wrapped key is malformed (wrong length).");
        }

        ReadOnlySpan<byte> span = wrapInfo.Span;
        ReadOnlySpan<byte> nonce = span[..NonceLength];
        ReadOnlySpan<byte> tag = span.Slice(NonceLength, TagLength);
        ReadOnlySpan<byte> wrapped = span.Slice(NonceLength + TagLength, ContentKeyLength);

        byte[] contentKey = new byte[ContentKeyLength];
        try
        {
            using var gcm = new AesGcm(_kek, TagLength);
            gcm.Decrypt(nonce, wrapped, tag, contentKey, WrapAad);
            return Task.FromResult(contentKey);
        }
        catch (AuthenticationTagMismatchException ex)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw new PqDecryptionException(
                "Decryption failed: wrong key-encryption key, or the wrapped key has been altered.", ex);
        }
    }

    /// <summary>Zeroes the KEK from memory.</summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            CryptographicOperations.ZeroMemory(_kek);
            _disposed = true;
        }
    }
}
