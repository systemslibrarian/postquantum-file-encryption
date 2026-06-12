using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption;

/// <summary>
/// Encrypts files and streams into authenticated PostQuantum.FileEncryption containers, either
/// with a passphrase or to a recipient's public key. Instances are immutable and safe to
/// share across threads.
/// </summary>
/// <example>
/// <code>
/// // Passphrase
/// await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", "correct horse battery staple");
///
/// // To a recipient's public key (requires platform ML-KEM support)
/// var recipient = PqRecipientPublicKey.Import(publicKeyBytes);
/// await new PqFileEncryptor().EncryptFileAsync("report.pdf", "report.pdf.pqfe", recipient);
/// </code>
/// </example>
public sealed class PqFileEncryptor
{
    private readonly PqEncryptionOptions _options;

    /// <summary>Creates an encryptor using the strong default options.</summary>
    public PqFileEncryptor() : this(PqEncryptionOptions.Default) { }

    /// <summary>Creates an encryptor using the supplied options.</summary>
    /// <param name="options">Configuration for new ciphertext. Validated immediately.</param>
    public PqFileEncryptor(PqEncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
    }

    // ------------------------------------------------------------------ Passphrase: file

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> with a passphrase.</summary>
    /// <remarks>Output is written atomically: a sibling temp file is moved into place only on full success.</remarks>
    public Task EncryptFileAsync(
        string inputPath, string outputPath, string passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p =>
            EncryptFileAsync(inputPath, outputPath, p, progress, cancellationToken));
    }

    /// <summary>
    /// Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> with a passphrase
    /// supplied as bytes (typically UTF-8). Prefer this overload when you want to zero the
    /// passphrase from memory yourself; this library does not retain it.
    /// </summary>
    public Task EncryptFileAsync(
        string inputPath, string outputPath, ReadOnlyMemory<byte> passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);

        return EncryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.EncryptPassphraseAsync(input, output, passphrase, _options, total, progress, cancellationToken));
    }

    // ------------------------------------------------------------------ Passphrase: stream

    /// <summary>Encrypts <paramref name="input"/> to <paramref name="output"/> with a passphrase. Neither stream is disposed.</summary>
    public Task EncryptAsync(
        Stream input, Stream output, string passphrase, long? totalBytes = null,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p =>
            EncryptAsync(input, output, p, totalBytes, progress, cancellationToken));
    }

    /// <summary>Encrypts <paramref name="input"/> to <paramref name="output"/> with a passphrase supplied as bytes.</summary>
    public Task EncryptAsync(
        Stream input, Stream output, ReadOnlyMemory<byte> passphrase, long? totalBytes = null,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        long? total = ResolveTotal(input, totalBytes);
        return PqContainer.EncryptPassphraseAsync(input, output, passphrase, _options, total, progress, cancellationToken);
    }

    // ------------------------------------------------------------------ Recipient: file & stream

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> for a recipient's public key. <b>Experimental.</b></summary>
    /// <exception cref="PlatformNotSupportedException">The platform does not provide ML-KEM.</exception>
    [Experimental("PQFE001")]
    [Obsolete(
        "ML-KEM-only recipient mode in PostQuantum.FileEncryption is deprecated as of 1.0.0-rc.2. " +
        "Use the PostQuantum.FileEncryption.Hybrid package (X25519 + ML-KEM-768 combiner, multi-recipient, " +
        "fully managed, runs anywhere .NET 8 or later does). See docs/ROADMAP-v3.md.",
        DiagnosticId = "PQFE002",
        UrlFormat = "https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ROADMAP-v3.md#{0}")]
    public Task EncryptFileAsync(
        string inputPath, string outputPath, PqRecipientPublicKey recipient,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(recipient);

        return EncryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.EncryptRecipientAsync(input, output, recipient, _options, total, progress, cancellationToken));
    }

    /// <summary>Encrypts <paramref name="input"/> to <paramref name="output"/> for a recipient's public key. <b>Experimental.</b></summary>
    /// <exception cref="PlatformNotSupportedException">The platform does not provide ML-KEM.</exception>
    [Experimental("PQFE001")]
    [Obsolete(
        "ML-KEM-only recipient mode in PostQuantum.FileEncryption is deprecated as of 1.0.0-rc.2. " +
        "Use the PostQuantum.FileEncryption.Hybrid package (X25519 + ML-KEM-768 combiner, multi-recipient, " +
        "fully managed, runs anywhere .NET 8 or later does). See docs/ROADMAP-v3.md.",
        DiagnosticId = "PQFE002",
        UrlFormat = "https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ROADMAP-v3.md#{0}")]
    public Task EncryptAsync(
        Stream input, Stream output, PqRecipientPublicKey recipient, long? totalBytes = null,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(recipient);
        long? total = ResolveTotal(input, totalBytes);
        return PqContainer.EncryptRecipientAsync(input, output, recipient, _options, total, progress, cancellationToken);
    }

    // ------------------------------------------------------------------ Envelope key provider

    /// <summary>
    /// Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> using an external
    /// envelope-key provider (KMS/HSM/local-KEK). The master key never enters this process beyond
    /// the provider's boundary.
    /// </summary>
    public Task EncryptFileAsync(
        string inputPath, string outputPath, IContentKeyProvider keyProvider,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(keyProvider);

        return EncryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.EncryptKeyProviderAsync(input, output, keyProvider, _options, total, progress, cancellationToken));
    }

    /// <summary>Encrypts <paramref name="input"/> to <paramref name="output"/> using an envelope-key provider.</summary>
    public Task EncryptAsync(
        Stream input, Stream output, IContentKeyProvider keyProvider, long? totalBytes = null,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(keyProvider);
        long? total = ResolveTotal(input, totalBytes);
        return PqContainer.EncryptKeyProviderAsync(input, output, keyProvider, _options, total, progress, cancellationToken);
    }

    /// <summary>Encrypts an in-memory buffer using an envelope-key provider and returns the container bytes.</summary>
    public async Task<byte[]> EncryptBytesAsync(
        ReadOnlyMemory<byte> plaintext, IContentKeyProvider keyProvider,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        using var input = new MemoryStream(plaintext.ToArray(), writable: false);
        using var output = new MemoryStream(plaintext.Length + 256);
        await PqContainer.EncryptKeyProviderAsync(
            input, output, keyProvider, _options, plaintext.Length, progress, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    // ------------------------------------------------------------------ In-memory convenience

    /// <summary>
    /// Encrypts an in-memory buffer with a passphrase and returns the container bytes — the
    /// simplest way to protect a small blob without touching streams or files.
    /// </summary>
    public async Task<byte[]> EncryptBytesAsync(
        ReadOnlyMemory<byte> plaintext, string passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            return await EncryptBytesAsync(plaintext, passphraseBytes, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>Encrypts an in-memory buffer with a passphrase supplied as bytes.</summary>
    public async Task<byte[]> EncryptBytesAsync(
        ReadOnlyMemory<byte> plaintext, ReadOnlyMemory<byte> passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        using var input = new MemoryStream(plaintext.ToArray(), writable: false);
        using var output = new MemoryStream(plaintext.Length + 256);
        await PqContainer.EncryptPassphraseAsync(
            input, output, passphrase, _options, plaintext.Length, progress, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    // ------------------------------------------------------------------ Synchronous bytes API

    /// <summary>
    /// Synchronously encrypts an in-memory buffer with a <see cref="ReadOnlySpan{T}"/> of
    /// passphrase characters — the simplest path for callers that never go async and want a
    /// stack-friendly, zeroable passphrase. The span is UTF-8 encoded into a temporary buffer
    /// that is zeroed before this method returns.
    /// </summary>
    /// <remarks>
    /// In-memory encryption performs no real async I/O (the underlying streams are
    /// <see cref="MemoryStream"/>), so this overload reuses the async implementation by
    /// completing it inline — no <c>SynchronizationContext</c> capture, no deadlock surface.
    /// </remarks>
    public byte[] EncryptBytes(ReadOnlySpan<byte> plaintext, ReadOnlySpan<char> passphrase)
    {
        int byteCount = Encoding.UTF8.GetByteCount(passphrase);
        byte[] passphraseBytes = new byte[byteCount];
        try
        {
            Encoding.UTF8.GetBytes(passphrase, passphraseBytes);
            byte[] plaintextCopy = plaintext.ToArray();
            return EncryptBytesAsync(plaintextCopy, (ReadOnlyMemory<byte>)passphraseBytes)
                .GetAwaiter().GetResult();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static async Task EncryptFileCoreAsync(
        string inputPath, string outputPath, Func<FileStream, FileStream, long?, Task> encrypt)
    {
        await using var input = FileIo.OpenRead(inputPath);
        long? total = input.CanSeek ? input.Length : null;
        await FileIo.WriteViaTempAsync(outputPath, output => encrypt(input, output, total)).ConfigureAwait(false);
    }

    private static long? ResolveTotal(Stream input, long? totalBytes) =>
        totalBytes ?? (input.CanSeek ? input.Length - input.Position : null);

    private static async Task WithPassphraseBytesAsync(string passphrase, Func<ReadOnlyMemory<byte>, Task> body)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            await body(bytes).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
