using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption;

/// <summary>
/// Decrypts PostQuantum.FileEncryption containers back into their original bytes, using either
/// the passphrase or the recipient private key the container was created with. Instances are
/// stateless and safe to share across threads.
/// </summary>
/// <remarks>
/// Decryption is fail-closed. If the key is wrong, or the container has been altered,
/// corrupted, or truncated, a <see cref="PqDecryptionException"/> is thrown and no plaintext is
/// left at the destination — for file output, the partially written temporary file is deleted
/// before the exception propagates.
/// </remarks>
public sealed class PqFileDecryptor
{
    private readonly PqDecryptionLimits _limits;

    /// <summary>Creates a decryptor. Decryption parameters are read from each container's header.</summary>
    public PqFileDecryptor() : this(PqDecryptionLimits.Default) { }

    /// <summary>
    /// Creates a decryptor that enforces <paramref name="limits"/> on every container it opens.
    /// Use <see cref="PqDecryptionLimits.Untrusted"/> (or your own ceilings) when decrypting
    /// containers from untrusted sources, so a hostile header cannot demand gibibytes of memory
    /// or minutes of CPU before the first authentication check. A header above a limit is
    /// rejected with <see cref="PqFormatException"/> before any key derivation work.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">A limit is outside the format's supported range.</exception>
    public PqFileDecryptor(PqDecryptionLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        _limits = limits;
    }

    // ------------------------------------------------------------------ Passphrase: file

    /// <summary>Decrypts the container at <paramref name="inputPath"/> to <paramref name="outputPath"/> with a passphrase.</summary>
    /// <exception cref="PqFormatException">The input is not a recognizable container.</exception>
    /// <exception cref="PqDecryptionException">The passphrase is wrong, or the container is altered or truncated.</exception>
    public Task DecryptFileAsync(
        string inputPath, string outputPath, string passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p =>
            DecryptFileAsync(inputPath, outputPath, p, progress, cancellationToken));
    }

    /// <summary>Decrypts the container at <paramref name="inputPath"/> to <paramref name="outputPath"/> with a passphrase supplied as bytes.</summary>
    public Task DecryptFileAsync(
        string inputPath, string outputPath, ReadOnlyMemory<byte> passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);

        return DecryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.DecryptPassphraseAsync(input, output, passphrase, _limits, total, progress, cancellationToken));
    }

    // ------------------------------------------------------------------ Passphrase: stream

    /// <summary>Decrypts the container read from <paramref name="input"/> to <paramref name="output"/> with a passphrase. Neither stream is disposed.</summary>
    public Task DecryptAsync(
        Stream input, Stream output, string passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p =>
            DecryptAsync(input, output, p, progress, cancellationToken));
    }

    /// <summary>Decrypts the container read from <paramref name="input"/> to <paramref name="output"/> with a passphrase supplied as bytes.</summary>
    public Task DecryptAsync(
        Stream input, Stream output, ReadOnlyMemory<byte> passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        long? total = input.CanSeek ? input.Length - input.Position : null;
        return PqContainer.DecryptPassphraseAsync(input, output, passphrase, _limits, total, progress, cancellationToken);
    }

    // ------------------------------------------------------------------ Recipient: file & stream

    /// <summary>Decrypts a recipient-encrypted container at <paramref name="inputPath"/> to <paramref name="outputPath"/> using a private key. <b>Experimental.</b></summary>
    /// <exception cref="PlatformNotSupportedException">The platform does not provide ML-KEM.</exception>
    [Experimental("PQFE001")]
    [Obsolete(
        "ML-KEM-only recipient mode in PostQuantum.FileEncryption is deprecated as of 1.0.0-rc.2. " +
        "Use the PostQuantum.FileEncryption.Hybrid package (X25519 + ML-KEM-768 combiner, multi-recipient, " +
        "fully managed, runs anywhere .NET 10 does). See docs/ROADMAP-v3.md.",
        DiagnosticId = "PQFE002",
        UrlFormat = "https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ROADMAP-v3.md#{0}")]
    public Task DecryptFileAsync(
        string inputPath, string outputPath, PqRecipientPrivateKey privateKey,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(privateKey);

        return DecryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.DecryptRecipientAsync(input, output, privateKey, _limits, total, progress, cancellationToken));
    }

    /// <summary>Decrypts a recipient-encrypted container read from <paramref name="input"/> to <paramref name="output"/> using a private key. <b>Experimental.</b></summary>
    /// <exception cref="PlatformNotSupportedException">The platform does not provide ML-KEM.</exception>
    [Experimental("PQFE001")]
    [Obsolete(
        "ML-KEM-only recipient mode in PostQuantum.FileEncryption is deprecated as of 1.0.0-rc.2. " +
        "Use the PostQuantum.FileEncryption.Hybrid package (X25519 + ML-KEM-768 combiner, multi-recipient, " +
        "fully managed, runs anywhere .NET 10 does). See docs/ROADMAP-v3.md.",
        DiagnosticId = "PQFE002",
        UrlFormat = "https://github.com/systemslibrarian/postquantum-file-encryption/blob/main/docs/ROADMAP-v3.md#{0}")]
    public Task DecryptAsync(
        Stream input, Stream output, PqRecipientPrivateKey privateKey,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(privateKey);
        long? total = input.CanSeek ? input.Length - input.Position : null;
        return PqContainer.DecryptRecipientAsync(input, output, privateKey, _limits, total, progress, cancellationToken);
    }

    // ------------------------------------------------------------------ Envelope key provider

    /// <summary>Decrypts a container at <paramref name="inputPath"/> to <paramref name="outputPath"/> using an envelope-key provider.</summary>
    /// <exception cref="PqDecryptionException">Wrong provider/key, or the container is altered or truncated.</exception>
    public Task DecryptFileAsync(
        string inputPath, string outputPath, IContentKeyProvider keyProvider,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(keyProvider);

        return DecryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.DecryptKeyProviderAsync(input, output, keyProvider, _limits, total, progress, cancellationToken));
    }

    /// <summary>Decrypts the container read from <paramref name="input"/> to <paramref name="output"/> using an envelope-key provider.</summary>
    public Task DecryptAsync(
        Stream input, Stream output, IContentKeyProvider keyProvider,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(keyProvider);
        long? total = input.CanSeek ? input.Length - input.Position : null;
        return PqContainer.DecryptKeyProviderAsync(input, output, keyProvider, _limits, total, progress, cancellationToken);
    }

    /// <summary>Decrypts an in-memory container using an envelope-key provider and returns the plaintext.</summary>
    public async Task<byte[]> DecryptBytesAsync(
        ReadOnlyMemory<byte> container, IContentKeyProvider keyProvider,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(keyProvider);
        using var input = new MemoryStream(container.ToArray(), writable: false);
        using var output = new MemoryStream(container.Length);
        await PqContainer.DecryptKeyProviderAsync(input, output, keyProvider, _limits, container.Length, progress, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    // ------------------------------------------------------------------ All-or-nothing stream

    /// <summary>
    /// Decrypts the container from <paramref name="input"/> and writes the plaintext to
    /// <paramref name="output"/> <b>only if the entire container authenticates</b> — nothing is
    /// written on failure. This closes the streaming gap where <see cref="DecryptAsync(Stream, Stream, string, IProgress{PqProgress}?, CancellationToken)"/>
    /// emits earlier authentic chunks before a later truncation is detected.
    /// </summary>
    /// <remarks>
    /// The recovered plaintext is buffered in memory before being written, so peak memory is
    /// proportional to the plaintext size. For very large inputs prefer the file API
    /// (<see cref="DecryptFileAsync(string, string, string, IProgress{PqProgress}?, CancellationToken)"/>),
    /// which is already atomic via a temp file and rename without buffering.
    /// </remarks>
    public Task DecryptAtomicAsync(
        Stream input, Stream output, string passphrase, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p => DecryptAtomicAsync(input, output, p, cancellationToken));
    }

    /// <summary>All-or-nothing stream decryption with a passphrase supplied as bytes.</summary>
    public async Task DecryptAtomicAsync(
        Stream input, Stream output, ReadOnlyMemory<byte> passphrase, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);

        using var buffer = new MemoryStream();
        // If this throws, `output` has not been touched — that is the all-or-nothing guarantee.
        await DecryptAsync(input, buffer, passphrase, null, cancellationToken).ConfigureAwait(false);
        buffer.Position = 0;
        await buffer.CopyToAsync(output, cancellationToken).ConfigureAwait(false);
    }

    // ------------------------------------------------------------------ In-memory convenience

    /// <summary>
    /// Decrypts an in-memory container with a passphrase and returns the recovered plaintext.
    /// Fail-closed: throws <see cref="PqDecryptionException"/> rather than returning bad data.
    /// </summary>
    public async Task<byte[]> DecryptBytesAsync(
        ReadOnlyMemory<byte> container, string passphrase, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            return await DecryptBytesAsync(container, passphraseBytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>Decrypts an in-memory container with a passphrase supplied as bytes.</summary>
    public async Task<byte[]> DecryptBytesAsync(
        ReadOnlyMemory<byte> container, ReadOnlyMemory<byte> passphrase, CancellationToken cancellationToken = default)
    {
        using var input = new MemoryStream(container.ToArray(), writable: false);
        using var output = new MemoryStream(container.Length);
        await PqContainer.DecryptPassphraseAsync(
            input, output, passphrase, _limits, container.Length, null, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    // ------------------------------------------------------------------ Synchronous bytes API

    /// <summary>
    /// Synchronously decrypts an in-memory container with a <see cref="ReadOnlySpan{T}"/> of
    /// passphrase characters — fail-closed, throws <see cref="PqDecryptionException"/> on any
    /// authentication failure rather than returning bad data. The span is UTF-8 encoded into a
    /// temporary buffer that is zeroed before this method returns.
    /// </summary>
    /// <remarks>
    /// In-memory decryption performs no real async I/O, so this overload reuses the async
    /// implementation by completing it inline — no <c>SynchronizationContext</c> capture,
    /// no deadlock surface.
    /// </remarks>
    public byte[] DecryptBytes(ReadOnlySpan<byte> container, ReadOnlySpan<char> passphrase)
    {
        int byteCount = Encoding.UTF8.GetByteCount(passphrase);
        byte[] passphraseBytes = new byte[byteCount];
        try
        {
            Encoding.UTF8.GetBytes(passphrase, passphraseBytes);
            byte[] containerCopy = container.ToArray();
            return DecryptBytesAsync(containerCopy, (ReadOnlyMemory<byte>)passphraseBytes)
                .GetAwaiter().GetResult();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    // ------------------------------------------------------------------ helpers

    private static async Task DecryptFileCoreAsync(
        string inputPath, string outputPath, Func<FileStream, FileStream, long?, Task> decrypt)
    {
        await using var input = FileIo.OpenRead(inputPath);
        long? total = input.CanSeek ? input.Length : null;
        await FileIo.WriteViaTempAsync(outputPath, output => decrypt(input, output, total)).ConfigureAwait(false);
    }

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
