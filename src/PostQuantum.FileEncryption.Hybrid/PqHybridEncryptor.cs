using System.Security.Cryptography;
using PostQuantum.FileEncryption.Hybrid.Internal;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption.Hybrid;

/// <summary>
/// Encrypts files, streams, and in-memory buffers to one or more recipients' hybrid public keys
/// (X25519 + ML-KEM-768). Produces standard <c>.pqfe</c> containers that the core
/// <c>PqFileDecryptor</c> recognizes (and rejects with a clear message — only
/// <see cref="PqHybridDecryptor"/> can open them). Instances are immutable and thread-safe.
/// </summary>
public sealed class PqHybridEncryptor
{
    private readonly PqEncryptionOptions _options;

    /// <summary>Creates an encryptor using the strong default options.</summary>
    public PqHybridEncryptor() : this(PqEncryptionOptions.Default) { }

    /// <summary>Creates an encryptor using the supplied options (chunk size, etc.).</summary>
    public PqHybridEncryptor(PqEncryptionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        options.Validate();
        _options = options;
    }

    // ------------------------------------------------------------------ single recipient

    /// <summary>Encrypts <paramref name="input"/> to <paramref name="output"/> for one recipient.</summary>
    public Task EncryptAsync(
        Stream input, Stream output, PqHybridPublicKey recipient, long? totalBytes = null,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(recipient);
        return EncryptToAsync(input, output, [recipient], totalBytes, progress, cancellationToken);
    }

    /// <summary>Encrypts <paramref name="inputPath"/> to <paramref name="outputPath"/> for one recipient (atomic output).</summary>
    public Task EncryptFileAsync(
        string inputPath, string outputPath, PqHybridPublicKey recipient,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
        => EncryptFileToAsync(inputPath, outputPath, [recipient], progress, cancellationToken);

    /// <summary>Encrypts an in-memory buffer for one recipient and returns the container bytes.</summary>
    public Task<byte[]> EncryptBytesAsync(
        ReadOnlyMemory<byte> plaintext, PqHybridPublicKey recipient, CancellationToken cancellationToken = default)
        => EncryptBytesToAsync(plaintext, [recipient], cancellationToken);

    // ------------------------------------------------------------------ multiple recipients

    /// <summary>Encrypts <paramref name="input"/> so that any one of <paramref name="recipients"/> can open it.</summary>
    public Task EncryptToAsync(
        Stream input, Stream output, IReadOnlyList<PqHybridPublicKey> recipients, long? totalBytes = null,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ValidateRecipients(recipients);

        (byte keySource, byte[] keyParams, byte[] contentKey) = Establish(recipients);
        long? total = totalBytes ?? (input.CanSeek ? input.Length - input.Position : null);
        var header = ContainerHeader.Create(keySource, _options.ChunkSizeBytes, keyParams);
        return PqContainerEngine.EncryptCoreAsync(input, output, contentKey, header, total, progress, cancellationToken);
    }

    /// <summary>Encrypts a file so that any one of <paramref name="recipients"/> can open it (atomic output).</summary>
    public async Task EncryptFileToAsync(
        string inputPath, string outputPath, IReadOnlyList<PqHybridPublicKey> recipients,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ValidateRecipients(recipients);

        await using var input = FileIo.OpenRead(inputPath);
        long? total = input.CanSeek ? input.Length : null;
        await FileIo.WriteViaTempAsync(outputPath, output =>
            EncryptToAsync(input, output, recipients, total, progress, cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>Encrypts an in-memory buffer for multiple recipients and returns the container bytes.</summary>
    public async Task<byte[]> EncryptBytesToAsync(
        ReadOnlyMemory<byte> plaintext, IReadOnlyList<PqHybridPublicKey> recipients, CancellationToken cancellationToken = default)
    {
        ValidateRecipients(recipients);
        using var input = new MemoryStream(plaintext.ToArray(), writable: false);
        using var output = new MemoryStream(plaintext.Length + 1536);
        await EncryptToAsync(input, output, recipients, plaintext.Length, null, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    // ------------------------------------------------------------------ helpers

    private static (byte keySource, byte[] keyParams, byte[] contentKey) Establish(IReadOnlyList<PqHybridPublicKey> recipients)
    {
        byte[] contentKey = RandomNumberGenerator.GetBytes(32);
        if (recipients.Count == 1)
        {
            return (ContainerFormat.KeySourceHybridRecipient, HybridKeyEstablishment.WrapToRecipient(recipients[0], contentKey), contentKey);
        }
        return (ContainerFormat.KeySourceMultiRecipient, HybridKeyEstablishment.WrapToRecipients(recipients, contentKey), contentKey);
    }

    private static void ValidateRecipients(IReadOnlyList<PqHybridPublicKey> recipients)
    {
        ArgumentNullException.ThrowIfNull(recipients);
        if (recipients.Count == 0)
        {
            throw new ArgumentException("At least one recipient is required.", nameof(recipients));
        }
        if (recipients.Count > byte.MaxValue)
        {
            throw new ArgumentException($"At most {byte.MaxValue} recipients are supported.", nameof(recipients));
        }
        foreach (var recipient in recipients)
        {
            ArgumentNullException.ThrowIfNull(recipient);
        }
    }
}
