using PostQuantum.FileEncryption.Hybrid.Internal;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption.Hybrid;

/// <summary>
/// Decrypts hybrid recipient containers (single or multi-recipient) with a hybrid private key.
/// Fail-closed: if the file is not encrypted to this key, or has been altered or truncated, a
/// <see cref="PqDecryptionException"/> is thrown and no plaintext is left at the destination.
/// </summary>
public sealed class PqHybridDecryptor
{
    private readonly PqDecryptionLimits _limits;

    /// <summary>Creates a decryptor. Parameters are read from each container's header.</summary>
    public PqHybridDecryptor() : this(PqDecryptionLimits.Default) { }

    /// <summary>
    /// Creates a decryptor that enforces <paramref name="limits"/> on every container it opens.
    /// Use <see cref="PqDecryptionLimits.Untrusted"/> (or your own ceilings) when decrypting
    /// containers from untrusted sources. On the hybrid path only
    /// <see cref="PqDecryptionLimits.MaxChunkSizeBytes"/> applies — key unwrap is a fixed-cost
    /// KEM operation, so there is no KDF cost for a hostile header to inflate — and a header
    /// above the limit is rejected with <see cref="PqFormatException"/> before key
    /// establishment or buffer allocation.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">A limit is outside the format's supported range.</exception>
    public PqHybridDecryptor(PqDecryptionLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        limits.Validate();
        _limits = limits;
    }

    /// <summary>Decrypts the container read from <paramref name="input"/> to <paramref name="output"/>.</summary>
    /// <exception cref="PqFormatException">The input is not a recognizable container.</exception>
    /// <exception cref="PqDecryptionException">Not encrypted to this key, or altered/truncated.</exception>
    public async Task DecryptAsync(
        Stream input, Stream output, PqHybridPrivateKey privateKey,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(privateKey);

        // Capture the total before the header is consumed: the engine expects the whole
        // container's length and derives the plaintext total for progress reporting from it.
        long? total = input.CanSeek ? input.Length - input.Position : null;
        ContainerHeader header = await PqContainerEngine.ReadHeaderAsync(input, cancellationToken).ConfigureAwait(false);
        PqContainer.EnforceChunkLimit(header, _limits);
        byte[] contentKey = header.KeySource switch
        {
            ContainerFormat.KeySourceHybridRecipient => HybridKeyEstablishment.UnwrapFromRecipient(header.KeyParams, privateKey),
            ContainerFormat.KeySourceMultiRecipient => HybridKeyEstablishment.UnwrapFromRecipients(header.KeyParams, privateKey),
            _ => throw new PqDecryptionException("This container is not a hybrid-recipient container (use the matching decryptor)."),
        };

        await PqContainerEngine.DecryptCoreAsync(input, output, contentKey, header, total, progress, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Decrypts the container at <paramref name="inputPath"/> to <paramref name="outputPath"/> (atomic output).</summary>
    public async Task DecryptFileAsync(
        string inputPath, string outputPath, PqHybridPrivateKey privateKey,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(privateKey);

        // FileIo owns the ordering invariants: input opened before the temp file exists
        // (missing input has no destination side effect) and closed before the atomic move
        // (in-place decryption works on Windows).
        await FileIo.TransformViaTempAsync(inputPath, outputPath, (input, output, _) =>
            DecryptAsync(input, output, privateKey, progress, cancellationToken)).ConfigureAwait(false);
    }

    /// <summary>Decrypts an in-memory container and returns the recovered plaintext.</summary>
    public async Task<byte[]> DecryptBytesAsync(
        ReadOnlyMemory<byte> container, PqHybridPrivateKey privateKey, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        using var input = new MemoryStream(container.ToArray(), writable: false);
        using var output = new MemoryStream(container.Length);
        await DecryptAsync(input, output, privateKey, null, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }
}
