using PostQuantum.FileEncryption.Hybrid.Internal;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption.Hybrid;

/// <summary>
/// Decrypts hybrid recipient containers (single or multi-recipient) with a hybrid private key.
/// Fail-closed: if the file is not encrypted to this key, or has been altered or truncated, a
/// <see cref="PqDecryptionException"/> is thrown and no plaintext is left at the destination.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Performance", "CA1822:Mark members as static",
    Justification = "Kept as instance methods for symmetry with PqHybridEncryptor and the core decryptor.")]
public sealed class PqHybridDecryptor
{
    /// <summary>Creates a decryptor. Parameters are read from each container's header.</summary>
    public PqHybridDecryptor() { }

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

        ContainerHeader header = await PqContainerEngine.ReadHeaderAsync(input, cancellationToken).ConfigureAwait(false);
        byte[] contentKey = header.KeySource switch
        {
            ContainerFormat.KeySourceHybridRecipient => HybridKeyEstablishment.UnwrapFromRecipient(header.KeyParams, privateKey),
            ContainerFormat.KeySourceMultiRecipient => HybridKeyEstablishment.UnwrapFromRecipients(header.KeyParams, privateKey),
            _ => throw new PqDecryptionException("This container is not a hybrid-recipient container (use the matching decryptor)."),
        };

        long? total = input.CanSeek ? input.Length - input.Position : null;
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

        await using var input = FileIo.OpenRead(inputPath);
        await FileIo.WriteViaTempAsync(outputPath, output =>
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
