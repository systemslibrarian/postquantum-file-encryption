using System.Diagnostics;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// Orchestrates a full encrypt/decrypt operation: establish the content key, build or parse
/// the header, then hand the stream work to the container codec. This is the single place
/// where key establishment meets the container body, the natural home for future delegation to
/// <c>PostQuantum.FileFormat</c>, and where non-sensitive telemetry is emitted.
/// </summary>
internal static class PqContainer
{
    /// <summary>Wraps an operation with start/complete/failed telemetry and timing.</summary>
    private static async Task InstrumentedAsync(string operation, string keySource, long? bytes, Func<Task> work)
    {
        PqfeEventSource.Log.OperationStarted(operation, keySource);
        long startTimestamp = Stopwatch.GetTimestamp();
        try
        {
            await work().ConfigureAwait(false);
            PqfeEventSource.Log.OperationCompleted(operation, bytes ?? -1, Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds);
        }
        catch (Exception ex)
        {
            PqfeEventSource.Log.OperationFailed(operation, ex.GetType().Name);
            throw;
        }
    }

    // Typed as the interface on purpose: this is the seam where a PostQuantum.FileFormat-backed
    // codec will be substituted. The indirection is architectural, not accidental.
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Performance", "CA1859:Use concrete types when possible for improved performance",
        Justification = "Intentional delegation seam; see IPqContainerCodec.")]
    private static IPqContainerCodec Codec => SelfContainedContainerCodec.Instance;

    public static async Task EncryptPassphraseAsync(
        Stream source, Stream destination, ReadOnlyMemory<byte> passphrase, PqEncryptionOptions options,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken,
        byte[]? saltOverride = null, byte[]? noncePrefixOverride = null)
    {
        // The override parameters are used only by deterministic conformance tests; production
        // callers leave them null so salt and nonce prefix are freshly random per file.
        await InstrumentedAsync("encrypt", "passphrase", totalBytes, async () =>
        {
            (byte[] keyParams, byte[] contentKey) = await KeyEstablishment.BuildPassphraseAsync(passphrase, options, saltOverride).ConfigureAwait(false);
            var header = ContainerHeader.Create(ContainerFormat.KeySourcePassphrase, options.ChunkSizeBytes, keyParams, noncePrefixOverride);
            await Codec.WriteAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    public static async Task DecryptPassphraseAsync(
        Stream source, Stream destination, ReadOnlyMemory<byte> passphrase,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken)
    {
        await InstrumentedAsync("decrypt", "passphrase", totalBytes, async () =>
        {
            ContainerHeader header = await Codec.ReadHeaderAsync(source, cancellationToken).ConfigureAwait(false);
            if (header.KeySource != ContainerFormat.KeySourcePassphrase)
            {
                throw new PqDecryptionException("This container is encrypted to a recipient key, not a passphrase.");
            }
            byte[] contentKey = await KeyEstablishment.DerivePassphraseKeyAsync(passphrase, header).ConfigureAwait(false);
            await Codec.ReadBodyAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    public static async Task EncryptRecipientAsync(
        Stream source, Stream destination, PqRecipientPublicKey recipient, PqEncryptionOptions options,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken)
    {
        await InstrumentedAsync("encrypt", "ml-kem-recipient", totalBytes, async () =>
        {
            (byte[] keyParams, byte[] contentKey) = KeyEstablishment.BuildRecipient(recipient);
            var header = ContainerHeader.Create(ContainerFormat.KeySourceMlKemRecipient, options.ChunkSizeBytes, keyParams);
            await Codec.WriteAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    public static async Task DecryptRecipientAsync(
        Stream source, Stream destination, PqRecipientPrivateKey privateKey,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken)
    {
        await InstrumentedAsync("decrypt", "ml-kem-recipient", totalBytes, async () =>
        {
            ContainerHeader header = await Codec.ReadHeaderAsync(source, cancellationToken).ConfigureAwait(false);
            if (header.KeySource != ContainerFormat.KeySourceMlKemRecipient)
            {
                throw new PqDecryptionException("This container is encrypted with a passphrase, not a recipient key.");
            }
            byte[] contentKey = KeyEstablishment.UnwrapRecipientKey(header, privateKey);
            await Codec.ReadBodyAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }
}
