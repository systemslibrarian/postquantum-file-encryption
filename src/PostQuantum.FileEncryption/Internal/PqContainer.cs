using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

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
            // The codec zeroes contentKey in its own finally; this one covers the window where
            // header creation throws before the codec is ever entered (re-zeroing is harmless).
            try
            {
                var header = ContainerHeader.Create(ContainerFormat.KeySourcePassphrase, options.ChunkSizeBytes, keyParams, noncePrefixOverride);
                await Codec.WriteAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(contentKey); }
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
            try
            {
                var header = ContainerHeader.Create(ContainerFormat.KeySourceMlKemRecipient, options.ChunkSizeBytes, keyParams);
                await Codec.WriteAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(contentKey); }
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

    // ---------------------------------------------------------------- external key provider (KeySource = 5)

    public static async Task EncryptKeyProviderAsync(
        Stream source, Stream destination, IContentKeyProvider provider, PqEncryptionOptions options,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken)
    {
        await InstrumentedAsync("encrypt", "key-provider", totalBytes, async () =>
        {
            (byte[] contentKey, byte[] wrapInfo) = await provider.WrapNewKeyAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                byte[] keyParams = SerializeKeyProviderParams(provider.ProviderId, wrapInfo);
                var header = ContainerHeader.Create(ContainerFormat.KeySourceKeyProvider, options.ChunkSizeBytes, keyParams);
                await Codec.WriteAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
            }
            finally { CryptographicOperations.ZeroMemory(contentKey); }
        }).ConfigureAwait(false);
    }

    public static async Task DecryptKeyProviderAsync(
        Stream source, Stream destination, IContentKeyProvider provider,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken)
    {
        await InstrumentedAsync("decrypt", "key-provider", totalBytes, async () =>
        {
            ContainerHeader header = await Codec.ReadHeaderAsync(source, cancellationToken).ConfigureAwait(false);
            if (header.KeySource != ContainerFormat.KeySourceKeyProvider)
            {
                throw new PqDecryptionException("This container was not encrypted with an external key provider.");
            }
            (string providerId, byte[] wrapInfo) = ParseKeyProviderParams(header.KeyParams);
            if (!string.Equals(providerId, provider.ProviderId, StringComparison.Ordinal))
            {
                throw new PqDecryptionException(
                    $"This container was encrypted by a different key provider ('{providerId}'), not '{provider.ProviderId}'.");
            }
            byte[] contentKey = await provider.UnwrapKeyAsync(wrapInfo, cancellationToken).ConfigureAwait(false);
            await Codec.ReadBodyAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }

    // KeyParams (KeySource=5): ProviderIdLength(1) | ProviderId(UTF-8) | WrapInfoLength(2 BE) | WrapInfo
    private static byte[] SerializeKeyProviderParams(string providerId, byte[] wrapInfo)
    {
        byte[] id = Encoding.UTF8.GetBytes(providerId);
        if (id.Length is 0 or > byte.MaxValue)
        {
            throw new ArgumentException("Provider id must be between 1 and 255 UTF-8 bytes.", nameof(providerId));
        }
        if (wrapInfo.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Provider wrap info is too large.", nameof(wrapInfo));
        }

        var buffer = new byte[1 + id.Length + 2 + wrapInfo.Length];
        buffer[0] = (byte)id.Length;
        id.CopyTo(buffer, 1);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(1 + id.Length), (ushort)wrapInfo.Length);
        wrapInfo.CopyTo(buffer, 1 + id.Length + 2);
        return buffer;
    }

    private static (string providerId, byte[] wrapInfo) ParseKeyProviderParams(byte[] keyParams)
    {
        var span = keyParams.AsSpan();
        if (span.Length < 1)
        {
            throw new PqFormatException("Key-provider parameters are empty.");
        }
        int idLength = span[0];
        if (idLength == 0 || span.Length < 1 + idLength + 2)
        {
            throw new PqFormatException("Key-provider parameters are malformed.");
        }
        string providerId = Encoding.UTF8.GetString(span.Slice(1, idLength));
        int wrapInfoLength = BinaryPrimitives.ReadUInt16BigEndian(span[(1 + idLength)..]);
        if (span.Length != 1 + idLength + 2 + wrapInfoLength)
        {
            throw new PqFormatException("Key-provider parameters have an invalid length.");
        }
        byte[] wrapInfo = span.Slice(1 + idLength + 2, wrapInfoLength).ToArray();
        return (providerId, wrapInfo);
    }
}
