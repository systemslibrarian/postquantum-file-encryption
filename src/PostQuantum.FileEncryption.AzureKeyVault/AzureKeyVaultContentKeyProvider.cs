using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Azure;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace PostQuantum.FileEncryption.AzureKeyVault;

/// <summary>
/// An <see cref="IContentKeyProvider"/> backed by <b>Azure Key Vault</b> (or Managed HSM).
/// Each file is encrypted under a fresh per-file content key generated locally and wrapped by
/// the vault's key-wrap operation (RSA-OAEP-256 by default); the key-encryption key never
/// leaves the vault or HSM. Decryption sends only the small wrapped blob back for unwrap.
/// </summary>
/// <remarks>
/// <para>
/// The wrap records the exact (versioned) Key Vault key id that produced it. On unwrap, that
/// recorded id must match the configured client's key — a wrapped key from a different key
/// fails closed with <see cref="PqDecryptionException"/> before any vault round-trip, and the
/// recorded algorithm is never honored from the (unauthenticated-at-this-point) header: the
/// provider always unwraps with its <em>configured</em> algorithm. Vault-side cryptographic
/// failures map to <see cref="PqDecryptionException"/>; operational failures (authentication,
/// authorization, network, throttling) propagate as the SDK's own exceptions so they are not
/// mistaken for tampering.
/// </para>
/// <para>
/// Construct the <see cref="CryptographyClient"/> with a <b>versioned</b> key URI to keep old
/// files decryptable across key rotation (an unversioned client always targets the latest key
/// version). Instances are immutable and thread-safe; the provider does not own the client.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultContentKeyProvider : IContentKeyProvider
{
    // wrapInfo layout: Version(1) ‖ KeyIdLength(2, big-endian) ‖ KeyId(UTF-8) ‖ WrappedKey.
    private const byte WrapInfoVersion = 1;
    private const int ContentKeyLength = 32;
    private const int MaxKeyIdLength = 2048;

    private readonly CryptographyClient _client;
    private readonly KeyWrapAlgorithm _algorithm;

    /// <inheritdoc/>
    public string ProviderId => "azure-key-vault";

    /// <summary>Creates a provider that wraps with <c>RSA-OAEP-256</c>.</summary>
    /// <param name="cryptographyClient">
    /// A client for the Key Vault key that wraps every content key. The caller owns its
    /// lifetime and credentials. Prefer a versioned key URI (see remarks on the class).
    /// </param>
    public AzureKeyVaultContentKeyProvider(CryptographyClient cryptographyClient)
        : this(cryptographyClient, KeyWrapAlgorithm.RsaOaep256)
    {
    }

    /// <summary>Creates a provider with an explicit key-wrap algorithm (e.g. <c>A256KW</c> on Managed HSM).</summary>
    public AzureKeyVaultContentKeyProvider(CryptographyClient cryptographyClient, KeyWrapAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(cryptographyClient);
        _client = cryptographyClient;
        _algorithm = algorithm;
    }

    /// <inheritdoc/>
    public async Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken cancellationToken = default)
    {
        byte[] contentKey = RandomNumberGenerator.GetBytes(ContentKeyLength);
        try
        {
            WrapResult result = await _client.WrapKeyAsync(_algorithm, contentKey, cancellationToken).ConfigureAwait(false);

            byte[] keyId = Encoding.UTF8.GetBytes(result.KeyId ?? _client.KeyId);
            if (keyId.Length is 0 or > MaxKeyIdLength)
            {
                throw new PqEncryptionException("Azure Key Vault returned an unusable key id for the wrap.");
            }

            byte[] wrapInfo = new byte[1 + 2 + keyId.Length + result.EncryptedKey.Length];
            wrapInfo[0] = WrapInfoVersion;
            BinaryPrimitives.WriteUInt16BigEndian(wrapInfo.AsSpan(1), (ushort)keyId.Length);
            keyId.CopyTo(wrapInfo, 3);
            result.EncryptedKey.CopyTo(wrapInfo, 3 + keyId.Length);
            return (contentKey, wrapInfo);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw;
        }
    }

    /// <inheritdoc/>
    public async Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken cancellationToken = default)
    {
        ReadOnlySpan<byte> span = wrapInfo.Span;
        if (span.Length < 4 || span[0] != WrapInfoVersion)
        {
            throw new PqDecryptionException("The wrapped key is malformed or was not produced by the azure-key-vault provider.");
        }

        int keyIdLength = BinaryPrimitives.ReadUInt16BigEndian(span[1..]);
        if (keyIdLength is 0 or > MaxKeyIdLength || span.Length < 3 + keyIdLength + 1)
        {
            throw new PqDecryptionException("The wrapped key is malformed or was not produced by the azure-key-vault provider.");
        }

        string recordedKeyId = Encoding.UTF8.GetString(span.Slice(3, keyIdLength));
        if (!KeyIdMatchesConfiguredKey(recordedKeyId))
        {
            // A clear operational error, like LocalKek's wrong-length message: the caller is
            // holding the wrong provider, not (necessarily) a tampered file.
            throw new PqDecryptionException(
                $"The container's content key was wrapped under Key Vault key '{recordedKeyId}', " +
                $"but this provider is configured for '{_client.KeyId}'.");
        }

        byte[] wrappedKey = span[(3 + keyIdLength)..].ToArray();
        UnwrapResult result;
        try
        {
            result = await _client.UnwrapKeyAsync(_algorithm, wrappedKey, cancellationToken).ConfigureAwait(false);
        }
        catch (RequestFailedException ex) when (ex.Status == 400)
        {
            throw new PqDecryptionException(
                "Decryption failed: the wrapped key is invalid, was altered, or was not produced under this key and algorithm.", ex);
        }

        byte[] contentKey = result.Key;
        if (contentKey is null || contentKey.Length != ContentKeyLength)
        {
            if (contentKey is not null)
            {
                CryptographicOperations.ZeroMemory(contentKey);
            }
            throw new PqDecryptionException("Azure Key Vault returned a content key of unexpected length.");
        }
        return contentKey;
    }

    /// <summary>
    /// The recorded id must be the configured key, allowing an unversioned configured client to
    /// match the versioned id the service recorded (Key Vault ids are
    /// <c>https://vault/keys/name[/version]</c>).
    /// </summary>
    private bool KeyIdMatchesConfiguredKey(string recordedKeyId) =>
        string.Equals(recordedKeyId, _client.KeyId, StringComparison.Ordinal) ||
        recordedKeyId.StartsWith(_client.KeyId + "/", StringComparison.Ordinal);
}
