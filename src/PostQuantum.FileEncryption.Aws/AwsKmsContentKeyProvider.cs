using System.Security.Cryptography;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;

namespace PostQuantum.FileEncryption.Aws;

/// <summary>
/// An <see cref="IContentKeyProvider"/> backed by <b>AWS KMS</b>. Each file is encrypted under
/// a fresh per-file content key obtained from KMS <c>GenerateDataKey</c>; KMS wraps that key
/// under your customer master key (CMK), which never leaves AWS. Decryption sends only the
/// small wrapped blob back to KMS <c>Decrypt</c>.
/// </summary>
/// <remarks>
/// <para>
/// Every wrap is bound to a library-specific <b>encryption context</b> (plus any caller-supplied
/// entries) and, on unwrap, to the configured key id — a wrapped key produced under a different
/// CMK or context fails closed with <see cref="PqDecryptionException"/>. Operational failures
/// (missing key, access denied, throttling, network) propagate as the SDK's own exceptions so
/// they are not mistaken for tampering.
/// </para>
/// <para>
/// Instances are immutable and thread-safe; the provider does not own or dispose the supplied
/// KMS client.
/// </para>
/// </remarks>
public sealed class AwsKmsContentKeyProvider : IContentKeyProvider
{
    // wrapInfo layout: Version(1) ‖ KMS ciphertext blob (opaque, self-describing).
    private const byte WrapInfoVersion = 1;
    private const int ContentKeyLength = 32;
    private const string ReservedContextPrefix = "pqfe:";

    private readonly IAmazonKeyManagementService _kms;
    private readonly string _keyId;
    private readonly Dictionary<string, string> _encryptionContext;

    /// <inheritdoc/>
    public string ProviderId => "aws-kms";

    /// <summary>
    /// Creates a provider over a KMS client and key id (key id, key ARN, alias name, or alias ARN).
    /// </summary>
    /// <param name="kms">The KMS client. The caller owns its lifetime and credentials.</param>
    /// <param name="keyId">The CMK that wraps every content key. Unwrap is pinned to this key.</param>
    /// <param name="encryptionContext">
    /// Optional extra encryption-context entries (e.g. a tenant or dataset id) bound into every
    /// wrap; the same entries are required to unwrap. Keys must not start with <c>pqfe:</c>,
    /// which is reserved for the library's own binding.
    /// </param>
    public AwsKmsContentKeyProvider(
        IAmazonKeyManagementService kms,
        string keyId,
        IReadOnlyDictionary<string, string>? encryptionContext = null)
    {
        ArgumentNullException.ThrowIfNull(kms);
        ArgumentException.ThrowIfNullOrEmpty(keyId);

        _kms = kms;
        _keyId = keyId;
        _encryptionContext = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // Domain separation: a blob wrapped by some other KMS user of the same CMK cannot
            // be replayed into a .pqfe header, and vice versa.
            ["pqfe:wrap"] = "PostQuantum.FileEncryption/aws-kms cek-wrap v1",
        };
        if (encryptionContext is not null)
        {
            foreach ((string key, string value) in encryptionContext)
            {
                if (key.StartsWith(ReservedContextPrefix, StringComparison.Ordinal))
                {
                    throw new ArgumentException(
                        $"Encryption-context keys must not start with '{ReservedContextPrefix}' (reserved).",
                        nameof(encryptionContext));
                }
                _encryptionContext[key] = value;
            }
        }
    }

    /// <inheritdoc/>
    public async Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken cancellationToken = default)
    {
        var response = await _kms.GenerateDataKeyAsync(
            new GenerateDataKeyRequest
            {
                KeyId = _keyId,
                KeySpec = DataKeySpec.AES_256,
                EncryptionContext = _encryptionContext,
            },
            cancellationToken).ConfigureAwait(false);

        byte[] contentKey = ReadAndZero(response.Plaintext);
        if (contentKey.Length != ContentKeyLength)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw new PqEncryptionException("AWS KMS returned a data key of unexpected length.");
        }

        byte[] blob = response.CiphertextBlob.ToArray();
        byte[] wrapInfo = new byte[1 + blob.Length];
        wrapInfo[0] = WrapInfoVersion;
        blob.CopyTo(wrapInfo, 1);
        return (contentKey, wrapInfo);
    }

    /// <inheritdoc/>
    public async Task<byte[]> UnwrapKeyAsync(ReadOnlyMemory<byte> wrapInfo, CancellationToken cancellationToken = default)
    {
        if (wrapInfo.Length < 2 || wrapInfo.Span[0] != WrapInfoVersion)
        {
            throw new PqDecryptionException("The wrapped key is malformed or was not produced by the aws-kms provider.");
        }

        using var blob = new MemoryStream(wrapInfo[1..].ToArray(), writable: false);
        DecryptResponse response;
        try
        {
            response = await _kms.DecryptAsync(
                new DecryptRequest
                {
                    CiphertextBlob = blob,
                    EncryptionContext = _encryptionContext,
                    // Pinning the key id means a valid blob wrapped under a *different* CMK the
                    // caller can also decrypt is still rejected — no confused-deputy unwraps.
                    KeyId = _keyId,
                },
                cancellationToken).ConfigureAwait(false);
        }
        catch (InvalidCiphertextException ex)
        {
            throw new PqDecryptionException(
                "Decryption failed: the wrapped key is invalid, was altered, or was not produced under this key and context.", ex);
        }
        catch (IncorrectKeyException ex)
        {
            throw new PqDecryptionException(
                "Decryption failed: the wrapped key is invalid, was altered, or was not produced under this key and context.", ex);
        }

        byte[] contentKey = ReadAndZero(response.Plaintext);
        if (contentKey.Length != ContentKeyLength)
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw new PqDecryptionException("AWS KMS returned a data key of unexpected length.");
        }
        return contentKey;
    }

    /// <summary>
    /// Copies the SDK's plaintext stream out and zeroes the stream's internal buffer so this
    /// type does not leave an extra copy of key material behind (best effort — the SDK may
    /// hold others; see KNOWN-GAPS.md).
    /// </summary>
    private static byte[] ReadAndZero(MemoryStream plaintext)
    {
        using (plaintext)
        {
            byte[] copy = plaintext.ToArray();
            if (plaintext.TryGetBuffer(out ArraySegment<byte> buffer))
            {
                CryptographicOperations.ZeroMemory(buffer);
            }
            return copy;
        }
    }
}
