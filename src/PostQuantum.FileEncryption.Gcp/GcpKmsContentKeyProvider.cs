using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Google.Api.Gax.Grpc;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Grpc.Core;

namespace PostQuantum.FileEncryption.Gcp;

/// <summary>
/// An <see cref="IContentKeyProvider"/> backed by <b>Google Cloud KMS</b>. Each file is
/// encrypted under a fresh per-file content key generated locally and wrapped by Cloud KMS
/// <c>Encrypt</c> under your key-ring key, which never leaves Google Cloud. Decryption sends
/// only the small wrapped blob back to Cloud KMS <c>Decrypt</c>.
/// </summary>
/// <remarks>
/// <para>
/// Unlike AWS KMS, Cloud KMS has no server-side data-key generation, so the 32-byte content
/// key originates in this process (<see cref="RandomNumberGenerator"/>) and crosses to the
/// service once, for wrapping — the same envelope pattern Google's Tink library uses.
/// Every wrap is bound to library-specific <b>additional authenticated data</b> (plus any
/// caller-supplied bytes), and unwrap targets only the configured <c>CryptoKey</c> — a blob
/// wrapped under a different key or AAD fails closed with <see cref="PqDecryptionException"/>.
/// Operational failures (missing key, permission denied, throttling, network) propagate as
/// <see cref="RpcException"/> so they are not mistaken for tampering.
/// </para>
/// <para>
/// The CRC32C integrity fields Cloud KMS offers are populated on every request and verified
/// on every response (the .NET SDK does not do this for you); a checksum mismatch fails the
/// operation rather than trusting a possibly corrupted round-trip.
/// </para>
/// <para>
/// Instances are immutable and thread-safe; the provider does not own or dispose the supplied
/// KMS client.
/// </para>
/// </remarks>
public sealed class GcpKmsContentKeyProvider : IContentKeyProvider
{
    // wrapInfo layout: Version(1) ‖ Cloud KMS ciphertext (opaque, self-describing — it names
    // the CryptoKeyVersion that produced it, so rotation needs nothing recorded here).
    private const byte WrapInfoVersion = 1;
    private const int ContentKeyLength = 32;
    // Cloud KMS symmetric Encrypt of a 32-byte CEK yields ~113 bytes (a few hundred for
    // HSM/EXTERNAL protection levels); 16 KiB is far above any legitimate ciphertext. A
    // hostile container can declare up to 65535 bytes of wrapInfo; rejecting oversized blobs
    // here keeps the failure inside the library's exception contract (and skips a doomed,
    // billable network round-trip) instead of letting a service or transport error surface
    // as a raw SDK exception. (Matches the aws-kms provider's local cap.)
    private const int MaxKmsCiphertextLength = 16 * 1024;

    // Domain separation, fixed-length so appending caller AAD is unambiguous: a blob wrapped
    // by some other Cloud KMS user of the same key cannot be replayed into a .pqfe header,
    // and vice versa.
    private static readonly byte[] LibraryAadPrefix =
        Encoding.UTF8.GetBytes("PostQuantum.FileEncryption/gcp-kms cek-wrap v1\n");

    // One literal on purpose: every unwrap-authenticity failure must surface with
    // byte-identical text, or the difference becomes an oracle.
    private const string UnwrapFailedMessage =
        "Decryption failed: the wrapped key is invalid, was altered, or was not produced under this key and AAD.";

    private readonly KeyManagementServiceClient _kms;
    private readonly string _cryptoKeyName;
    private readonly byte[] _aad;

    /// <inheritdoc/>
    public string ProviderId => "gcp-kms";

    /// <summary>
    /// Creates a provider over a Cloud KMS client and the full resource name of the wrapping
    /// key (<c>projects/*/locations/*/keyRings/*/cryptoKeys/*</c>).
    /// </summary>
    /// <param name="kms">The Cloud KMS client. The caller owns its lifetime and credentials.</param>
    /// <param name="cryptoKeyName">
    /// The <c>CryptoKey</c> that wraps every content key. Unwrap always targets this key, and
    /// Cloud KMS selects the correct <c>CryptoKeyVersion</c> from the ciphertext itself, so
    /// old files stay decryptable across key rotation. Must be the full resource name; a
    /// malformed name is rejected here (<see cref="ArgumentException"/>) rather than being
    /// misreported as a decryption failure later.
    /// </param>
    /// <param name="additionalAuthenticatedData">
    /// Optional extra bytes (e.g. a tenant or dataset id) bound into every wrap after the
    /// library's own binding; the same bytes are required to unwrap.
    /// </param>
    public GcpKmsContentKeyProvider(
        KeyManagementServiceClient kms,
        string cryptoKeyName,
        ReadOnlyMemory<byte> additionalAuthenticatedData = default)
    {
        ArgumentNullException.ThrowIfNull(kms);
        ArgumentException.ThrowIfNullOrEmpty(cryptoKeyName);
        // Cloud KMS reports a malformed resource name as INVALID_ARGUMENT — the same status
        // an undecryptable ciphertext gets. Rejecting the typo here keeps a configuration
        // mistake from ever being misreported as tampering at unwrap time.
        if (!CryptoKeyName.TryParse(cryptoKeyName, out _))
        {
            throw new ArgumentException(
                "The crypto key name must be a full resource name of the form " +
                "projects/*/locations/*/keyRings/*/cryptoKeys/*.",
                nameof(cryptoKeyName));
        }

        _kms = kms;
        _cryptoKeyName = cryptoKeyName;
        _aad = new byte[LibraryAadPrefix.Length + additionalAuthenticatedData.Length];
        LibraryAadPrefix.CopyTo(_aad, 0);
        additionalAuthenticatedData.Span.CopyTo(_aad.AsSpan(LibraryAadPrefix.Length));
    }

    /// <inheritdoc/>
    public async Task<(byte[] contentKey, byte[] wrapInfo)> WrapNewKeyAsync(CancellationToken cancellationToken = default)
    {
        byte[] contentKey = RandomNumberGenerator.GetBytes(ContentKeyLength);
        try
        {
            // UnsafeWrap shares the array instead of copying it into an unzeroable ByteString;
            // the request does not outlive this call, and the caller owns (and zeroes) the key.
            EncryptResponse response = await _kms.EncryptAsync(
                new EncryptRequest
                {
                    Name = _cryptoKeyName,
                    Plaintext = UnsafeByteOperations.UnsafeWrap(contentKey),
                    AdditionalAuthenticatedData = ByteString.CopyFrom(_aad),
                    PlaintextCrc32C = Crc32C.Compute(contentKey),
                    AdditionalAuthenticatedDataCrc32C = Crc32C.Compute(_aad),
                },
                CallSettings.FromCancellationToken(cancellationToken)).ConfigureAwait(false);

            // The service echoes whether it saw and verified each request checksum, and
            // checksums its own response; anything short of full verification means the
            // round-trip cannot be trusted end to end.
            if (!response.VerifiedPlaintextCrc32C
                || !response.VerifiedAdditionalAuthenticatedDataCrc32C
                || response.CiphertextCrc32C != Crc32C.Compute(response.Ciphertext.Span))
            {
                throw new PqEncryptionException(
                    "Cloud KMS Encrypt failed its CRC32C integrity check; the request or response was corrupted in transit.");
            }
            // The CRC fields cover the payload bytes but not the request's key name; the
            // response names the CryptoKeyVersion that actually wrapped. Anything but the
            // configured key means the file would be silently unrecoverable under it.
            if (!response.Name.StartsWith(_cryptoKeyName + "/cryptoKeyVersions/", StringComparison.Ordinal))
            {
                throw new PqEncryptionException(
                    "Cloud KMS Encrypt responded for an unexpected key; the request may have been corrupted in transit.");
            }

            byte[] wrapInfo = new byte[1 + response.Ciphertext.Length];
            wrapInfo[0] = WrapInfoVersion;
            response.Ciphertext.Span.CopyTo(wrapInfo.AsSpan(1));
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
        if (wrapInfo.Length < 2 || wrapInfo.Length > 1 + MaxKmsCiphertextLength || wrapInfo.Span[0] != WrapInfoVersion)
        {
            throw new PqDecryptionException("The wrapped key is malformed or was not produced by the gcp-kms provider.");
        }

        ReadOnlyMemory<byte> ciphertext = wrapInfo[1..];
        DecryptResponse response;
        try
        {
            // Decrypt targets the configured CryptoKey, so a valid blob wrapped under a
            // *different* key the caller can also decrypt is still rejected — no
            // confused-deputy unwraps.
            response = await _kms.DecryptAsync(
                new DecryptRequest
                {
                    Name = _cryptoKeyName,
                    Ciphertext = ByteString.CopyFrom(ciphertext.Span),
                    AdditionalAuthenticatedData = ByteString.CopyFrom(_aad),
                    CiphertextCrc32C = Crc32C.Compute(ciphertext.Span),
                    AdditionalAuthenticatedDataCrc32C = Crc32C.Compute(_aad),
                },
                CallSettings.FromCancellationToken(cancellationToken)).ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.InvalidArgument)
        {
            // Cloud KMS surfaces a tampered, foreign-key, or AAD-mismatched ciphertext as
            // INVALID_ARGUMENT; operational failures use other status codes and propagate.
            throw new PqDecryptionException(UnwrapFailedMessage, ex);
        }

        byte[] contentKey = ReadAndZero(response.Plaintext);
        try
        {
            if (response.PlaintextCrc32C != Crc32C.Compute(contentKey))
            {
                throw new PqDecryptionException(
                    "Cloud KMS Decrypt failed its CRC32C integrity check; the response was corrupted in transit.");
            }
            if (contentKey.Length != ContentKeyLength)
            {
                throw new PqDecryptionException("Cloud KMS returned a content key of unexpected length.");
            }
            return contentKey;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(contentKey);
            throw;
        }
    }

    /// <summary>
    /// Copies the SDK's plaintext out and zeroes the <see cref="ByteString"/>'s backing array
    /// so this type does not leave an extra copy of key material behind (best effort — the
    /// gRPC stack may hold others; see KNOWN-GAPS.md).
    /// </summary>
    private static byte[] ReadAndZero(ByteString plaintext)
    {
        byte[] copy = plaintext.ToByteArray();
        if (MemoryMarshal.TryGetArray(plaintext.Memory, out ArraySegment<byte> buffer))
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
        return copy;
    }
}
