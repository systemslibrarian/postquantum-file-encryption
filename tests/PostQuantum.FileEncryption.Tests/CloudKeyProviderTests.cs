using System.Security.Cryptography;
using System.Text;
using Amazon.KeyManagementService;
using Amazon.KeyManagementService.Model;
using Amazon.Runtime;
using Azure;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Google.Api.Gax.Grpc;
using Google.Cloud.Kms.V1;
using Google.Protobuf;
using Grpc.Core;
using PostQuantum.FileEncryption.Aws;
using PostQuantum.FileEncryption.AzureKeyVault;
using PostQuantum.FileEncryption.Gcp;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;
using AwsDecryptRequest = Amazon.KeyManagementService.Model.DecryptRequest;
using AwsDecryptResponse = Amazon.KeyManagementService.Model.DecryptResponse;
using GcpDecryptRequest = Google.Cloud.Kms.V1.DecryptRequest;
using GcpDecryptResponse = Google.Cloud.Kms.V1.DecryptResponse;
using GcpEncryptRequest = Google.Cloud.Kms.V1.EncryptRequest;
using GcpEncryptResponse = Google.Cloud.Kms.V1.EncryptResponse;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// The AWS KMS, Azure Key Vault, and Google Cloud KMS envelope-key providers, exercised
/// against in-process fakes of the cloud SDK clients (no credentials, no network). The fakes
/// implement real wrap semantics — AES-GCM with the encryption context (or AAD) as AAD for
/// the two "KMS" services, RSA-OAEP-256 for "Key Vault" — so the providers' binding and
/// fail-closed behavior is genuinely tested. Live-cloud integration is deliberately out of
/// CI scope (KNOWN-GAPS.md).
/// </summary>
public sealed class CloudKeyProviderTests
{
    // ---------------------------------------------------------------- AWS KMS

    private const string KmsKeyId = "alias/pqfe-test-key";

    [Fact]
    public async Task Aws_wrap_unwrap_round_trip()
    {
        using var kms = new FakeKmsClient(KmsKeyId);
        var provider = new AwsKmsContentKeyProvider(kms, KmsKeyId);

        (byte[] contentKey, byte[] wrapInfo) = await provider.WrapNewKeyAsync();
        byte[] recovered = await provider.UnwrapKeyAsync(wrapInfo);

        Assert.Equal(32, contentKey.Length);
        Assert.Equal(contentKey, recovered);
    }

    [Fact]
    public async Task Aws_container_round_trip()
    {
        using var kms = new FakeKmsClient(KmsKeyId);
        var provider = new AwsKmsContentKeyProvider(kms, KmsKeyId);
        byte[] original = RandomBytes(5000);

        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, provider);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, provider);

        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Aws_tampered_wrap_fails_closed()
    {
        using var kms = new FakeKmsClient(KmsKeyId);
        var provider = new AwsKmsContentKeyProvider(kms, KmsKeyId);
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        wrapInfo[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public async Task Aws_wrong_version_byte_fails_closed()
    {
        using var kms = new FakeKmsClient(KmsKeyId);
        var provider = new AwsKmsContentKeyProvider(kms, KmsKeyId);
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        wrapInfo[0] = 0xFF;
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(Array.Empty<byte>()));
    }

    [Fact]
    public async Task Aws_encryption_context_is_binding()
    {
        using var kms = new FakeKmsClient(KmsKeyId);
        var tenantA = new AwsKmsContentKeyProvider(kms, KmsKeyId,
            new Dictionary<string, string> { ["tenant"] = "a" });
        var tenantB = new AwsKmsContentKeyProvider(kms, KmsKeyId,
            new Dictionary<string, string> { ["tenant"] = "b" });

        (_, byte[] wrapInfo) = await tenantA.WrapNewKeyAsync();
        await Assert.ThrowsAsync<PqDecryptionException>(() => tenantB.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public void Aws_reserved_context_prefix_is_rejected()
    {
        using var kms = new FakeKmsClient(KmsKeyId);
        Assert.Throws<ArgumentException>(() => new AwsKmsContentKeyProvider(kms, KmsKeyId,
            new Dictionary<string, string> { ["pqfe:evil"] = "x" }));
    }

    // ---------------------------------------------------------------- Azure Key Vault

    private const string VaultKeyId = "https://unit.vault.azure.net/keys/pqfe-kek";
    private const string VaultKeyIdVersioned = VaultKeyId + "/0123456789abcdef0123456789abcdef";

    [Fact]
    public async Task Azure_wrap_unwrap_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var provider = new AzureKeyVaultContentKeyProvider(new FakeCryptographyClient(VaultKeyIdVersioned, rsa));

        (byte[] contentKey, byte[] wrapInfo) = await provider.WrapNewKeyAsync();
        byte[] recovered = await provider.UnwrapKeyAsync(wrapInfo);

        Assert.Equal(32, contentKey.Length);
        Assert.Equal(contentKey, recovered);
    }

    [Fact]
    public async Task Azure_container_round_trip()
    {
        using var rsa = RSA.Create(2048);
        var provider = new AzureKeyVaultContentKeyProvider(new FakeCryptographyClient(VaultKeyIdVersioned, rsa));
        byte[] original = RandomBytes(5000);

        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, provider);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, provider);

        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Azure_tampered_wrap_fails_closed()
    {
        using var rsa = RSA.Create(2048);
        var provider = new AzureKeyVaultContentKeyProvider(new FakeCryptographyClient(VaultKeyIdVersioned, rsa));
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        wrapInfo[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public async Task Azure_malformed_wrap_fails_closed()
    {
        using var rsa = RSA.Create(2048);
        var provider = new AzureKeyVaultContentKeyProvider(new FakeCryptographyClient(VaultKeyIdVersioned, rsa));
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo.AsMemory(..3)));
        wrapInfo[0] = 0xFF;
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public async Task Azure_wrap_from_a_different_key_fails_closed()
    {
        using var rsa = RSA.Create(2048);
        var alice = new AzureKeyVaultContentKeyProvider(
            new FakeCryptographyClient("https://unit.vault.azure.net/keys/alice-kek", rsa));
        var bob = new AzureKeyVaultContentKeyProvider(
            new FakeCryptographyClient("https://unit.vault.azure.net/keys/bob-kek", rsa));

        (_, byte[] wrapInfo) = await alice.WrapNewKeyAsync();
        var ex = await Assert.ThrowsAsync<PqDecryptionException>(() => bob.UnwrapKeyAsync(wrapInfo));
        Assert.Contains("alice-kek", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Azure_unversioned_client_accepts_its_own_versioned_wrap()
    {
        using var rsa = RSA.Create(2048);
        // The fake's WrapResult records the versioned id while the client reports the
        // unversioned one — the rotation-friendly shape a real vault produces.
        var client = new FakeCryptographyClient(VaultKeyId, rsa, wrapResultKeyId: VaultKeyIdVersioned);
        var provider = new AzureKeyVaultContentKeyProvider(client);

        (byte[] contentKey, byte[] wrapInfo) = await provider.WrapNewKeyAsync();
        Assert.Equal(contentKey, await provider.UnwrapKeyAsync(wrapInfo));
    }

    // ---------------------------------------------------------------- Google Cloud KMS

    private const string GcpKeyName =
        "projects/unit/locations/global/keyRings/pqfe-test/cryptoKeys/pqfe-test-key";

    [Fact]
    public async Task Gcp_wrap_unwrap_round_trip()
    {
        var kms = new FakeGcpKmsClient(GcpKeyName);
        var provider = new GcpKmsContentKeyProvider(kms, GcpKeyName);

        (byte[] contentKey, byte[] wrapInfo) = await provider.WrapNewKeyAsync();
        byte[] recovered = await provider.UnwrapKeyAsync(wrapInfo);

        Assert.Equal(32, contentKey.Length);
        Assert.Equal(contentKey, recovered);
    }

    [Fact]
    public async Task Gcp_container_round_trip()
    {
        var kms = new FakeGcpKmsClient(GcpKeyName);
        var provider = new GcpKmsContentKeyProvider(kms, GcpKeyName);
        byte[] original = RandomBytes(5000);

        byte[] container = await new PqFileEncryptor(Fast()).EncryptBytesAsync(original, provider);
        byte[] restored = await new PqFileDecryptor().DecryptBytesAsync(container, provider);

        Assert.Equal(original, restored);
    }

    [Fact]
    public async Task Gcp_tampered_wrap_fails_closed()
    {
        var kms = new FakeGcpKmsClient(GcpKeyName);
        var provider = new GcpKmsContentKeyProvider(kms, GcpKeyName);
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        wrapInfo[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public async Task Gcp_wrong_version_byte_fails_closed()
    {
        var kms = new FakeGcpKmsClient(GcpKeyName);
        var provider = new GcpKmsContentKeyProvider(kms, GcpKeyName);
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        wrapInfo[0] = 0xFF;
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(Array.Empty<byte>()));
    }

    [Fact]
    public async Task Gcp_additional_authenticated_data_is_binding()
    {
        var kms = new FakeGcpKmsClient(GcpKeyName);
        var tenantA = new GcpKmsContentKeyProvider(kms, GcpKeyName, "tenant=a"u8.ToArray());
        var tenantB = new GcpKmsContentKeyProvider(kms, GcpKeyName, "tenant=b"u8.ToArray());

        (_, byte[] wrapInfo) = await tenantA.WrapNewKeyAsync();
        await Assert.ThrowsAsync<PqDecryptionException>(() => tenantB.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public async Task Gcp_wrap_from_a_different_key_fails_closed()
    {
        // Two "projects", each with its own master key. The blob from alice's key reaches
        // bob's — like the real service, decryption under the wrong key fails with
        // INVALID_ARGUMENT, which must surface as the fail-closed exception.
        const string bobKeyName = "projects/unit/locations/global/keyRings/pqfe-test/cryptoKeys/bob-key";
        var alice = new GcpKmsContentKeyProvider(new FakeGcpKmsClient(GcpKeyName), GcpKeyName);
        var bob = new GcpKmsContentKeyProvider(new FakeGcpKmsClient(bobKeyName), bobKeyName);

        (_, byte[] wrapInfo) = await alice.WrapNewKeyAsync();
        await Assert.ThrowsAsync<PqDecryptionException>(() => bob.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public async Task Gcp_corrupted_response_checksum_fails_closed()
    {
        var kms = new FakeGcpKmsClient(GcpKeyName);
        var provider = new GcpKmsContentKeyProvider(kms, GcpKeyName);
        (_, byte[] wrapInfo) = await provider.WrapNewKeyAsync();

        kms.CorruptResponseCrc = true;
        await Assert.ThrowsAsync<PqEncryptionException>(() => provider.WrapNewKeyAsync());
        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(wrapInfo));
    }

    [Fact]
    public void Gcp_malformed_crypto_key_name_is_rejected_at_construction()
    {
        // Cloud KMS reports a malformed resource name as INVALID_ARGUMENT — the same status
        // an undecryptable ciphertext gets. The constructor must catch the typo so it can
        // never be misreported as tampering at unwrap time.
        var kms = new FakeGcpKmsClient(GcpKeyName);
        Assert.Throws<ArgumentException>(() => new GcpKmsContentKeyProvider(kms, "my-key"));
        Assert.Throws<ArgumentException>(() => new GcpKmsContentKeyProvider(
            kms, "projects/unit/locations/global/keyRings/pqfe-test"));
    }

    [Fact]
    public async Task Gcp_oversized_wrap_info_fails_closed_locally()
    {
        // The container header allows up to 65535 bytes of wrapInfo; a legitimate Cloud KMS
        // ciphertext is ~113 bytes. Oversized hostile blobs must be rejected before any
        // network round-trip, inside the library's exception contract.
        var provider = new GcpKmsContentKeyProvider(new FakeGcpKmsClient(GcpKeyName), GcpKeyName);
        byte[] oversized = new byte[1 + (16 * 1024) + 1];
        oversized[0] = 0x01;

        await Assert.ThrowsAsync<PqDecryptionException>(() => provider.UnwrapKeyAsync(oversized));
    }

    [Fact]
    public async Task Gcp_wrap_under_an_unexpected_key_fails_closed()
    {
        // The CRC fields cover payload bytes but not the request's key name; if the response
        // names a different CryptoKeyVersion parent, the file would be silently unrecoverable
        // under the configured key — encrypt must fail instead.
        var kms = new FakeGcpKmsClient(GcpKeyName) { ReturnWrongKeyName = true };
        var provider = new GcpKmsContentKeyProvider(kms, GcpKeyName);

        await Assert.ThrowsAsync<PqEncryptionException>(() => provider.WrapNewKeyAsync());
    }

    [Fact]
    public void Gcp_crc32c_matches_the_published_check_value()
    {
        // The CRC32C check value from RFC 3720 §B.4 — if this drifts, every request the
        // provider sends would be rejected by the real service.
        Assert.Equal(0xE3069283L, Crc32C.Compute("123456789"u8));
    }

    // ---------------------------------------------------------------- fakes

    /// <summary>
    /// In-process "KMS": GenerateDataKey/Decrypt with a local master key, AES-GCM, and the
    /// canonicalized encryption context as AAD — the same binding semantics as the service.
    /// </summary>
    private sealed class FakeKmsClient : AmazonKeyManagementServiceClient
    {
        private readonly byte[] _masterKey = RandomNumberGenerator.GetBytes(32);
        private readonly string _keyId;

        public FakeKmsClient(string keyId)
            : base(new AnonymousAWSCredentials(), Amazon.RegionEndpoint.USEast1) => _keyId = keyId;

        public override Task<GenerateDataKeyResponse> GenerateDataKeyAsync(
            GenerateDataKeyRequest request, CancellationToken cancellationToken = default)
        {
            Assert.Equal(_keyId, request.KeyId);
            byte[] cek = RandomNumberGenerator.GetBytes(32);
            byte[] aad = CanonicalContext(request.EncryptionContext);

            byte[] blob = new byte[12 + 16 + cek.Length];
            RandomNumberGenerator.Fill(blob.AsSpan(0, 12));
            using (var gcm = new AesGcm(_masterKey, 16))
            {
                gcm.Encrypt(blob.AsSpan(0, 12), cek, blob.AsSpan(28), blob.AsSpan(12, 16), aad);
            }

            return Task.FromResult(new GenerateDataKeyResponse
            {
                KeyId = _keyId,
                Plaintext = new MemoryStream(cek),
                CiphertextBlob = new MemoryStream(blob),
            });
        }

        public override Task<AwsDecryptResponse> DecryptAsync(
            AwsDecryptRequest request, CancellationToken cancellationToken = default)
        {
            if (request.KeyId is not null && request.KeyId != _keyId)
            {
                throw new IncorrectKeyException("The provided key id does not match the ciphertext's key.");
            }

            byte[] blob = request.CiphertextBlob.ToArray();
            if (blob.Length != 12 + 16 + 32)
            {
                throw new InvalidCiphertextException("Malformed ciphertext blob.");
            }

            byte[] aad = CanonicalContext(request.EncryptionContext);
            byte[] cek = new byte[32];
            try
            {
                using var gcm = new AesGcm(_masterKey, 16);
                gcm.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), cek, aad);
            }
            catch (AuthenticationTagMismatchException)
            {
                throw new InvalidCiphertextException("Ciphertext failed to decrypt.");
            }

            return Task.FromResult(new AwsDecryptResponse
            {
                KeyId = _keyId,
                Plaintext = new MemoryStream(cek),
            });
        }

        private static byte[] CanonicalContext(Dictionary<string, string>? context) =>
            Encoding.UTF8.GetBytes(string.Join(";",
                (context ?? []).OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => $"{p.Key}={p.Value}")));
    }

    /// <summary>In-process "Key Vault key": RSA-OAEP-256 wrap/unwrap over a local RSA key.</summary>
    private sealed class FakeCryptographyClient : CryptographyClient
    {
        private readonly string _keyId;
        private readonly string _wrapResultKeyId;
        private readonly RSA _rsa;

        public FakeCryptographyClient(string keyId, RSA rsa, string? wrapResultKeyId = null)
        {
            _keyId = keyId;
            _rsa = rsa;
            _wrapResultKeyId = wrapResultKeyId ?? keyId;
        }

        public override string KeyId => _keyId;

        public override Task<WrapResult> WrapKeyAsync(
            KeyWrapAlgorithm algorithm, byte[] key, CancellationToken cancellationToken = default)
        {
            Assert.Equal(KeyWrapAlgorithm.RsaOaep256, algorithm);
            byte[] wrapped = _rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256);
            return Task.FromResult(CryptographyModelFactory.WrapResult(_wrapResultKeyId, wrapped, algorithm));
        }

        public override Task<UnwrapResult> UnwrapKeyAsync(
            KeyWrapAlgorithm algorithm, byte[] encryptedKey, CancellationToken cancellationToken = default)
        {
            Assert.Equal(KeyWrapAlgorithm.RsaOaep256, algorithm);
            try
            {
                byte[] key = _rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
                return Task.FromResult(CryptographyModelFactory.UnwrapResult(_keyId, key, algorithm));
            }
            catch (CryptographicException)
            {
                // The service surfaces a bad wrap as HTTP 400; mimic that contract.
                throw new RequestFailedException(400, "Unable to unwrap the key.");
            }
        }
    }

    /// <summary>
    /// In-process "Cloud KMS": Encrypt/Decrypt with a local master key, AES-GCM, and the
    /// request's additional authenticated data as AAD — the same binding semantics as the
    /// service, including its CRC32C request/response integrity fields and the
    /// INVALID_ARGUMENT contract for undecryptable ciphertext.
    /// </summary>
    private sealed class FakeGcpKmsClient : KeyManagementServiceClient
    {
        private readonly byte[] _masterKey = RandomNumberGenerator.GetBytes(32);
        private readonly string _keyName;

        /// <summary>When set, responses carry an off-by-one checksum, as if corrupted in transit.</summary>
        public bool CorruptResponseCrc { get; set; }

        /// <summary>When set, Encrypt responds naming a different key, as if the request name was corrupted.</summary>
        public bool ReturnWrongKeyName { get; set; }

        public FakeGcpKmsClient(string keyName) => _keyName = keyName;

        public override Task<GcpEncryptResponse> EncryptAsync(
            GcpEncryptRequest request, CallSettings? callSettings = null)
        {
            Assert.Equal(_keyName, request.Name);

            byte[] plaintext = request.Plaintext.ToByteArray();
            byte[] aad = request.AdditionalAuthenticatedData.ToByteArray();
            if (request.PlaintextCrc32C != Crc32C.Compute(plaintext)
                || request.AdditionalAuthenticatedDataCrc32C != Crc32C.Compute(aad))
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Checksum mismatch."));
            }

            byte[] blob = new byte[12 + 16 + plaintext.Length];
            RandomNumberGenerator.Fill(blob.AsSpan(0, 12));
            using (var gcm = new AesGcm(_masterKey, 16))
            {
                gcm.Encrypt(blob.AsSpan(0, 12), plaintext, blob.AsSpan(28), blob.AsSpan(12, 16), aad);
            }

            return Task.FromResult(new GcpEncryptResponse
            {
                Name = (ReturnWrongKeyName ? _keyName + "-other" : _keyName) + "/cryptoKeyVersions/1",
                Ciphertext = ByteString.CopyFrom(blob),
                CiphertextCrc32C = Crc32C.Compute(blob) + (CorruptResponseCrc ? 1 : 0),
                VerifiedPlaintextCrc32C = true,
                VerifiedAdditionalAuthenticatedDataCrc32C = true,
            });
        }

        public override Task<GcpDecryptResponse> DecryptAsync(
            GcpDecryptRequest request, CallSettings? callSettings = null)
        {
            Assert.Equal(_keyName, request.Name);

            byte[] blob = request.Ciphertext.ToByteArray();
            byte[] aad = request.AdditionalAuthenticatedData.ToByteArray();
            if (request.CiphertextCrc32C != Crc32C.Compute(blob)
                || request.AdditionalAuthenticatedDataCrc32C != Crc32C.Compute(aad))
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Checksum mismatch."));
            }
            if (blob.Length != 12 + 16 + 32)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Decryption failed."));
            }

            byte[] cek = new byte[32];
            try
            {
                using var gcm = new AesGcm(_masterKey, 16);
                gcm.Decrypt(blob.AsSpan(0, 12), blob.AsSpan(28), blob.AsSpan(12, 16), cek, aad);
            }
            catch (AuthenticationTagMismatchException)
            {
                throw new RpcException(new Status(StatusCode.InvalidArgument, "Decryption failed."));
            }

            return Task.FromResult(new GcpDecryptResponse
            {
                Plaintext = ByteString.CopyFrom(cek),
                PlaintextCrc32C = Crc32C.Compute(cek) + (CorruptResponseCrc ? 1 : 0),
            });
        }
    }
}
