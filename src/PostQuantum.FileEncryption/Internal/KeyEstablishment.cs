using System.Buffers.Binary;
using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// Establishes the per-file 32-byte content key and the matching serialized
/// <c>KeyParams</c> block that goes in the container header. Two sources are supported:
/// a passphrase (via PBKDF2 or Argon2id) and an ML-KEM recipient public key (KEM-DEM).
/// </summary>
/// <remarks>
/// Nothing here is novel cryptography: PBKDF2, Argon2id, ML-KEM, HKDF, and AES-256-GCM are
/// composed in the standard KEM-DEM / password-hashing patterns. The content key returned to
/// callers is owned by the engine, which zeroes it after use.
/// </remarks>
internal static class KeyEstablishment
{
    // Context strings keep these derivations domain-separated from any other use of the secret.
    // Held as byte[] so the standard AES-GCM / HKDF byte[] overloads bind cleanly.
    private static readonly byte[] KekInfo = "PostQuantum.FileEncryption/v2 ml-kem-768 kek"u8.ToArray();
    private static readonly byte[] WrapAad = "PostQuantum.FileEncryption/v2 cek-wrap"u8.ToArray();

    // ---------------------------------------------------------------- Passphrase

    /// <summary>
    /// Derives a new content key from a passphrase and serializes its KeyParams.
    /// <paramref name="saltOverride"/> is for deterministic conformance tests only.
    /// </summary>
    public static async Task<(byte[] keyParams, byte[] contentKey)> BuildPassphraseAsync(
        ReadOnlyMemory<byte> passphrase, PqEncryptionOptions options, byte[]? saltOverride = null)
    {
        byte[] salt = saltOverride ?? RandomNumberGenerator.GetBytes(options.SaltSizeBytes);

        byte[] contentKey = options.Kdf switch
        {
            PqKdf.Pbkdf2HmacSha256 => DerivePbkdf2(passphrase.Span, salt, options.Pbkdf2Iterations),
            PqKdf.Argon2id => await DeriveArgon2idAsync(
                passphrase, salt, options.Argon2MemoryKiB, options.Argon2Iterations, options.Argon2Parallelism).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };

        byte[] keyParams = options.Kdf switch
        {
            PqKdf.Pbkdf2HmacSha256 => SerializePbkdf2Params(salt, options.Pbkdf2Iterations),
            PqKdf.Argon2id => SerializeArgon2idParams(salt, options.Argon2MemoryKiB, options.Argon2Iterations, options.Argon2Parallelism),
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };

        return (keyParams, contentKey);
    }

    /// <summary>
    /// Re-derives the content key from a passphrase and a parsed header's KeyParams.
    /// <paramref name="limits"/> caps the KDF cost an untrusted header may demand; parameters
    /// above a limit are rejected with <see cref="PqFormatException"/> before any derivation work.
    /// </summary>
    public static async Task<byte[]> DerivePassphraseKeyAsync(
        ReadOnlyMemory<byte> passphrase, ContainerHeader header, PqDecryptionLimits limits)
    {
        var p = header.KeyParams.AsSpan();
        if (p.Length < 2)
        {
            throw new PqFormatException("Passphrase key parameters are too short.");
        }

        byte kdfId = p[0];
        int saltLength = p[1];
        int offset = 2;
        if (saltLength < PqEncryptionOptions.MinSaltSizeBytes || p.Length < offset + saltLength)
        {
            throw new PqFormatException("Container declares an invalid salt.");
        }
        byte[] salt = p.Slice(offset, saltLength).ToArray();
        offset += saltLength;

        switch (kdfId)
        {
            case ContainerFormat.KdfPbkdf2HmacSha256:
            {
                if (p.Length < offset + 4)
                {
                    throw new PqFormatException("PBKDF2 key parameters are truncated.");
                }
                long iterations = BinaryPrimitives.ReadUInt32BigEndian(p[offset..]);
                if (iterations < PqEncryptionOptions.MinPbkdf2Iterations || iterations > PqEncryptionOptions.MaxPbkdf2Iterations)
                {
                    throw new PqFormatException($"Container declares an out-of-range PBKDF2 iteration count of {iterations}.");
                }
                if (iterations > limits.MaxPbkdf2Iterations)
                {
                    throw new PqFormatException(
                        $"Container demands {iterations} PBKDF2 iterations, above this decryptor's configured limit of {limits.MaxPbkdf2Iterations} (see PqDecryptionLimits).");
                }
                return DerivePbkdf2(passphrase.Span, salt, (int)iterations);
            }
            case ContainerFormat.KdfArgon2id:
            {
                if (p.Length < offset + 9)
                {
                    throw new PqFormatException("Argon2id key parameters are truncated.");
                }
                long memoryKiB = BinaryPrimitives.ReadUInt32BigEndian(p[offset..]);
                long iterations = BinaryPrimitives.ReadUInt32BigEndian(p[(offset + 4)..]);
                int parallelism = p[offset + 8];
                // Upper bounds matter here: these come from the (untrusted) container and bound
                // how much memory/CPU decryption will spend, so a hostile file fails closed.
                if (memoryKiB < PqEncryptionOptions.MinArgon2MemoryKiB || memoryKiB > PqEncryptionOptions.MaxArgon2MemoryKiB ||
                    iterations < PqEncryptionOptions.MinArgon2Iterations || iterations > PqEncryptionOptions.MaxArgon2Iterations ||
                    parallelism < 1)
                {
                    throw new PqFormatException("Container declares out-of-range Argon2id parameters.");
                }
                if (memoryKiB > limits.MaxArgon2MemoryKiB || iterations > limits.MaxArgon2Iterations)
                {
                    throw new PqFormatException(
                        $"Container demands Argon2id with {memoryKiB} KiB memory and {iterations} iterations, above this decryptor's configured limits of {limits.MaxArgon2MemoryKiB} KiB / {limits.MaxArgon2Iterations} (see PqDecryptionLimits).");
                }
                return await DeriveArgon2idAsync(passphrase, salt, (int)memoryKiB, (int)iterations, parallelism).ConfigureAwait(false);
            }
            default:
                throw new PqFormatException($"Unsupported KDF identifier {kdfId}.");
        }
    }

    private static byte[] DerivePbkdf2(ReadOnlySpan<byte> passphrase, byte[] salt, int iterations) =>
        Rfc2898DeriveBytes.Pbkdf2(passphrase, salt, iterations, HashAlgorithmName.SHA256, ContainerFormat.KeyLength);

    private static async Task<byte[]> DeriveArgon2idAsync(
        ReadOnlyMemory<byte> passphrase, byte[] salt, int memoryKiB, int iterations, int parallelism)
    {
        // Konscious takes the password as a byte[]; copy so we can zero our temporary afterwards.
        byte[] password = passphrase.ToArray();
        try
        {
            using var argon = new Argon2id(password)
            {
                Salt = salt,
                MemorySize = memoryKiB,
                Iterations = iterations,
                DegreeOfParallelism = parallelism,
            };
            return await argon.GetBytesAsync(ContainerFormat.KeyLength).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private static byte[] SerializePbkdf2Params(byte[] salt, int iterations)
    {
        var buffer = new byte[2 + salt.Length + 4];
        buffer[0] = ContainerFormat.KdfPbkdf2HmacSha256;
        buffer[1] = (byte)salt.Length;
        salt.CopyTo(buffer, 2);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(2 + salt.Length), (uint)iterations);
        return buffer;
    }

    private static byte[] SerializeArgon2idParams(byte[] salt, int memoryKiB, int iterations, int parallelism)
    {
        var buffer = new byte[2 + salt.Length + 9];
        buffer[0] = ContainerFormat.KdfArgon2id;
        buffer[1] = (byte)salt.Length;
        salt.CopyTo(buffer, 2);
        int offset = 2 + salt.Length;
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset), (uint)memoryKiB);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(offset + 4), (uint)iterations);
        buffer[offset + 8] = (byte)parallelism;
        return buffer;
    }

    // ---------------------------------------------------------------- ML-KEM recipient

    /// <summary>
    /// Generates a random content key and wraps it to <paramref name="recipient"/> using
    /// ML-KEM-768 (encapsulate → HKDF → AES-256-GCM key wrap), returning the KeyParams to embed.
    /// </summary>
    public static (byte[] keyParams, byte[] contentKey) BuildRecipient(PqRecipientPublicKey recipient)
    {
        EnsureMlKemSupported();

        byte[] contentKey = RandomNumberGenerator.GetBytes(ContainerFormat.KeyLength);
        using MLKem encapsulationKey = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, recipient.KeyBytes);
        encapsulationKey.Encapsulate(out byte[] kemCiphertext, out byte[] sharedSecret);
        try
        {
            byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, ContainerFormat.KeyLength, salt: null, info: KekInfo);
            try
            {
                byte[] wrapNonce = RandomNumberGenerator.GetBytes(ContainerFormat.NonceLength);
                byte[] wrappedKey = new byte[ContainerFormat.KeyLength];
                byte[] wrapTag = new byte[ContainerFormat.TagLength];
                using (var gcm = new AesGcm(kek, ContainerFormat.TagLength))
                {
                    gcm.Encrypt(wrapNonce, contentKey, wrappedKey, wrapTag, WrapAad);
                }

                byte[] keyParams = SerializeRecipientParams(kemCiphertext, wrapNonce, wrapTag, wrappedKey);
                return (keyParams, contentKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    /// <summary>Recovers the content key from a recipient container using the private key.</summary>
    public static byte[] UnwrapRecipientKey(ContainerHeader header, PqRecipientPrivateKey privateKey)
    {
        EnsureMlKemSupported();

        var p = header.KeyParams.AsSpan();
        // Layout: KemId(1) | C(2) | KemCiphertext(C) | WrapNonce(12) | WrapTag(16) | WrappedKey(32)
        if (p.Length < 3 || p[0] != ContainerFormat.KemMlKem768)
        {
            throw new PqFormatException("Unsupported or malformed recipient key parameters.");
        }

        int c = BinaryPrimitives.ReadUInt16BigEndian(p[1..]);
        int expected = 3 + c + ContainerFormat.NonceLength + ContainerFormat.TagLength + ContainerFormat.KeyLength;
        if (c != KemSizes.MlKem768Ciphertext || p.Length != expected)
        {
            throw new PqFormatException("Recipient key parameters have an invalid length.");
        }

        int offset = 3;
        byte[] kemCiphertext = p.Slice(offset, c).ToArray();
        offset += c;
        byte[] wrapNonce = p.Slice(offset, ContainerFormat.NonceLength).ToArray();
        offset += ContainerFormat.NonceLength;
        byte[] wrapTag = p.Slice(offset, ContainerFormat.TagLength).ToArray();
        offset += ContainerFormat.TagLength;
        byte[] wrappedKey = p.Slice(offset, ContainerFormat.KeyLength).ToArray();

        using MLKem decapsulationKey = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, privateKey.DecapsulationKey);
        byte[] sharedSecret = decapsulationKey.Decapsulate(kemCiphertext);
        try
        {
            byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, ContainerFormat.KeyLength, salt: null, info: KekInfo);
            try
            {
                byte[] contentKey = new byte[ContainerFormat.KeyLength];
                using var gcm = new AesGcm(kek, ContainerFormat.TagLength);
                gcm.Decrypt(wrapNonce, wrappedKey, wrapTag, contentKey, WrapAad);
                return contentKey;
            }
            catch (AuthenticationTagMismatchException ex)
            {
                throw new PqDecryptionException(
                    "Decryption failed: the recipient key is wrong, or the container has been altered.", ex);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(kek);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedSecret);
        }
    }

    private static byte[] SerializeRecipientParams(byte[] kemCiphertext, byte[] wrapNonce, byte[] wrapTag, byte[] wrappedKey)
    {
        var buffer = new byte[3 + kemCiphertext.Length + wrapNonce.Length + wrapTag.Length + wrappedKey.Length];
        buffer[0] = ContainerFormat.KemMlKem768;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(1), (ushort)kemCiphertext.Length);
        int offset = 3;
        kemCiphertext.CopyTo(buffer, offset); offset += kemCiphertext.Length;
        wrapNonce.CopyTo(buffer, offset); offset += wrapNonce.Length;
        wrapTag.CopyTo(buffer, offset); offset += wrapTag.Length;
        wrappedKey.CopyTo(buffer, offset);
        return buffer;
    }

    private static void EnsureMlKemSupported()
    {
        if (!MLKem.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "ML-KEM is not available on this platform. Recipient (public-key) encryption requires .NET 10 with platform PQC support (OpenSSL 3.5+ or Windows CNG).");
        }
    }
}
