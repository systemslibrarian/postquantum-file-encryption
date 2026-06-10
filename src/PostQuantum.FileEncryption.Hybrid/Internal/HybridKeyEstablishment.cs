using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption.Hybrid.Internal;

/// <summary>
/// The X25519 + ML-KEM-768 hybrid KEM-DEM. A random content key (CEK) is wrapped to one or more
/// recipients: ML-KEM-768 and X25519 each contribute a shared secret, HKDF combines them into a
/// key-wrapping key, and AES-256-GCM wraps the CEK. The content key — and therefore the file —
/// stays protected if <em>either</em> primitive is later broken.
/// </summary>
/// <remarks>No novel cryptography: standard KEM-DEM composition. ML-KEM and X25519 come from
/// BouncyCastle; HKDF and AES-256-GCM from .NET.</remarks>
internal static class HybridKeyEstablishment
{
    private const byte KemMlKem768 = 1;
    private const byte ModeHybrid = 3;
    private const int KemCiphertextLength = 1088;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int CekLength = 32;

    private static readonly byte[] KekInfo = "PostQuantum.FileEncryption/v3 hybrid kek"u8.ToArray();
    private static readonly byte[] WrapAad = "PostQuantum.FileEncryption/v3 cek-wrap"u8.ToArray();

    /// <summary>One serialized KeySource-3 block: KemId(1) + C(2) + KemCt + EphX25519 + Nonce + Tag + WrappedKey.</summary>
    private const int BlockLength = 3 + KemCiphertextLength + HybridSizes.X25519Key + NonceLength + TagLength + CekLength;

    /// <summary>
    /// The most recipients a KeySource-4 body can hold. Each entry is Mode(1) + BlockLength(2) +
    /// block after a 1-byte count, and the whole body must fit the container header's uint16
    /// KeyParams length — 55 with today's fixed block size.
    /// </summary>
    public const int MaxRecipients = (ContainerFormat.MaxKeyParamsLength - 1) / (3 + BlockLength);

    // ---- single recipient (KeySource = 3) ----

    /// <summary>Wraps <paramref name="cek"/> to one recipient and returns the KeySource-3 body.</summary>
    public static byte[] WrapToRecipient(PqHybridPublicKey recipient, byte[] cek)
    {
        var random = new SecureRandom();

        var encapsulator = new MLKemEncapsulator(MLKemParameters.ml_kem_768);
        encapsulator.Init(MLKemPublicKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, recipient.MlKemEncapsulationKey));
        byte[] kemCiphertext = new byte[encapsulator.EncapsulationLength];
        byte[] sharedSecretPq = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(kemCiphertext, sharedSecretPq);

        try
        {
            var ephemeralGen = new X25519KeyPairGenerator();
            ephemeralGen.Init(new X25519KeyGenerationParameters(random));
            var ephemeral = ephemeralGen.GenerateKeyPair();
            byte[] ephemeralPublic = ((X25519PublicKeyParameters)ephemeral.Public).GetEncoded();

            var agreement = new X25519Agreement();
            agreement.Init(ephemeral.Private);
            byte[] sharedSecretClassical = new byte[agreement.AgreementSize];
            agreement.CalculateAgreement(new X25519PublicKeyParameters(recipient.X25519PublicKey.ToArray()), sharedSecretClassical);

            try
            {
                byte[] kek = DeriveKek(sharedSecretPq, sharedSecretClassical);
                try
                {
                    byte[] wrapNonce = RandomNumberGenerator.GetBytes(NonceLength);
                    byte[] wrappedKey = new byte[CekLength];
                    byte[] wrapTag = new byte[TagLength];
                    using (var gcm = new AesGcm(kek, TagLength))
                    {
                        gcm.Encrypt(wrapNonce, cek, wrappedKey, wrapTag, WrapAad);
                    }
                    return SerializeBlock(kemCiphertext, ephemeralPublic, wrapNonce, wrapTag, wrappedKey);
                }
                finally { CryptographicOperations.ZeroMemory(kek); }
            }
            finally { CryptographicOperations.ZeroMemory(sharedSecretClassical); }
        }
        finally { CryptographicOperations.ZeroMemory(sharedSecretPq); }
    }

    /// <summary>Recovers the CEK from a KeySource-3 body. Throws if it is not ours or is corrupt.</summary>
    public static byte[] UnwrapFromRecipient(ReadOnlySpan<byte> body, PqHybridPrivateKey key)
        => TryUnwrapBlock(body, key)
           ?? throw new PqDecryptionException(
               "Decryption failed — this file is not encrypted to this key, or it has been altered.");

    // ---- multiple recipients (KeySource = 4) ----

    /// <summary>Wraps <paramref name="cek"/> to every recipient and returns the KeySource-4 body.</summary>
    public static byte[] WrapToRecipients(IReadOnlyList<PqHybridPublicKey> recipients, byte[] cek)
    {
        using var stream = new MemoryStream();
        stream.WriteByte((byte)recipients.Count);
        foreach (var recipient in recipients)
        {
            byte[] block = WrapToRecipient(recipient, cek);
            stream.WriteByte(ModeHybrid);
            stream.WriteByte((byte)(block.Length >> 8));   // BlockLength, big-endian u16
            stream.WriteByte((byte)(block.Length & 0xFF));
            stream.Write(block);
        }
        return stream.ToArray();
    }

    /// <summary>Tries each recipient block until one unwraps with <paramref name="key"/>; fails closed.</summary>
    public static byte[] UnwrapFromRecipients(ReadOnlySpan<byte> body, PqHybridPrivateKey key)
    {
        if (body.Length < 1)
        {
            throw new PqFormatException("Multi-recipient key parameters are empty.");
        }

        int count = body[0];
        if (count < 1)
        {
            throw new PqFormatException("Multi-recipient container declares zero recipients.");
        }

        int offset = 1;
        for (int i = 0; i < count; i++)
        {
            if (offset + 3 > body.Length)
            {
                throw new PqFormatException("Multi-recipient key parameters are truncated.");
            }
            byte mode = body[offset];
            int blockLength = BinaryPrimitives.ReadUInt16BigEndian(body[(offset + 1)..]);
            offset += 3;
            if (offset + blockLength > body.Length)
            {
                throw new PqFormatException("Multi-recipient block is truncated.");
            }

            ReadOnlySpan<byte> block = body.Slice(offset, blockLength);
            offset += blockLength;

            if (mode == ModeHybrid)
            {
                byte[]? cek = TryUnwrapBlock(block, key);
                if (cek is not null)
                {
                    return cek;
                }
            }
            // Unknown mode or not-ours block: keep trying the rest.
        }

        throw new PqDecryptionException(
            "Decryption failed — none of the recipients in this file match this key, or it has been altered.");
    }

    // ---- shared ----

    /// <summary>Returns the CEK if <paramref name="block"/> unwraps with <paramref name="key"/>, else null.</summary>
    private static byte[]? TryUnwrapBlock(ReadOnlySpan<byte> block, PqHybridPrivateKey key)
    {
        // Layout: KemId(1) | C(2) | KemCt(C) | EphX25519(32) | WrapNonce(12) | WrapTag(16) | WrappedKey(32)
        if (block.Length < 3 || block[0] != KemMlKem768)
        {
            throw new PqFormatException("Unsupported or malformed hybrid key parameters.");
        }
        int c = BinaryPrimitives.ReadUInt16BigEndian(block[1..]);
        int expected = 3 + c + HybridSizes.X25519Key + NonceLength + TagLength + CekLength;
        if (c != KemCiphertextLength || block.Length != expected)
        {
            throw new PqFormatException("Hybrid key parameters have an invalid length.");
        }

        int offset = 3;
        byte[] kemCiphertext = block.Slice(offset, c).ToArray(); offset += c;
        byte[] ephemeralPublic = block.Slice(offset, HybridSizes.X25519Key).ToArray(); offset += HybridSizes.X25519Key;
        byte[] wrapNonce = block.Slice(offset, NonceLength).ToArray(); offset += NonceLength;
        byte[] wrapTag = block.Slice(offset, TagLength).ToArray(); offset += TagLength;
        byte[] wrappedKey = block.Slice(offset, CekLength).ToArray();

        // ML-KEM decapsulation never fails (implicit rejection yields a pseudorandom secret), so a
        // block meant for someone else simply produces the wrong KEK and the AES-GCM tag mismatches.
        // BouncyCastle needs byte[] copies of the private keys; zero each copy after its last use.
        // (BouncyCastle's parameter objects keep their own internal copies we cannot zero.)
        var decapsulator = new MLKemDecapsulator(MLKemParameters.ml_kem_768);
        byte[] mlKemKeyCopy = key.MlKemDecapsulationKey.ToArray();
        byte[] sharedSecretPq;
        try
        {
            decapsulator.Init(MLKemPrivateKeyParameters.FromEncoding(MLKemParameters.ml_kem_768, mlKemKeyCopy));
            sharedSecretPq = new byte[decapsulator.SecretLength]; // SecretLength is only valid after Init
            decapsulator.Decapsulate(kemCiphertext, sharedSecretPq);
        }
        finally { CryptographicOperations.ZeroMemory(mlKemKeyCopy); }

        try
        {
            var agreement = new X25519Agreement();
            byte[] x25519KeyCopy = key.X25519PrivateKey.ToArray();
            byte[] sharedSecretClassical;
            try
            {
                agreement.Init(new X25519PrivateKeyParameters(x25519KeyCopy));
                sharedSecretClassical = new byte[agreement.AgreementSize];
                agreement.CalculateAgreement(new X25519PublicKeyParameters(ephemeralPublic), sharedSecretClassical);
            }
            finally { CryptographicOperations.ZeroMemory(x25519KeyCopy); }

            try
            {
                byte[] kek = DeriveKek(sharedSecretPq, sharedSecretClassical);
                try
                {
                    byte[] cek = new byte[CekLength];
                    using var gcm = new AesGcm(kek, TagLength);
                    gcm.Decrypt(wrapNonce, wrappedKey, wrapTag, cek, WrapAad);
                    return cek;
                }
                catch (AuthenticationTagMismatchException)
                {
                    return null; // not our block, or tampered
                }
                finally { CryptographicOperations.ZeroMemory(kek); }
            }
            finally { CryptographicOperations.ZeroMemory(sharedSecretClassical); }
        }
        finally { CryptographicOperations.ZeroMemory(sharedSecretPq); }
    }

    private static byte[] DeriveKek(byte[] sharedSecretPq, byte[] sharedSecretClassical)
    {
        // IKM = ss_pq ‖ ss_classical, in that fixed (authenticated) order.
        byte[] ikm = new byte[sharedSecretPq.Length + sharedSecretClassical.Length];
        sharedSecretPq.CopyTo(ikm, 0);
        sharedSecretClassical.CopyTo(ikm, sharedSecretPq.Length);
        try
        {
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, CekLength, salt: null, info: KekInfo);
        }
        finally { CryptographicOperations.ZeroMemory(ikm); }
    }

    private static byte[] SerializeBlock(byte[] kemCiphertext, byte[] ephemeralPublic, byte[] wrapNonce, byte[] wrapTag, byte[] wrappedKey)
    {
        var buffer = new byte[3 + kemCiphertext.Length + ephemeralPublic.Length + wrapNonce.Length + wrapTag.Length + wrappedKey.Length];
        buffer[0] = KemMlKem768;
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(1), (ushort)kemCiphertext.Length);
        int offset = 3;
        kemCiphertext.CopyTo(buffer, offset); offset += kemCiphertext.Length;
        ephemeralPublic.CopyTo(buffer, offset); offset += ephemeralPublic.Length;
        wrapNonce.CopyTo(buffer, offset); offset += wrapNonce.Length;
        wrapTag.CopyTo(buffer, offset); offset += wrapTag.Length;
        wrappedKey.CopyTo(buffer, offset);
        return buffer;
    }
}
