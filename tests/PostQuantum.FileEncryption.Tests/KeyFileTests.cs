using PostQuantum.FileEncryption.Hybrid;
using PostQuantum.FileEncryption.Signing;
using Xunit;
using static PostQuantum.FileEncryption.Tests.TestSupport;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// The PQKF v1 passphrase-encrypted key-file format (docs/KEY-FILE-FORMAT.md): round trips,
/// the fail-closed contract inherited from the container engine, and the authenticated
/// key-type binding that stops one kind of key from being imported as another.
/// </summary>
public sealed class KeyFileTests
{
    private const string Passphrase = "a key-file passphrase";

    // Fast KDF options for the suite; the production default is the Argon2id preset,
    // pinned separately below.
    private static PqEncryptionOptions FastKdf => Fast();

    [Fact]
    public void Hybrid_private_key_round_trips_through_an_encrypted_key_file()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf);

        using var restored = PqHybridPrivateKey.ImportEncrypted(keyFile, Passphrase);
        Assert.Equal(keyPair.PrivateKey.Export(), restored.Export());
    }

    [Fact]
    public void Signing_private_key_round_trips_through_an_encrypted_key_file()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf);

        using var restored = PqSigningPrivateKey.ImportEncrypted(keyFile, Passphrase);
        Assert.Equal(keyPair.PrivateKey.Export(), restored.Export());

        // The restored key actually signs, and the original public key verifies it.
        byte[] data = RandomBytes(500);
        byte[] signature = new PqSigner().SignBytes(data, restored);
        new PqVerifier().VerifyBytes(data, signature, keyPair.PublicKey);
    }

    [Fact]
    public void Default_key_file_kdf_is_argon2id_and_import_limits_gate_it()
    {
        // Key files are long-lived secrets; the memory-hard default is part of the contract
        // (KEY-FILE-FORMAT.md writer rule 3). Proof without header spelunking: an import
        // ceiling below the 19 MiB Argon2id preset must reject the file before any KDF work
        // (a PBKDF2 container would sail past that limit) — this doubles as the gate against
        // a hostile key file demanding gibibytes of KDF memory pre-authentication.
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase);

        var belowPreset = new PqDecryptionLimits { MaxArgon2MemoryKiB = 8 * 1024 };
        Assert.Throws<PqFormatException>(() =>
            PqSigningPrivateKey.ImportEncrypted(keyFile, Passphrase, belowPreset));

        // The permissive default still opens every legal key file.
        using var restored = PqSigningPrivateKey.ImportEncrypted(keyFile, Passphrase);
        Assert.Equal(keyPair.PrivateKey.Export(), restored.Export());
    }

    [Fact]
    public void IsEncryptedKeyFile_distinguishes_the_two_export_forms()
    {
        using var hybrid = PqHybridKeyPair.Generate();
        byte[] encrypted = hybrid.PrivateKey.ExportEncrypted(Passphrase, FastKdf);
        byte[] raw = hybrid.PrivateKey.Export();

        Assert.True(PqHybridPrivateKey.IsEncryptedKeyFile(encrypted));
        Assert.True(PqSigningPrivateKey.IsEncryptedKeyFile(encrypted)); // format check, not type check
        Assert.False(PqHybridPrivateKey.IsEncryptedKeyFile(raw));
        Assert.False(PqHybridPrivateKey.IsEncryptedKeyFile([]));
        Assert.False(PqHybridPrivateKey.IsEncryptedKeyFile("PQKF"u8));           // magic only, too short
        Assert.False(PqHybridPrivateKey.IsEncryptedKeyFile([.. "PQKF"u8, 0xFF, 0x00])); // unknown version

        // The minimal recognizable framing: magic + known version + one body byte. Not a
        // decryptable key file, but detection is a framing check, not a validity check.
        Assert.True(PqHybridPrivateKey.IsEncryptedKeyFile([.. "PQKF"u8, 0x01, 0x00]));
    }

    [Fact]
    public void Wrong_passphrase_fails_closed()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf);

        Assert.Throws<PqDecryptionException>(() =>
            PqHybridPrivateKey.ImportEncrypted(keyFile, "not the passphrase"));
    }

    [Fact]
    public void Tampered_key_file_fails_closed()
    {
        using var keyPair = PqSigningKeyPair.Generate();
        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf);

        keyFile[^1] ^= 0x01;
        Assert.Throws<PqDecryptionException>(() =>
            PqSigningPrivateKey.ImportEncrypted(keyFile, Passphrase));
    }

    [Fact]
    public void A_key_file_of_the_wrong_kind_is_rejected_even_with_the_right_passphrase()
    {
        // The type byte is inside the authenticated plaintext, so a signing key file can
        // never import as a hybrid recipient key (or vice versa) — a structural error,
        // not an authentication failure.
        using var signing = PqSigningKeyPair.Generate();
        byte[] signingFile = signing.PrivateKey.ExportEncrypted(Passphrase, FastKdf);
        Assert.Throws<PqFormatException>(() =>
            PqHybridPrivateKey.ImportEncrypted(signingFile, Passphrase));

        using var hybrid = PqHybridKeyPair.Generate();
        byte[] hybridFile = hybrid.PrivateKey.ExportEncrypted(Passphrase, FastKdf);
        Assert.Throws<PqFormatException>(() =>
            PqSigningPrivateKey.ImportEncrypted(hybridFile, Passphrase));
    }

    [Fact]
    public void A_key_file_with_the_right_length_but_wrong_type_byte_is_rejected()
    {
        // The wrong-kind test above changes both length and type; this one isolates the type
        // byte (same length, unknown type), so a flipped conjunction in the check can't hide.
        byte[] bogusTyped = Internal.PqKeyFileFormat.Encrypt(
            keyType: 99, keyBytes: new byte[2432], Passphrase, FastKdf);

        Assert.Throws<PqFormatException>(() =>
            PqHybridPrivateKey.ImportEncrypted(bogusTyped, Passphrase));
    }

    [Fact]
    public void Caller_supplied_kdf_options_are_honored_not_silently_replaced()
    {
        // Export with fast PBKDF2 options, then import under an Argon2id ceiling far below the
        // Argon2id default: if the options were ignored (default Argon2id 19 MiB), this import
        // would be rejected; a PBKDF2 key file sails past the Argon2id limit.
        using var keyPair = PqHybridKeyPair.Generate();
        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf);

        var tightArgonLimits = new PqDecryptionLimits { MaxArgon2MemoryKiB = 8 * 1024 };
        using var restored = PqHybridPrivateKey.ImportEncrypted(keyFile, Passphrase, tightArgonLimits);

        Assert.Equal(keyPair.PrivateKey.Export(), restored.Export());
    }

    [Fact]
    public void Garbage_and_truncated_inputs_are_format_errors()
    {
        Assert.Throws<PqFormatException>(() =>
            PqHybridPrivateKey.ImportEncrypted(RandomBytes(200), Passphrase));
        Assert.Throws<PqFormatException>(() =>
            PqHybridPrivateKey.ImportEncrypted([], Passphrase));
        Assert.Throws<PqFormatException>(() =>
            PqHybridPrivateKey.ImportEncrypted("PQKF"u8.ToArray(), Passphrase));

        // Right magic, unknown version.
        byte[] wrongVersion = [.. "PQKF"u8, 0xFF, 0x00];
        Assert.Throws<PqFormatException>(() =>
            PqHybridPrivateKey.ImportEncrypted(wrongVersion, Passphrase));
    }

    [Fact]
    public void Empty_passphrases_are_rejected()
    {
        using var keyPair = PqHybridKeyPair.Generate();
        Assert.Throws<ArgumentException>(() =>
            keyPair.PrivateKey.ExportEncrypted(ReadOnlySpan<char>.Empty, FastKdf));

        byte[] keyFile = keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf);
        Assert.Throws<ArgumentException>(() =>
            PqHybridPrivateKey.ImportEncrypted(keyFile, ReadOnlySpan<char>.Empty));
    }

    [Fact]
    public void Disposed_key_cannot_be_exported()
    {
        var keyPair = PqHybridKeyPair.Generate();
        keyPair.Dispose();
        Assert.Throws<ObjectDisposedException>(() => keyPair.PrivateKey.ExportEncrypted(Passphrase, FastKdf));
    }
}
