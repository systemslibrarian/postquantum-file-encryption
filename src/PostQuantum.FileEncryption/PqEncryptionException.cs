namespace PostQuantum.FileEncryption;

/// <summary>
/// Base type for every error raised by PostQuantum.FileEncryption. Catch this to handle
/// all library failures uniformly; catch a derived type for finer-grained handling.
/// </summary>
public class PqEncryptionException : Exception
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqEncryptionException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    public PqEncryptionException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when the input is not a recognizable PostQuantum.FileEncryption container:
/// wrong magic bytes, an unsupported format version, or a structurally invalid header.
/// </summary>
public sealed class PqFormatException : PqEncryptionException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqFormatException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    public PqFormatException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// Thrown when authenticated decryption fails: a wrong passphrase, tampered or corrupted
/// ciphertext, or a truncated container. This is the library's fail-closed signal — no
/// plaintext is ever released to the caller's destination when this is thrown.
/// </summary>
/// <remarks>
/// The message is intentionally generic. Distinguishing "wrong passphrase" from "tampered
/// data" would leak an oracle to an attacker, so the library treats every authentication
/// failure identically.
/// </remarks>
public sealed class PqDecryptionException : PqEncryptionException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqDecryptionException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    public PqDecryptionException(string message, Exception innerException)
        : base(message, innerException) { }
}
