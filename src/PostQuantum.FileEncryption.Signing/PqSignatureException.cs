namespace PostQuantum.FileEncryption.Signing;

/// <summary>
/// Thrown when signature verification fails: the data was altered, the signature was produced
/// by a different key, or the signature bytes themselves were tampered with. This is the
/// package's fail-closed signal — verification either succeeds completely or throws.
/// </summary>
/// <remarks>
/// The message is intentionally generic. A hybrid signature verifies only when <b>both</b> the
/// Ed25519 and the ML-DSA-65 component verify; distinguishing which component failed (or why)
/// would leak an oracle, so every verification failure looks identical to the caller.
/// </remarks>
public sealed class PqSignatureException : PqEncryptionException
{
    /// <summary>Initializes a new instance with a message.</summary>
    public PqSignatureException(string message) : base(message) { }

    /// <summary>Initializes a new instance with a message and inner exception.</summary>
    public PqSignatureException(string message, Exception innerException)
        : base(message, innerException) { }
}
