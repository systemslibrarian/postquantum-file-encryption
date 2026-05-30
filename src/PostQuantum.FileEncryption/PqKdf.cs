namespace PostQuantum.FileEncryption;

/// <summary>
/// The password-based key-derivation function used to turn a passphrase into a content key.
/// </summary>
public enum PqKdf
{
    /// <summary>
    /// PBKDF2-HMAC-SHA256. Built into .NET, no extra dependency. The default. Strong when
    /// given a high iteration count, but not memory-hard.
    /// </summary>
    Pbkdf2HmacSha256 = 1,

    /// <summary>
    /// Argon2id — a memory-hard KDF that resists GPU/ASIC cracking far better than PBKDF2.
    /// Provided by the Konscious.Security.Cryptography dependency. Prefer this for
    /// human-chosen passphrases when you can afford the memory cost.
    /// </summary>
    Argon2id = 2,
}
