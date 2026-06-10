namespace PostQuantum.FileEncryption;

/// <summary>
/// A progress snapshot reported during encryption or decryption. Reported through an
/// <see cref="IProgress{T}"/> that you pass to the operation; if you pass none, no
/// progress objects are allocated.
/// </summary>
/// <param name="BytesProcessed">Plaintext bytes processed so far.</param>
/// <param name="TotalBytes">
/// Total plaintext bytes expected, or <see langword="null"/> when the total is unknown
/// (for example, a non-seekable stream without an explicit length). During decryption this
/// is derived exactly from the container length, so <see cref="Fraction"/> reaches 1.0 on
/// completion in both directions.
/// </param>
public readonly record struct PqProgress(long BytesProcessed, long? TotalBytes)
{
    /// <summary>
    /// Completed fraction in the range 0.0–1.0, or <see langword="null"/> when
    /// <see cref="TotalBytes"/> is unknown or zero.
    /// </summary>
    public double? Fraction =>
        TotalBytes is > 0 ? Math.Clamp((double)BytesProcessed / TotalBytes.Value, 0.0, 1.0) : null;
}
