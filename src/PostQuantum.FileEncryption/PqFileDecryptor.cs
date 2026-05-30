using System.Security.Cryptography;
using System.Text;
using PostQuantum.FileEncryption.Internal;

namespace PostQuantum.FileEncryption;

/// <summary>
/// Decrypts PostQuantum.FileEncryption containers back into their original bytes, using either
/// the passphrase or the recipient private key the container was created with. Instances are
/// stateless and safe to share across threads.
/// </summary>
/// <remarks>
/// Decryption is fail-closed. If the key is wrong, or the container has been altered,
/// corrupted, or truncated, a <see cref="PqDecryptionException"/> is thrown and no plaintext is
/// left at the destination — for file output, the partially written temporary file is deleted
/// before the exception propagates.
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage(
    "Performance", "CA1822:Mark members as static",
    Justification = "Kept as instance methods for symmetry with PqFileEncryptor and to carry decryptor options in a future release.")]
public sealed class PqFileDecryptor
{
    /// <summary>Creates a decryptor. Decryption parameters are read from each container's header.</summary>
    public PqFileDecryptor() { }

    // ------------------------------------------------------------------ Passphrase: file

    /// <summary>Decrypts the container at <paramref name="inputPath"/> to <paramref name="outputPath"/> with a passphrase.</summary>
    /// <exception cref="PqFormatException">The input is not a recognizable container.</exception>
    /// <exception cref="PqDecryptionException">The passphrase is wrong, or the container is altered or truncated.</exception>
    public Task DecryptFileAsync(
        string inputPath, string outputPath, string passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p =>
            DecryptFileAsync(inputPath, outputPath, p, progress, cancellationToken));
    }

    /// <summary>Decrypts the container at <paramref name="inputPath"/> to <paramref name="outputPath"/> with a passphrase supplied as bytes.</summary>
    public Task DecryptFileAsync(
        string inputPath, string outputPath, ReadOnlyMemory<byte> passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);

        return DecryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.DecryptPassphraseAsync(input, output, passphrase, total, progress, cancellationToken));
    }

    // ------------------------------------------------------------------ Passphrase: stream

    /// <summary>Decrypts the container read from <paramref name="input"/> to <paramref name="output"/> with a passphrase. Neither stream is disposed.</summary>
    public Task DecryptAsync(
        Stream input, Stream output, string passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        return WithPassphraseBytesAsync(passphrase, p =>
            DecryptAsync(input, output, p, progress, cancellationToken));
    }

    /// <summary>Decrypts the container read from <paramref name="input"/> to <paramref name="output"/> with a passphrase supplied as bytes.</summary>
    public Task DecryptAsync(
        Stream input, Stream output, ReadOnlyMemory<byte> passphrase,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        long? total = input.CanSeek ? input.Length - input.Position : null;
        return PqContainer.DecryptPassphraseAsync(input, output, passphrase, total, progress, cancellationToken);
    }

    // ------------------------------------------------------------------ Recipient: file & stream

    /// <summary>Decrypts a recipient-encrypted container at <paramref name="inputPath"/> to <paramref name="outputPath"/> using a private key.</summary>
    /// <exception cref="PlatformNotSupportedException">The platform does not provide ML-KEM.</exception>
    public Task DecryptFileAsync(
        string inputPath, string outputPath, PqRecipientPrivateKey privateKey,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath);
        ArgumentException.ThrowIfNullOrEmpty(outputPath);
        ArgumentNullException.ThrowIfNull(privateKey);

        return DecryptFileCoreAsync(inputPath, outputPath, (input, output, total) =>
            PqContainer.DecryptRecipientAsync(input, output, privateKey, total, progress, cancellationToken));
    }

    /// <summary>Decrypts a recipient-encrypted container read from <paramref name="input"/> to <paramref name="output"/> using a private key.</summary>
    /// <exception cref="PlatformNotSupportedException">The platform does not provide ML-KEM.</exception>
    public Task DecryptAsync(
        Stream input, Stream output, PqRecipientPrivateKey privateKey,
        IProgress<PqProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(privateKey);
        long? total = input.CanSeek ? input.Length - input.Position : null;
        return PqContainer.DecryptRecipientAsync(input, output, privateKey, total, progress, cancellationToken);
    }

    // ------------------------------------------------------------------ In-memory convenience

    /// <summary>
    /// Decrypts an in-memory container with a passphrase and returns the recovered plaintext.
    /// Fail-closed: throws <see cref="PqDecryptionException"/> rather than returning bad data.
    /// </summary>
    public async Task<byte[]> DecryptBytesAsync(
        ReadOnlyMemory<byte> container, string passphrase, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(passphrase);
        byte[] passphraseBytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            return await DecryptBytesAsync(container, passphraseBytes, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphraseBytes);
        }
    }

    /// <summary>Decrypts an in-memory container with a passphrase supplied as bytes.</summary>
    public async Task<byte[]> DecryptBytesAsync(
        ReadOnlyMemory<byte> container, ReadOnlyMemory<byte> passphrase, CancellationToken cancellationToken = default)
    {
        using var input = new MemoryStream(container.ToArray(), writable: false);
        using var output = new MemoryStream(container.Length);
        await PqContainer.DecryptPassphraseAsync(
            input, output, passphrase, container.Length, null, cancellationToken).ConfigureAwait(false);
        return output.ToArray();
    }

    // ------------------------------------------------------------------ helpers

    private static async Task DecryptFileCoreAsync(
        string inputPath, string outputPath, Func<FileStream, FileStream, long?, Task> decrypt)
    {
        await using var input = FileIo.OpenRead(inputPath);
        long? total = input.CanSeek ? input.Length : null;
        await FileIo.WriteViaTempAsync(outputPath, output => decrypt(input, output, total)).ConfigureAwait(false);
    }

    private static async Task WithPassphraseBytesAsync(string passphrase, Func<ReadOnlyMemory<byte>, Task> body)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(passphrase);
        try
        {
            await body(bytes).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }
}
