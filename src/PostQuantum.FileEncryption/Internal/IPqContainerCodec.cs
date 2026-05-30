namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// The low-level read/write seam for the container body. Today there is exactly one
/// implementation, <see cref="SelfContainedContainerCodec"/>, which uses the in-repo
/// <see cref="PqContainerEngine"/>.
/// </summary>
/// <remarks>
/// This interface exists so that, once the lower-level <c>PostQuantum.FileFormat</c> package
/// is published, an alternative codec backed by it can be dropped in here — behind the same
/// public <see cref="PqFileEncryptor"/> / <see cref="PqFileDecryptor"/> API — without touching
/// key establishment or the public surface. That delegation is intentionally NOT wired up yet
/// (the package does not exist); see <c>KNOWN-GAPS.md</c>.
/// </remarks>
internal interface IPqContainerCodec
{
    /// <summary>Writes the header and all chunk frames; zeroes <paramref name="contentKey"/> when done.</summary>
    Task WriteAsync(
        Stream source, Stream destination, byte[] contentKey, ContainerHeader header,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken);

    /// <summary>Reads and verifies all chunk frames; zeroes <paramref name="contentKey"/> when done.</summary>
    Task ReadBodyAsync(
        Stream source, Stream destination, byte[] contentKey, ContainerHeader header,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken);

    /// <summary>Reads and validates just the container header.</summary>
    Task<ContainerHeader> ReadHeaderAsync(Stream source, CancellationToken cancellationToken);
}

/// <summary>The default codec: the self-contained <see cref="PqContainerEngine"/>.</summary>
internal sealed class SelfContainedContainerCodec : IPqContainerCodec
{
    public static readonly SelfContainedContainerCodec Instance = new();

    private SelfContainedContainerCodec() { }

    public Task WriteAsync(
        Stream source, Stream destination, byte[] contentKey, ContainerHeader header,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken) =>
        PqContainerEngine.EncryptCoreAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken);

    public Task ReadBodyAsync(
        Stream source, Stream destination, byte[] contentKey, ContainerHeader header,
        long? totalBytes, IProgress<PqProgress>? progress, CancellationToken cancellationToken) =>
        PqContainerEngine.DecryptCoreAsync(source, destination, contentKey, header, totalBytes, progress, cancellationToken);

    public Task<ContainerHeader> ReadHeaderAsync(Stream source, CancellationToken cancellationToken) =>
        PqContainerEngine.ReadHeaderAsync(source, cancellationToken);
}
