namespace PostQuantum.FileEncryption.Internal;

/// <summary>
/// Shared file-I/O helpers. The write path goes through a sibling temporary file that is
/// atomically moved into place only on full success, so a crash or thrown exception never
/// leaves a partial or unverified file at the destination.
/// </summary>
internal static class FileIo
{
    // A buffer large enough to keep large-file I/O efficient (one syscall per chunk-sized read),
    // while staying small relative to the bounded streaming memory the engine already uses.
    private const int FileBufferSize = 64 * 1024;

    public static FileStream OpenRead(string path) =>
        new(path, FileMode.Open, FileAccess.Read, FileShare.Read, FileBufferSize, useAsync: true);

    /// <summary>
    /// Runs <paramref name="writeBody"/> against a temporary file, then atomically moves it to
    /// <paramref name="outputPath"/>. Deletes the temporary file if anything fails.
    /// </summary>
    public static async Task WriteViaTempAsync(string outputPath, Func<FileStream, Task> writeBody)
    {
        string tempPath = outputPath + ".tmp-" + Guid.NewGuid().ToString("N");
        try
        {
            await using (var output = new FileStream(
                tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                FileBufferSize, useAsync: true))
            {
                await writeBody(output).ConfigureAwait(false);
                // Force the bytes to stable storage before the rename can become visible: some
                // filesystems persist a rename ahead of the renamed file's data on power loss,
                // which would leave a truncated file at the destination. The device sync can
                // take a long time on slow media and has no async form, so it runs off-thread
                // to keep the async contract.
                await Task.Run(() => output.Flush(flushToDisk: true)).ConfigureAwait(false);
            }

            File.Move(tempPath, outputPath, overwrite: true);
        }
        catch
        {
            TryDelete(tempPath);
            throw;
        }
    }

    /// <summary>
    /// Reads <paramref name="inputPath"/> through <paramref name="body"/> into a temporary
    /// file that is atomically moved to <paramref name="outputPath"/> on success. This helper
    /// owns two ordering invariants every file-transforming API needs: the input is opened
    /// <em>before</em> the temporary file exists, so a missing or unreadable input fails with
    /// no filesystem side effect at the destination; and it is closed <em>before</em> the
    /// atomic move, so transforming a file onto its own path works on Windows (an open input
    /// handle makes the final rename fail with a sharing violation).
    /// </summary>
    /// <param name="inputPath">The file to read.</param>
    /// <param name="outputPath">The destination, replaced atomically on success.</param>
    /// <param name="body">
    /// Receives the input stream, the temporary output stream, and the input length when
    /// seekable (for progress totals). The input stream is disposed by this helper as soon as
    /// the body returns — do not use it afterwards.
    /// </param>
    public static async Task TransformViaTempAsync(
        string inputPath, string outputPath, Func<FileStream, FileStream, long?, Task> body)
    {
        var input = OpenRead(inputPath);
        try
        {
            long? total = input.CanSeek ? input.Length : null;
            await WriteViaTempAsync(outputPath, async output =>
            {
                try
                {
                    await body(input, output, total).ConfigureAwait(false);
                }
                finally
                {
                    await input.DisposeAsync().ConfigureAwait(false);
                }
            }).ConfigureAwait(false);
        }
        finally
        {
            // Idempotent safety net for the paths where the write body never ran
            // (e.g. the temporary file could not be created).
            await input.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best-effort cleanup; the original exception is the one worth surfacing.
        }
    }
}
