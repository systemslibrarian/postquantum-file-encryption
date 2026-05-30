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
            }

            File.Move(tempPath, outputPath, overwrite: true);
        }
        catch
        {
            TryDelete(tempPath);
            throw;
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
