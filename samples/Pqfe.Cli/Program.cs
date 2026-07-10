// pqfe — a minimal command-line frontend for PostQuantum.FileEncryption.
//
// Usage:
//   pqfe encrypt <input> <output> [--argon2id] [--passphrase-env VAR]
//   pqfe decrypt <input> <output>                [--passphrase-env VAR]
//   pqfe keygen  <keyfile>
//   pqfe sign    <input> <keyfile>     [--signature PATH]
//   pqfe verify  <input> <keyfile.pub> [--signature PATH]
//   pqfe --help | --version
//
// By default the passphrase is read from stdin (no echo on a TTY). For scripted use,
// set the environment variable named via --passphrase-env and the value is read from
// there. This sample is deliberately small; it exists to (a) make the README
// copy-paste runnable and (b) serve as the AOT smoke-test target in CI.

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Signing;

namespace Pqfe.Cli;

internal static class Program
{
    private const int ExitOk = 0;
    private const int ExitUsage = 64;
    private const int ExitDataErr = 65;
    private const int ExitNoInput = 66;
    private const int ExitCantCreate = 73; // sysexits.h EX_CANTCREAT — output exists, no --force
    private const int ExitIoErr = 74;
    private const int ExitInterrupted = 130; // shell convention for SIGINT

    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || IsHelp(args[0]))
        {
            PrintUsage();
            return args.Length == 0 ? ExitUsage : ExitOk;
        }

        if (args[0] is "--version" or "-V")
        {
            Console.WriteLine($"pqfe sample using PostQuantum.FileEncryption {LibraryVersion()}");
            return ExitOk;
        }

        // Turn Ctrl+C into cooperative cancellation instead of a hard process kill, so the
        // library's temp-file cleanup runs and no partial plaintext is left behind.
        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler onCancel = (_, e) =>
        {
            e.Cancel = true;
            // A Ctrl+C racing process exit can fire after the CTS is disposed; swallowing the
            // ObjectDisposedException here beats crashing on the very keystroke we intercepted.
            try { cts.Cancel(); }
            catch (ObjectDisposedException) { }
        };
        Console.CancelKeyPress += onCancel;

        try
        {
            string[] rest = args[1..];
            return args[0] switch
            {
                "encrypt" => await EncryptAsync(rest, cts.Token).ConfigureAwait(false),
                "decrypt" => await DecryptAsync(rest, cts.Token).ConfigureAwait(false),
                "keygen" => KeyGen(rest, cts.Token),
                "sign" => await SignAsync(rest, cts.Token).ConfigureAwait(false),
                "verify" => await VerifyAsync(rest, cts.Token).ConfigureAwait(false),
                _ => Fail($"unknown command: {args[0]}", ExitUsage),
            };
        }
        catch (OperationCanceledException)
        {
            return Fail("cancelled", ExitInterrupted);
        }
        catch (PqDecryptionException ex)
        {
            return Fail($"decryption failed: {ex.Message}", ExitDataErr);
        }
        catch (PqSignatureException ex)
        {
            return Fail(ex.Message, ExitDataErr);
        }
        catch (PqFormatException ex)
        {
            return Fail($"unrecognized input: {ex.Message}", ExitDataErr);
        }
        catch (FileNotFoundException ex)
        {
            return Fail(ex.Message, ExitNoInput);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Fail(ex.Message, ExitIoErr);
        }
        catch (CliUsageException ex)
        {
            return Fail(ex.Message, ExitUsage);
        }
        catch (ArgumentException ex)
        {
            return Fail(ex.Message, ExitUsage);
        }
        finally
        {
            Console.CancelKeyPress -= onCancel;
        }
    }

    private static async Task<int> EncryptAsync(string[] rest, CancellationToken cancellationToken)
    {
        if (!TryParsePaths(rest, out string? input, out string? output, out var flags))
            return Fail("usage: pqfe encrypt <input> <output> [--argon2id] [--passphrase-env VAR] [--force]", ExitUsage);

        if (!flags.Force && File.Exists(output))
            return Fail($"'{output}' already exists; refusing to overwrite (use --force).", ExitCantCreate);

        var options = new PqEncryptionOptions
        {
            Kdf = flags.UseArgon2id ? PqKdf.Argon2id : PqKdf.Pbkdf2HmacSha256,
        };

        byte[] passphrase = ReadPassphrase(flags.PassphraseEnv, confirm: true, cancellationToken);
        try
        {
            var encryptor = new PqFileEncryptor(options);
            var progress = new Progress<PqProgress>(ReportProgress);
            await encryptor.EncryptFileAsync(input, output, passphrase, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphrase);
        }

        Console.Error.WriteLine($"\nEncrypted {input} -> {output}");
        return ExitOk;
    }

    private static async Task<int> DecryptAsync(string[] rest, CancellationToken cancellationToken)
    {
        if (!TryParsePaths(rest, out string? input, out string? output, out var flags))
            return Fail("usage: pqfe decrypt <input> <output> [--passphrase-env VAR] [--force]", ExitUsage);

        if (!flags.Force && File.Exists(output))
            return Fail($"'{output}' already exists; refusing to overwrite (use --force).", ExitCantCreate);

        byte[] passphrase = ReadPassphrase(flags.PassphraseEnv, confirm: false, cancellationToken);
        try
        {
            var decryptor = new PqFileDecryptor();
            var progress = new Progress<PqProgress>(ReportProgress);
            await decryptor.DecryptFileAsync(input, output, passphrase, progress, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphrase);
        }

        Console.Error.WriteLine($"\nDecrypted {input} -> {output}");
        return ExitOk;
    }

    private static int KeyGen(string[] rest, CancellationToken cancellationToken)
    {
        if (!TryParseKeyGen(rest, out string? privatePath, out bool encrypt, out string? passphraseEnv))
            return Fail("usage: pqfe keygen <keyfile> [--encrypt [--passphrase-env VAR]]   (writes <keyfile> and <keyfile>.pub)", ExitUsage);

        string publicPath = privatePath + ".pub";

        using var keyPair = PqSigningKeyPair.Generate();
        byte[] privateBytes;
        if (encrypt)
        {
            // The PQKF key file wraps the key in a passphrase-encrypted .pqfe container
            // (Argon2id), so the file at rest is useless without the passphrase.
            string passphrase = ReadPassphraseString(passphraseEnv, confirm: true, cancellationToken);
            privateBytes = keyPair.PrivateKey.ExportEncrypted(passphrase);
        }
        else
        {
            privateBytes = keyPair.PrivateKey.Export();
        }
        try
        {
            // CreateNew refuses to overwrite: a signing key silently replaced is a key lost.
            WriteNewFile(privatePath, privateBytes, ownerOnly: true);
            try
            {
                WriteNewFile(publicPath, keyPair.PublicKey.Export(), ownerOnly: false);
            }
            catch
            {
                // Don't leave an orphaned private key from a half-finished pair: a rerun would
                // hit CreateNew on the private file and could end up with mismatched halves.
                TryDelete(privatePath);
                throw;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }

        Console.Error.WriteLine($"Wrote {privatePath} (private key — keep secret) and {publicPath} (public key — share).");
        return ExitOk;
    }

    private static async Task<int> SignAsync(string[] rest, CancellationToken cancellationToken)
    {
        if (!TryParseSigning(rest, out string? input, out string? keyPath, out string? signaturePath, out string? passphraseEnv))
            return Fail("usage: pqfe sign <input> <keyfile> [--signature PATH] [--passphrase-env VAR]", ExitUsage);

        byte[] keyBytes = await File.ReadAllBytesAsync(keyPath, cancellationToken).ConfigureAwait(false);
        try
        {
            PqSigningPrivateKey privateKey;
            if (PqSigningPrivateKey.IsEncryptedKeyFile(keyBytes))
            {
                // An encrypted key file from `pqfe keygen --encrypt`; wrong passphrase or
                // tampering surfaces via Main's PqDecryptionException handler (exit 65).
                string passphrase = ReadPassphraseString(passphraseEnv, confirm: false, cancellationToken);
                privateKey = PqSigningPrivateKey.ImportEncrypted(keyBytes, passphrase);
            }
            else
            {
                if (passphraseEnv is not null)
                {
                    // Failing loudly beats silently signing with an unprotected key the
                    // operator believed was passphrase-gated.
                    return Fail($"--passphrase-env was given, but '{keyPath}' is not a passphrase-protected key file.", ExitUsage);
                }
                try
                {
                    privateKey = PqSigningPrivateKey.Import(keyBytes);
                }
                catch (ArgumentException)
                {
                    return Fail($"'{keyPath}' is not a valid signing private key (expected the file written by 'pqfe keygen').", ExitDataErr);
                }
            }

            using (privateKey)
            {
                await new PqSigner().SignFileAsync(input, signaturePath, privateKey, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        Console.Error.WriteLine($"Signed {input} -> {signaturePath}");
        return ExitOk;
    }

    private static async Task<int> VerifyAsync(string[] rest, CancellationToken cancellationToken)
    {
        if (!TryParseSigning(rest, out string? input, out string? keyPath, out string? signaturePath, out string? passphraseEnv))
            return Fail("usage: pqfe verify <input> <keyfile.pub> [--signature PATH]", ExitUsage);
        if (passphraseEnv is not null)
        {
            // Verification uses the public key; accepting (and ignoring) the flag would let a
            // meaningless invocation exit 0 and cement a wrong mental model.
            return Fail("verify does not take --passphrase-env (verification uses the public key)", ExitUsage);
        }

        byte[] keyBytes = await File.ReadAllBytesAsync(keyPath, cancellationToken).ConfigureAwait(false);
        PqSigningPublicKey publicKey;
        try
        {
            publicKey = PqSigningPublicKey.Import(keyBytes);
        }
        catch (ArgumentException)
        {
            return Fail($"'{keyPath}' is not a valid signing public key (expected the .pub file written by 'pqfe keygen').", ExitDataErr);
        }

        await new PqVerifier().VerifyFileAsync(input, signaturePath, publicKey, cancellationToken).ConfigureAwait(false);

        Console.Error.WriteLine($"Signature OK: {input} verified against {signaturePath}");
        return ExitOk;
    }

    private static void WriteNewFile(string path, byte[] bytes, bool ownerOnly)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
        };
        if (ownerOnly && !OperatingSystem.IsWindows())
        {
            // Without this a private key lands with the default umask-derived mode
            // (typically 0644 — readable by every local user). 0600, like ssh-keygen.
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        using var stream = new FileStream(path, options);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Best-effort cleanup; the original failure is the one worth surfacing.
        }
    }

    private static bool TryParseSigning(
        string[] args,
        [NotNullWhen(true)] out string? input,
        [NotNullWhen(true)] out string? keyPath,
        [NotNullWhen(true)] out string? signaturePath,
        out string? passphraseEnv)
    {
        input = null;
        keyPath = null;
        signaturePath = null;
        passphraseEnv = null;

        var positionals = new List<string>(capacity: 2);
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "--signature":
                    if (i + 1 >= args.Length) return false;
                    signaturePath = args[++i];
                    break;
                case "--passphrase-env":
                    if (i + 1 >= args.Length) return false;
                    passphraseEnv = args[++i];
                    break;
                default:
                    if (a.StartsWith('-')) return false;
                    positionals.Add(a);
                    break;
            }
        }

        if (positionals.Count != 2) return false;
        input = positionals[0];
        keyPath = positionals[1];
        signaturePath ??= input + ".sig";
        return true;
    }

    private static bool TryParseKeyGen(
        string[] args,
        [NotNullWhen(true)] out string? privatePath,
        out bool encrypt,
        out string? passphraseEnv)
    {
        privatePath = null;
        encrypt = false;
        passphraseEnv = null;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--encrypt":
                    encrypt = true;
                    break;
                case "--passphrase-env":
                    if (i + 1 >= args.Length) return false;
                    passphraseEnv = args[++i];
                    break;
                default:
                    if (args[i].StartsWith('-') || privatePath is not null) return false;
                    privatePath = args[i];
                    break;
            }
        }

        // --passphrase-env only makes sense when the key file will be passphrase-protected.
        return privatePath is not null && (passphraseEnv is null || encrypt);
    }

    private static bool TryParsePaths(
        string[] args,
        [NotNullWhen(true)] out string? input,
        [NotNullWhen(true)] out string? output,
        out Flags flags)
    {
        input = null;
        output = null;
        flags = default;

        var positionals = new List<string>(capacity: 2);
        for (int i = 0; i < args.Length; i++)
        {
            string a = args[i];
            switch (a)
            {
                case "--argon2id":
                    flags = flags with { UseArgon2id = true };
                    break;
                case "--passphrase-env":
                    if (i + 1 >= args.Length) return false;
                    flags = flags with { PassphraseEnv = args[++i] };
                    break;
                case "--force":
                    flags = flags with { Force = true };
                    break;
                default:
                    if (a.StartsWith('-')) return false;
                    positionals.Add(a);
                    break;
            }
        }

        if (positionals.Count != 2) return false;
        input = positionals[0];
        output = positionals[1];
        return true;
    }

    private static byte[] ReadPassphrase(string? envVar, bool confirm, CancellationToken cancellationToken) =>
        Encoding.UTF8.GetBytes(ReadPassphraseString(envVar, confirm, cancellationToken));

    private static string ReadPassphraseString(string? envVar, bool confirm, CancellationToken cancellationToken)
    {
        // Failures here throw CliUsageException rather than calling Environment.Exit:
        // Environment.Exit would skip every enclosing finally — the callers' passphrase and
        // key-byte zeroing, keygen's orphaned-private-key cleanup, Main's CancelKeyPress
        // unhook — while the exception unwinds through all of them to Main's usage handler.
        if (!string.IsNullOrEmpty(envVar))
        {
            string? value = Environment.GetEnvironmentVariable(envVar);
            return string.IsNullOrEmpty(value)
                ? throw new CliUsageException($"environment variable '{envVar}' is empty or unset")
                : value;
        }

        string? first = ReadLineSecret("Passphrase: ", cancellationToken);
        if (first is null)
        {
            // Redirected stdin already at EOF, e.g. `pqfe encrypt in out < /dev/null`.
            throw new CliUsageException("could not read a passphrase (end of input) — use --passphrase-env for non-interactive use");
        }
        if (first.Length == 0)
        {
            // Without this check an empty line would "succeed" with an empty passphrase,
            // producing a trivially decryptable file.
            throw new CliUsageException("passphrase must not be empty");
        }
        if (confirm)
        {
            string? second = ReadLineSecret("Confirm:    ", cancellationToken);
            if (second is null)
            {
                // Single-line piped stdin: the passphrase read fine but there is no second
                // line to confirm with. "passphrases do not match" would send the user off
                // to retype a passphrase that was never the problem.
                throw new CliUsageException("could not read the confirmation (end of input) — use --passphrase-env for non-interactive use");
            }
            if (!string.Equals(first, second, StringComparison.Ordinal))
            {
                throw new CliUsageException("passphrases do not match");
            }
        }
        return first;
    }

    /// <summary>Reads one line without echo. Returns null on end of input (redirected stdin at EOF).</summary>
    private static string? ReadLineSecret(string prompt, CancellationToken cancellationToken)
    {
        Console.Error.Write(prompt);

        // If stdin is redirected (pipe, file, CI), reading character by character
        // wouldn't make sense — just read a line.
        if (Console.IsInputRedirected)
        {
            return Console.In.ReadLine();
        }

        var sb = new StringBuilder();
        while (true)
        {
            // Poll instead of blocking in ReadKey so Ctrl+C cancels the prompt itself —
            // otherwise the intercepted SIGINT sets the token and the user sits at a prompt
            // that will never return until they press Enter.
            while (!Console.KeyAvailable)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Thread.Sleep(25);
            }
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (sb.Length > 0) sb.Length--;
                continue;
            }
            if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
        }
        return sb.ToString();
    }

    private static void ReportProgress(PqProgress p)
    {
        if (p.Fraction is double f)
        {
            Console.Error.Write($"\r {f * 100,5:F1}%  ({p.BytesProcessed:N0} / {p.TotalBytes:N0} bytes)");
        }
        else
        {
            Console.Error.Write($"\r        ({p.BytesProcessed:N0} bytes)");
        }
    }

    private static int Fail(string message, int exitCode)
    {
        Console.Error.WriteLine($"error: {message}");
        return exitCode;
    }

    private static bool IsHelp(string s) => s is "-h" or "--help" or "help";

    private static string LibraryVersion() =>
        typeof(PqFileEncryptor).Assembly.GetName().Version?.ToString() ?? "unknown";

    private static void PrintUsage()
    {
        Console.WriteLine("""
            pqfe — encrypt, decrypt, sign, and verify files from the command line.

            Usage:
              pqfe encrypt <input> <output> [--argon2id] [--passphrase-env VAR]
              pqfe decrypt <input> <output>                [--passphrase-env VAR]
              pqfe keygen  <keyfile> [--encrypt [--passphrase-env VAR]]
              pqfe sign    <input> <keyfile>     [--signature PATH] [--passphrase-env VAR]
              pqfe verify  <input> <keyfile.pub> [--signature PATH]
              pqfe --version
              pqfe --help

            Options:
              --argon2id            Use Argon2id (memory-hard) instead of PBKDF2-HMAC-SHA256.
                                    Decryption reads the KDF from the container header — no flag needed.
              --passphrase-env VAR  Read the passphrase from environment variable VAR
                                    instead of prompting. Recommended for scripts and CI.
                                    Caveat: environment variables are visible to child
                                    processes and can surface in crash dumps and process
                                    inspection — scope VAR to the single invocation.
              --signature PATH      Detached-signature path (default: <input> + ".sig").
              --encrypt             (keygen) Protect the private key file with a passphrase
                                    (PQKF format: an Argon2id-hardened .pqfe container).
                                    sign detects an encrypted key file automatically and
                                    prompts (or reads --passphrase-env) for its passphrase.

            keygen writes an Ed25519 + ML-DSA-65 hybrid signing key pair: <keyfile> holds the
            private key (keep secret; keygen refuses to overwrite), <keyfile>.pub the public
            key. sign/verify produce and check detached signatures over any file — typically
            a .pqfe container, proving who created it in addition to it being untampered.

            Exit codes follow sysexits.h conventions: 0 ok, 64 usage,
            65 data error (wrong key, tamper, or bad signature), 66 missing input, 74 i/o,
            130 interrupted (Ctrl+C).
            """);
    }

    private readonly record struct Flags(bool UseArgon2id, string? PassphraseEnv, bool Force);

    /// <summary>
    /// A usage-level failure raised deep in a helper. Main maps it to exit 64 after every
    /// enclosing <c>finally</c> (zeroing, cleanup, event unhook) has run — which is exactly
    /// what <see cref="Environment.Exit(int)"/> would skip.
    /// </summary>
    private sealed class CliUsageException(string message) : Exception(message);
}
