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
    private const int ExitIoErr = 74;

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

        try
        {
            string[] rest = args[1..];
            return args[0] switch
            {
                "encrypt" => await EncryptAsync(rest).ConfigureAwait(false),
                "decrypt" => await DecryptAsync(rest).ConfigureAwait(false),
                "keygen" => KeyGen(rest),
                "sign" => await SignAsync(rest).ConfigureAwait(false),
                "verify" => await VerifyAsync(rest).ConfigureAwait(false),
                _ => Fail($"unknown command: {args[0]}", ExitUsage),
            };
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
        catch (IOException ex)
        {
            return Fail(ex.Message, ExitIoErr);
        }
    }

    private static async Task<int> EncryptAsync(string[] rest)
    {
        if (!TryParsePaths(rest, out string? input, out string? output, out var flags))
            return Fail("usage: pqfe encrypt <input> <output> [--argon2id] [--passphrase-env VAR]", ExitUsage);

        var options = new PqEncryptionOptions
        {
            Kdf = flags.UseArgon2id ? PqKdf.Argon2id : PqKdf.Pbkdf2HmacSha256,
        };

        byte[] passphrase = ReadPassphrase(flags.PassphraseEnv, confirm: true);
        try
        {
            var encryptor = new PqFileEncryptor(options);
            var progress = new Progress<PqProgress>(ReportProgress);
            await encryptor.EncryptFileAsync(input, output, passphrase, progress).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphrase);
        }

        Console.Error.WriteLine($"\nEncrypted {input} -> {output}");
        return ExitOk;
    }

    private static async Task<int> DecryptAsync(string[] rest)
    {
        if (!TryParsePaths(rest, out string? input, out string? output, out var flags))
            return Fail("usage: pqfe decrypt <input> <output> [--passphrase-env VAR]", ExitUsage);

        byte[] passphrase = ReadPassphrase(flags.PassphraseEnv, confirm: false);
        try
        {
            var decryptor = new PqFileDecryptor();
            var progress = new Progress<PqProgress>(ReportProgress);
            await decryptor.DecryptFileAsync(input, output, passphrase, progress).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passphrase);
        }

        Console.Error.WriteLine($"\nDecrypted {input} -> {output}");
        return ExitOk;
    }

    private static int KeyGen(string[] rest)
    {
        if (rest.Length != 1 || rest[0].StartsWith('-'))
            return Fail("usage: pqfe keygen <keyfile>   (writes <keyfile> and <keyfile>.pub)", ExitUsage);

        string privatePath = rest[0];
        string publicPath = privatePath + ".pub";

        using var keyPair = PqSigningKeyPair.Generate();
        byte[] privateBytes = keyPair.PrivateKey.Export();
        try
        {
            // CreateNew refuses to overwrite: a signing key silently replaced is a key lost.
            WriteNewFile(privatePath, privateBytes);
            WriteNewFile(publicPath, keyPair.PublicKey.Export());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }

        Console.Error.WriteLine($"Wrote {privatePath} (private key — keep secret) and {publicPath} (public key — share).");
        return ExitOk;
    }

    private static async Task<int> SignAsync(string[] rest)
    {
        if (!TryParseSigning(rest, out string? input, out string? keyPath, out string? signaturePath))
            return Fail("usage: pqfe sign <input> <keyfile> [--signature PATH]", ExitUsage);

        byte[] keyBytes = await File.ReadAllBytesAsync(keyPath).ConfigureAwait(false);
        try
        {
            PqSigningPrivateKey privateKey;
            try
            {
                privateKey = PqSigningPrivateKey.Import(keyBytes);
            }
            catch (ArgumentException)
            {
                return Fail($"'{keyPath}' is not a valid signing private key (expected the file written by 'pqfe keygen').", ExitDataErr);
            }

            using (privateKey)
            {
                await new PqSigner().SignFileAsync(input, signaturePath, privateKey).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        Console.Error.WriteLine($"Signed {input} -> {signaturePath}");
        return ExitOk;
    }

    private static async Task<int> VerifyAsync(string[] rest)
    {
        if (!TryParseSigning(rest, out string? input, out string? keyPath, out string? signaturePath))
            return Fail("usage: pqfe verify <input> <keyfile.pub> [--signature PATH]", ExitUsage);

        byte[] keyBytes = await File.ReadAllBytesAsync(keyPath).ConfigureAwait(false);
        PqSigningPublicKey publicKey;
        try
        {
            publicKey = PqSigningPublicKey.Import(keyBytes);
        }
        catch (ArgumentException)
        {
            return Fail($"'{keyPath}' is not a valid signing public key (expected the .pub file written by 'pqfe keygen').", ExitDataErr);
        }

        await new PqVerifier().VerifyFileAsync(input, signaturePath, publicKey).ConfigureAwait(false);

        Console.Error.WriteLine($"Signature OK: {input} verified against {signaturePath}");
        return ExitOk;
    }

    private static void WriteNewFile(string path, byte[] bytes)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(bytes, 0, bytes.Length);
    }

    private static bool TryParseSigning(
        string[] args,
        [NotNullWhen(true)] out string? input,
        [NotNullWhen(true)] out string? keyPath,
        [NotNullWhen(true)] out string? signaturePath)
    {
        input = null;
        keyPath = null;
        signaturePath = null;

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

    private static byte[] ReadPassphrase(string? envVar, bool confirm)
    {
        if (!string.IsNullOrEmpty(envVar))
        {
            string? value = Environment.GetEnvironmentVariable(envVar);
            if (string.IsNullOrEmpty(value))
            {
                Console.Error.WriteLine($"error: environment variable '{envVar}' is empty or unset");
                Environment.Exit(ExitUsage);
            }
            return Encoding.UTF8.GetBytes(value);
        }

        string first = ReadLineSecret("Passphrase: ");
        if (confirm)
        {
            string second = ReadLineSecret("Confirm:    ");
            if (!string.Equals(first, second, StringComparison.Ordinal))
            {
                Console.Error.WriteLine("error: passphrases do not match");
                Environment.Exit(ExitUsage);
            }
        }
        return Encoding.UTF8.GetBytes(first);
    }

    private static string ReadLineSecret(string prompt)
    {
        Console.Error.Write(prompt);

        // If stdin is redirected (pipe, file, CI), reading character by character
        // wouldn't make sense — just read a line.
        if (Console.IsInputRedirected)
        {
            return Console.In.ReadLine() ?? string.Empty;
        }

        var sb = new StringBuilder();
        while (true)
        {
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
              pqfe keygen  <keyfile>
              pqfe sign    <input> <keyfile>     [--signature PATH]
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

            keygen writes an Ed25519 + ML-DSA-65 hybrid signing key pair: <keyfile> holds the
            private key (keep secret; keygen refuses to overwrite), <keyfile>.pub the public
            key. sign/verify produce and check detached signatures over any file — typically
            a .pqfe container, proving who created it in addition to it being untampered.

            Exit codes follow sysexits.h conventions: 0 ok, 64 usage,
            65 data error (wrong key, tamper, or bad signature), 66 missing input, 74 i/o.
            """);
    }

    private readonly record struct Flags(bool UseArgon2id, string? PassphraseEnv);
}
