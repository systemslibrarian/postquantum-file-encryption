// Quickstart: encrypt every file in a folder before it leaves the machine — the smallest
// complete backup-encryption program that still does everything right (runtime passphrase,
// atomic output, cooperative Ctrl+C, fail-closed error handling, correct exit codes).
//
//   set PQFE_PASS=...           (or: export PQFE_PASS=...)
//   dotnet run -- encrypt <sourceFolder> <destFolder>
//   dotnet run -- decrypt <sourceFolder> <destFolder>
//
// The positive patterns here are explained in docs/COOKBOOK.md; the shapes deliberately
// avoided are in docs/ANTI-PATTERNS.md.

using PostQuantum.FileEncryption;

if (args.Length != 3 || args[0] is not ("encrypt" or "decrypt"))
{
    Console.Error.WriteLine("usage: encrypt|decrypt <sourceFolder> <destFolder>   (passphrase from PQFE_PASS)");
    return 64;
}

// The passphrase enters at runtime — never a literal (the analyzers flag that as PQFE101).
string? passphrase = Environment.GetEnvironmentVariable("PQFE_PASS");
if (string.IsNullOrEmpty(passphrase))
{
    Console.Error.WriteLine("error: set the PQFE_PASS environment variable");
    return 64;
}

// Ctrl+C cancels cooperatively: the in-flight file's temp output is cleaned up and nothing
// partial is left at the destination.
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

string source = Path.GetFullPath(args[1]);
string dest = Path.GetFullPath(args[2]);
Directory.CreateDirectory(dest);

// Argon2id: memory-hard, the right default for passphrases an attacker may try to crack
// offline. Decryption reads the KDF from each container header — no flag needed there.
var encryptor = new PqFileEncryptor(PqEncryptionOptions.Argon2id);
var decryptor = new PqFileDecryptor();

int failures = 0;
try
{
    foreach (string inputPath in Directory.EnumerateFiles(source))
    {
        string name = Path.GetFileName(inputPath);
        try
        {
            if (args[0] == "encrypt")
            {
                await encryptor.EncryptFileAsync(inputPath, Path.Combine(dest, name + ".pqfe"), passphrase, null, cts.Token);
                Console.WriteLine($"encrypted {name}");
            }
            else
            {
                string outputName = name.EndsWith(".pqfe", StringComparison.OrdinalIgnoreCase) ? name[..^5] : name + ".out";
                await decryptor.DecryptFileAsync(inputPath, Path.Combine(dest, outputName), passphrase, null, cts.Token);
                Console.WriteLine($"decrypted {name}");
            }
        }
        catch (PqFormatException)
        {
            Console.Error.WriteLine($"skipped {name}: not a .pqfe container");
            failures++;
        }
        catch (PqDecryptionException)
        {
            // Wrong passphrase and tampered bytes are deliberately indistinguishable, and no
            // partial plaintext was written. Report and move on — never retry in a loop.
            Console.Error.WriteLine($"FAILED {name}: wrong passphrase, or the file was altered");
            failures++;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A locked, unreadable, or concurrently deleted file must not abort the whole run
            // with a raw stack trace — report it like the other per-file failures and move on.
            Console.Error.WriteLine($"FAILED {name}: {ex.Message}");
            failures++;
        }
    }
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("cancelled");
    return 130;
}

return failures == 0 ? 0 : 65;
