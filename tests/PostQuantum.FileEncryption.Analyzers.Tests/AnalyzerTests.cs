using Microsoft.CodeAnalysis.CSharp.Testing;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Testing;
using PostQuantum.FileEncryption.Analyzers;
using Xunit;

namespace PostQuantum.FileEncryption.Analyzers.Tests;

/// <summary>
/// Each rule is tested with at least one flagged shape (the marked span) and one clean shape,
/// so a rule can neither go silent nor turn noisy without a test failing. Test code compiles
/// against the real library assemblies — the analyzers see the same symbols users' code does.
/// </summary>
public static class AnalyzerTests
{
    private static CSharpAnalyzerTest<TAnalyzer, DefaultVerifier> CreateTest<TAnalyzer>(string source)
        where TAnalyzer : DiagnosticAnalyzer, new()
    {
        var test = new CSharpAnalyzerTest<TAnalyzer, DefaultVerifier>
        {
            TestCode = source,
            ReferenceAssemblies = ReferenceAssemblies.Net.Net80,
        };
        test.TestState.AdditionalReferences.Add(typeof(PqFileEncryptor).Assembly);
        test.TestState.AdditionalReferences.Add(typeof(Hybrid.PqHybridKeyPair).Assembly);
        test.TestState.AdditionalReferences.Add(typeof(Signing.PqSigningKeyPair).Assembly);
        return test;
    }

    // ------------------------------------------------------------------ PQFE101

    public sealed class Pqfe101_hardcoded_passphrase
    {
        [Fact]
        public async Task Flags_a_string_literal_passphrase()
        {
            const string source = """
                using System.Threading.Tasks;
                using PostQuantum.FileEncryption;

                class C
                {
                    async Task M()
                    {
                        await new PqFileEncryptor().EncryptFileAsync("in.bin", "out.pqfe", {|PQFE101:"hunter2"|});
                    }
                }
                """;
            await CreateTest<HardcodedPassphraseAnalyzer>(source).RunAsync();
        }

        [Fact]
        public async Task Flags_a_const_field_passphrase_and_the_sync_span_overload()
        {
            const string source = """
                using PostQuantum.FileEncryption;

                class C
                {
                    private const string Secret = "hunter2";

                    void M()
                    {
                        _ = new PqFileEncryptor().EncryptBytes(new byte[10], {|PQFE101:Secret|});
                    }
                }
                """;
            await CreateTest<HardcodedPassphraseAnalyzer>(source).RunAsync();
        }

        [Fact]
        public async Task Does_not_flag_a_runtime_passphrase()
        {
            const string source = """
                using System;
                using System.Threading.Tasks;
                using PostQuantum.FileEncryption;

                class C
                {
                    async Task M()
                    {
                        string passphrase = Environment.GetEnvironmentVariable("PQFE_PASS") ?? throw new InvalidOperationException();
                        await new PqFileEncryptor().EncryptFileAsync("in.bin", "out.pqfe", passphrase);
                    }
                }
                """;
            await CreateTest<HardcodedPassphraseAnalyzer>(source).RunAsync();
        }
    }

    // ------------------------------------------------------------------ PQFE102

    public sealed class Pqfe102_raw_private_key_to_disk
    {
        [Fact]
        public async Task Flags_raw_export_written_with_WriteAllBytes()
        {
            const string source = """
                using System.IO;
                using PostQuantum.FileEncryption.Hybrid;

                class C
                {
                    void M()
                    {
                        using var keyPair = PqHybridKeyPair.Generate();
                        {|PQFE102:File.WriteAllBytes("me.key", keyPair.PrivateKey.Export())|};
                    }
                }
                """;
            await CreateTest<RawPrivateKeyToDiskAnalyzer>(source).RunAsync();
        }

        [Fact]
        public async Task Does_not_flag_the_encrypted_export_or_public_keys()
        {
            const string source = """
                using System.IO;
                using PostQuantum.FileEncryption.Hybrid;

                class C
                {
                    void M(string passphrase)
                    {
                        using var keyPair = PqHybridKeyPair.Generate();
                        File.WriteAllBytes("me.key", keyPair.PrivateKey.ExportEncrypted(passphrase));
                        File.WriteAllBytes("me.key.pub", keyPair.PublicKey.Export());
                    }
                }
                """;
            await CreateTest<RawPrivateKeyToDiskAnalyzer>(source).RunAsync();
        }
    }

    // ------------------------------------------------------------------ PQFE103

    public sealed class Pqfe103_unawaited_crypto_task
    {
        [Fact]
        public async Task Flags_a_discarded_decrypt_task_in_a_synchronous_method()
        {
            const string source = """
                using PostQuantum.FileEncryption;

                class C
                {
                    void M(string passphrase)
                    {
                        {|PQFE103:new PqFileDecryptor().DecryptFileAsync("in.pqfe", "out.bin", passphrase);|}
                    }
                }
                """;
            await CreateTest<UnawaitedCryptoOperationAnalyzer>(source).RunAsync();
        }

        [Fact]
        public async Task Does_not_flag_awaited_or_explicitly_discarded_calls()
        {
            const string source = """
                using System.Threading.Tasks;
                using PostQuantum.FileEncryption;

                class C
                {
                    async Task M(string passphrase)
                    {
                        await new PqFileDecryptor().DecryptFileAsync("in.pqfe", "out.bin", passphrase);
                        Task pending = new PqFileDecryptor().DecryptFileAsync("in2.pqfe", "out2.bin", passphrase);
                        await pending;
                    }
                }
                """;
            await CreateTest<UnawaitedCryptoOperationAnalyzer>(source).RunAsync();
        }
    }

    // ------------------------------------------------------------------ PQFE104

    public sealed class Pqfe104_swallowed_fail_closed_exception
    {
        [Fact]
        public async Task Flags_an_empty_catch_of_the_decryption_exception()
        {
            const string source = """
                using System.Threading.Tasks;
                using PostQuantum.FileEncryption;

                class C
                {
                    async Task M(string passphrase)
                    {
                        try
                        {
                            await new PqFileDecryptor().DecryptFileAsync("in.pqfe", "out.bin", passphrase);
                        }
                        {|PQFE104:catch (PqDecryptionException)
                        {
                        }|}
                    }
                }
                """;
            await CreateTest<SwallowedFailClosedExceptionAnalyzer>(source).RunAsync();
        }

        [Fact]
        public async Task Does_not_flag_a_handled_catch_or_a_format_probe()
        {
            const string source = """
                using System;
                using System.Threading.Tasks;
                using PostQuantum.FileEncryption;

                class C
                {
                    async Task<bool> M(string passphrase)
                    {
                        try
                        {
                            await new PqFileDecryptor().DecryptFileAsync("in.pqfe", "out.bin", passphrase);
                            return true;
                        }
                        catch (PqDecryptionException ex)
                        {
                            Console.Error.WriteLine(ex.Message);
                            return false;
                        }
                        catch (PqFormatException)
                        {
                        }
                        return false;
                    }
                }
                """;
            await CreateTest<SwallowedFailClosedExceptionAnalyzer>(source).RunAsync();
        }
    }
}
