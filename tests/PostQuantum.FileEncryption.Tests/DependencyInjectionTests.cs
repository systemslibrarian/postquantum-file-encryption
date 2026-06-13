using Microsoft.Extensions.DependencyInjection;
using PostQuantum.FileEncryption.Hybrid;
using PostQuantum.FileEncryption.Signing;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

public sealed class DependencyInjectionTests
{
    [Fact]
    public void AddPqFileEncryption_registers_encryptor_and_decryptor_as_singletons()
    {
        var services = new ServiceCollection().AddPqFileEncryption();

        using var provider = services.BuildServiceProvider();

        var encryptor = provider.GetRequiredService<PqFileEncryptor>();
        var decryptor = provider.GetRequiredService<PqFileDecryptor>();
        Assert.Same(encryptor, provider.GetRequiredService<PqFileEncryptor>());
        Assert.Same(decryptor, provider.GetRequiredService<PqFileDecryptor>());
    }

    [Fact]
    public void AddPqFileEncryption_returns_the_same_collection_for_chaining()
    {
        var services = new ServiceCollection();

        Assert.Same(services, services.AddPqFileEncryption());
    }

    [Fact]
    public async Task Resolved_services_round_trip_with_default_options()
    {
        using var provider = new ServiceCollection()
            .AddPqFileEncryption()
            .BuildServiceProvider();

        var plaintext = new byte[] { 1, 2, 3, 4, 5 };
        var container = await provider.GetRequiredService<PqFileEncryptor>()
            .EncryptBytesAsync(plaintext, "correct horse battery staple");
        var decrypted = await provider.GetRequiredService<PqFileDecryptor>()
            .DecryptBytesAsync(container, "correct horse battery staple");

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public async Task Resolved_services_round_trip_with_explicit_options()
    {
        using var provider = new ServiceCollection()
            .AddPqFileEncryption(PqEncryptionOptions.Argon2id)
            .BuildServiceProvider();

        var plaintext = new byte[] { 9, 8, 7 };
        var container = await provider.GetRequiredService<PqFileEncryptor>()
            .EncryptBytesAsync(plaintext, "pass");
        var decrypted = await provider.GetRequiredService<PqFileDecryptor>()
            .DecryptBytesAsync(container, "pass");

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void AddPqFileEncryption_does_not_replace_an_existing_registration()
    {
        var mine = new PqFileEncryptor(PqEncryptionOptions.Default.WithChunkSize(128 * 1024));
        var services = new ServiceCollection();
        services.AddSingleton(mine);

        using var provider = services.AddPqFileEncryption().BuildServiceProvider();

        Assert.Same(mine, provider.GetRequiredService<PqFileEncryptor>());
    }

    [Fact]
    public void AddPqHybridFileEncryption_registers_hybrid_and_passphrase_services()
    {
        using var provider = new ServiceCollection()
            .AddPqHybridFileEncryption()
            .BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<PqFileEncryptor>());
        Assert.NotNull(provider.GetRequiredService<PqFileDecryptor>());
        Assert.NotNull(provider.GetRequiredService<PqHybridEncryptor>());
        Assert.NotNull(provider.GetRequiredService<PqHybridDecryptor>());
    }

    [Fact]
    public async Task Resolved_hybrid_services_round_trip()
    {
        using var provider = new ServiceCollection()
            .AddPqHybridFileEncryption()
            .BuildServiceProvider();
        using var keyPair = PqHybridKeyPair.Generate();

        var plaintext = new byte[] { 42, 42, 42 };
        var container = await provider.GetRequiredService<PqHybridEncryptor>()
            .EncryptBytesAsync(plaintext, keyPair.PublicKey);
        var decrypted = await provider.GetRequiredService<PqHybridDecryptor>()
            .DecryptBytesAsync(container, keyPair.PrivateKey);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void AddPqSigning_registers_signer_and_verifier_as_singletons()
    {
        using var provider = new ServiceCollection()
            .AddPqSigning()
            .BuildServiceProvider();

        var signer = provider.GetRequiredService<PqSigner>();
        var verifier = provider.GetRequiredService<PqVerifier>();
        Assert.Same(signer, provider.GetRequiredService<PqSigner>());
        Assert.Same(verifier, provider.GetRequiredService<PqVerifier>());
    }

    [Fact]
    public void Resolved_signing_services_round_trip()
    {
        using var provider = new ServiceCollection()
            .AddPqSigning()
            .BuildServiceProvider();
        using var keyPair = PqSigningKeyPair.Generate();

        var data = new byte[] { 42, 42, 42 };
        byte[] signature = provider.GetRequiredService<PqSigner>().SignBytes(data, keyPair.PrivateKey);
        provider.GetRequiredService<PqVerifier>().VerifyBytes(data, signature, keyPair.PublicKey);
    }

    [Fact]
    public void Add_methods_throw_on_null_services()
    {
        Assert.Throws<ArgumentNullException>(
            () => default(IServiceCollection)!.AddPqFileEncryption());
        Assert.Throws<ArgumentNullException>(
            () => default(IServiceCollection)!.AddPqHybridFileEncryption());
        Assert.Throws<ArgumentNullException>(
            () => default(IServiceCollection)!.AddPqSigning());
    }
}
