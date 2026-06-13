using Microsoft.Extensions.DependencyInjection.Extensions;
using PostQuantum.FileEncryption;
using PostQuantum.FileEncryption.Hybrid;
using PostQuantum.FileEncryption.Signing;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering PostQuantum.FileEncryption services with an
/// <see cref="IServiceCollection"/>.
/// </summary>
/// <remarks>
/// <para>
/// All registrations are singletons: the encryptor and decryptor types are immutable,
/// thread-safe, and hold no per-operation state, so a single instance serves the whole host.
/// </para>
/// <para>
/// Registrations use <c>TryAdd</c> semantics — if the application has already registered its
/// own instance of any of these types, that registration wins and is not replaced.
/// </para>
/// </remarks>
public static class PqFileEncryptionServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="PqFileEncryptor"/> and <see cref="PqFileDecryptor"/> as singletons
    /// for passphrase-based file and stream encryption.
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <param name="options">
    /// Encryption options applied by the registered <see cref="PqFileEncryptor"/>. When
    /// <see langword="null"/>, <see cref="PqEncryptionOptions.Default"/> is used — a caller who
    /// supplies no options gets a secure result. Options never affect decryption: the decryptor
    /// reads all parameters from the authenticated container header.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    public static IServiceCollection AddPqFileEncryption(
        this IServiceCollection services,
        PqEncryptionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(new PqFileEncryptor(options ?? PqEncryptionOptions.Default));
        services.TryAddSingleton(new PqFileDecryptor());
        return services;
    }

    /// <summary>
    /// Registers <see cref="PqHybridEncryptor"/> and <see cref="PqHybridDecryptor"/> as
    /// singletons for X25519 + ML-KEM-768 hybrid recipient (public-key) encryption, in
    /// addition to the passphrase services registered by
    /// <see cref="AddPqFileEncryption(IServiceCollection, PqEncryptionOptions?)"/>.
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <param name="options">
    /// Encryption options applied by the registered encryptors. When <see langword="null"/>,
    /// <see cref="PqEncryptionOptions.Default"/> is used. Options never affect decryption.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    public static IServiceCollection AddPqHybridFileEncryption(
        this IServiceCollection services,
        PqEncryptionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddPqFileEncryption(options);
        services.TryAddSingleton(new PqHybridEncryptor(options ?? PqEncryptionOptions.Default));
        services.TryAddSingleton(new PqHybridDecryptor());
        return services;
    }

    /// <summary>
    /// Registers <see cref="PqSigner"/> and <see cref="PqVerifier"/> as singletons for
    /// detached Ed25519 + ML-DSA-65 hybrid signing and verification. Key material is not
    /// registered — pass a <c>PqSigningPrivateKey</c>/<c>PqSigningPublicKey</c> per call,
    /// sourced from the application's own key storage.
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    public static IServiceCollection AddPqSigning(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(new PqSigner());
        services.TryAddSingleton(new PqVerifier());
        return services;
    }
}
