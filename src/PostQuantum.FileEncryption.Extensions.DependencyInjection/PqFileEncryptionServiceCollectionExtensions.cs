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
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0027:API with optional parameter(s) should have the most parameters amongst its public overloads",
        Justification = "This signature shipped in 1.4.0 and must stay byte-identical (PublicAPI baseline). The longer limits overload takes both parameters as required precisely so overload resolution never has two optional-bearing candidates.")]
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
    /// Registers <see cref="PqFileEncryptor"/> and <see cref="PqFileDecryptor"/> as singletons,
    /// with the decryptor enforcing <paramref name="limits"/> on every container it opens.
    /// Use this overload when the host decrypts containers from untrusted sources (uploads,
    /// shared storage) — a hostile header can otherwise legally demand gibibytes of KDF memory
    /// before anything authenticates. <see cref="PqDecryptionLimits.Untrusted"/> is the
    /// ready-made ceiling.
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <param name="options">
    /// Encryption options applied by the registered <see cref="PqFileEncryptor"/>; pass
    /// <see langword="null"/> for <see cref="PqEncryptionOptions.Default"/>. Options never
    /// affect decryption.
    /// </param>
    /// <param name="limits">
    /// Decrypt-time resource ceilings applied by the registered <see cref="PqFileDecryptor"/>.
    /// A container header above a limit is rejected with <c>PqFormatException</c> before any
    /// allocation or key-derivation work.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">A limit is outside the format's supported range.</exception>
    public static IServiceCollection AddPqFileEncryption(
        this IServiceCollection services,
        PqEncryptionOptions? options,
        PqDecryptionLimits limits)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(limits);

        services.TryAddSingleton(new PqFileEncryptor(options ?? PqEncryptionOptions.Default));
        services.TryAddSingleton(new PqFileDecryptor(limits));
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
    [System.Diagnostics.CodeAnalysis.SuppressMessage("ApiDesign", "RS0027:API with optional parameter(s) should have the most parameters amongst its public overloads",
        Justification = "This signature shipped in 1.4.0 and must stay byte-identical (PublicAPI baseline). The longer limits overload takes both parameters as required precisely so overload resolution never has two optional-bearing candidates.")]
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
    /// Registers the hybrid and passphrase services with both decryptors enforcing
    /// <paramref name="limits"/> — the overload for hosts that decrypt containers from
    /// untrusted sources. On the hybrid path only the chunk-size ceiling applies (key unwrap
    /// is a fixed-cost KEM operation); the passphrase decryptor is additionally capped on KDF
    /// cost. <see cref="PqDecryptionLimits.Untrusted"/> is the ready-made ceiling.
    /// </summary>
    /// <param name="services">The service collection to add the registrations to.</param>
    /// <param name="options">
    /// Encryption options applied by the registered encryptors; pass <see langword="null"/>
    /// for <see cref="PqEncryptionOptions.Default"/>. Options never affect decryption.
    /// </param>
    /// <param name="limits">
    /// Decrypt-time resource ceilings applied by both registered decryptors. A container
    /// header above a limit is rejected with <c>PqFormatException</c> before any allocation
    /// or key-derivation work.
    /// </param>
    /// <returns>The same <paramref name="services"/> instance, for chaining.</returns>
    /// <exception cref="ArgumentOutOfRangeException">A limit is outside the format's supported range.</exception>
    public static IServiceCollection AddPqHybridFileEncryption(
        this IServiceCollection services,
        PqEncryptionOptions? options,
        PqDecryptionLimits limits)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(limits);

        services.AddPqFileEncryption(options, limits);
        services.TryAddSingleton(new PqHybridEncryptor(options ?? PqEncryptionOptions.Default));
        services.TryAddSingleton(new PqHybridDecryptor(limits));
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
