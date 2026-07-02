using System.Text;
using PostQuantum.FileEncryption.Hybrid;
using Xunit;

namespace PostQuantum.FileEncryption.Tests;

/// <summary>
/// Pinned known-answer vector for hybrid recipient decryption (docs/TEST-VECTORS.md,
/// Vector 6) — the only vector that exercises the X25519 + ML-KEM-768 combiner byte-exactly
/// (KeySource 3). Encryption is randomized (fresh KEM encapsulation and ephemeral X25519 key
/// per container), so the vector is decrypt-only. If a change breaks it, that is a
/// deliberate, breaking change to the combiner or the wrap-block layout — spec-frozen with
/// v2. The key pair was generated solely for this vector and protects nothing.
/// </summary>
public sealed class HybridKnownAnswerVectorTests
{
    private static readonly byte[] ExpectedPlaintext = Encoding.UTF8.GetBytes(
        "PostQuantum.FileEncryption hybrid recipient known-answer vector (X25519 + ML-KEM-768).");

    // PqHybridPrivateKey.Export() bytes: X25519(32) ‖ ML-KEM-dk(2400).
    private const string PrivateKeyVector =
        "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";

    // A .pqfe v2 container, KeySource 3 (hybrid recipient), encrypted to the key above.
    private const string ContainerVector =
        "UFFGRQIBAwAAAQAAbJ94MQSfAQRApwX6GPuwscQTlP7g05KlVuy/M0lS7//jpMdspyN6UiJyLux73Kx26roy6YKAHnxf/M03kxfMZBIgTKAEWyubzia26L60Z55pMt3vG2zzCSqJ6CwMfcEEAqbg6fyQii8aCByjGata8FTv42bTcA67O98YHiJEiuCwlLUBDaiUiVFtVU51giibidZC/GFbx4Xi+No4qR0wBeXDpCyI9EgJeumXJtpcjcQcxDauG/RzX+Pq1MpxCZw7sID7Dj2wLb6I/wn1/WGiHlwO4PkXf0FB7NH82+YyUDeww0ihS6vQ+JZeGAaULwfWeyb2eXT/OPLdcFr/cXpUMHzyzs4U8a2+C/hC5+GAP6f2R6+cLbNewJyHBhe7i6EOaDnJH+UkWFXl02t9jfM/iy1cAl0nkMICEgB7c7uVEQFkticzFL4/dUMShsbl6P0dKD0LWF8P8CSYnomqDOB7SewKBUTDZk+RsMJCgulK/V2a3Z57NbPbMnE12YKuemkNe68djbRzPQxdII610oFppQhArObbtv43Y64SlBrA13l/d6sTZBU7SxKYllV3B2G7An24ITVGtPZm1F3fSgjlr9UlbFztkR9LAIWJfYmmFsP6dNFDOzscrOtaPOCp0Nzd5j8/PJoPG89E6ozM0WWlRswmq55kKvrsEbplktQ7TxY4hie5IZPQa5q+YNANbxBz/ks5xUtMeEgAlEtDwJhEKlLt8oHTNQD4t/cUDR5iuTG1xECIfmi2g4vT4lZHtKY2Oa/H6KkZa4iJ51RAMVrmx6E2pKK7MJiNH9hR6KavrzpOpUH4ddHgO5vpWqN5uHWB2E2+fyDB+72Jj/mPeaiCfAulwPTv0jTp6Ni5RPhe/n0HK3GoXOB0Y2HFSIPzipxcPByBuXBWEdL0P3CtrAIRPIFgOIo9fxJmfwdBnIPU0SXlgaD4RxAbmbjyhmR0Xw7lihzORWu0U4AK3XKc64TOrwJlgdlPRUkAhQMIoO1VkiQtoC7BiITpSLRU/iLK+sZByy0FOdrah34OrPXXUZ5KJAU8/R11gL7yOKMk8xlg67OAZyw86xIINYDNF6q/xMxTYcqqy9w9/mqN1a7uPOFgcPJOnZZw5pCXLgeikqNWpbucUDqK5KchiU6nQZnFQHg2E7MxSgFayxGehSMGlif/ICXRl9JYX98Ov1RNdzzyaw9Q7XAVga3L6Mdu0XyRLnu2oeZeTV/tm5GR5+ish8Za6nBjOpcK8mdqwbtmQH3J6KUeog6t4uGngbnoCvTSHHj+WN7tL6EVsIHER4H3BT9XP+KIYmnSxzOkbO0RFhBps2dFSoMxFq2w0UKpW8ZcVJie+E/A1fW3SA0OgApV+/PkcmYBaurEsfVbAsaXpgCbxgviSpXyFfbbWZLXeJiWYANCVDeDad6d8MZxXSazLVJZOFf8W0uAlwf6djFmsowQ6MyK06dtkGIR926eeLt/lWIgcRawsIqy/MeOhfuPHtD+JMK3nijSwMmPeLT6JjxZvpxutNnoIaxbkSJv+lRqse1UTYZBKABzw80Tk2sHjgFVKbj6MRv1PnFPxQb/95NbcvvSUxFm+wEAAABWygDtr/evifS8gBJKj/O2k+GKMFzLToZcsXZ3ay6P64UH4p8fcrJix9J/Lbl7oQ3ELgXZFbEC2kBWu9UrJSvUkOAxdfHu9FVHoRuJqKlFwi2QdkP69z9sOAihwG427RV6tZ5O4C5x";

    [Fact]
    public async Task Pinned_hybrid_container_decrypts_to_known_plaintext()
    {
        byte[] container = Convert.FromBase64String(ContainerVector);
        using var privateKey = PqHybridPrivateKey.Import(Convert.FromBase64String(PrivateKeyVector));

        byte[] plaintext = await new PqHybridDecryptor().DecryptBytesAsync(container, privateKey);

        Assert.Equal(ExpectedPlaintext, plaintext);
    }

    [Fact]
    public async Task Pinned_hybrid_container_rejects_a_different_key()
    {
        byte[] container = Convert.FromBase64String(ContainerVector);
        using var otherKey = PqHybridKeyPair.Generate();

        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqHybridDecryptor().DecryptBytesAsync(container, otherKey.PrivateKey));
    }

    [Fact]
    public async Task Pinned_hybrid_container_fails_closed_when_tampered()
    {
        byte[] container = Convert.FromBase64String(ContainerVector);
        using var privateKey = PqHybridPrivateKey.Import(Convert.FromBase64String(PrivateKeyVector));

        container[^1] ^= 0x01;
        await Assert.ThrowsAsync<PqDecryptionException>(() =>
            new PqHybridDecryptor().DecryptBytesAsync(container, privateKey));
    }
}
