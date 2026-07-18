//! Conformance tests: the Rust core must decrypt the exact same known-answer vectors used by
//! the .NET test suite (`tests/.../KnownAnswerVectorTests.cs`). This is what keeps the two
//! independent implementations byte-compatible with the `.pqfe` v2 format.

use base64::Engine;
use pqfe_wasm::{decrypt_bytes, decrypt_bytes_hybrid, encrypt_bytes, encrypt_bytes_with, PqError};

const PASSPHRASE: &[u8] = b"test-vector-passphrase";
const EXPECTED: &[u8] = b"PostQuantum.FileEncryption known-answer vector v2.";

// KeySource = passphrase, KDF = PBKDF2-HMAC-SHA256 (100,000 iters), 16-byte salt, 1 KiB chunks.
const PBKDF2_VECTOR: &str =
    "UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj";

// KeySource = passphrase, KDF = Argon2id (8 MiB, 1 pass, 1 lane), 16-byte salt, 1 KiB chunks.
const ARGON2_VECTOR: &str =
    "UFFGRQIBAQAAAAQAS7aXNQAbAhCZBPTffR0AgJ7we1bozxQOAAAgAAAAAAEBAQAAADJOzagbj5vUN9WHVWy1t7KN/pG9O5ab04z0IO4xyV5vRMxDN2TsXQGStrNyW5eC77skRpx0WhB0BC6SxsnfnwherIM=";

fn decode(b64: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap()
}

#[test]
fn decrypts_dotnet_pbkdf2_vector() {
    let container = decode(PBKDF2_VECTOR);
    let plaintext = decrypt_bytes(&container, PASSPHRASE).expect("PBKDF2 vector must decrypt");
    assert_eq!(plaintext, EXPECTED);
}

#[test]
fn decrypts_dotnet_argon2id_vector() {
    let container = decode(ARGON2_VECTOR);
    let plaintext = decrypt_bytes(&container, PASSPHRASE).expect("Argon2id vector must decrypt");
    assert_eq!(plaintext, EXPECTED);
}

// Multi-chunk vector (TEST-VECTORS.md): 3,000 bytes at 1 KiB chunks — two data frames plus a
// final frame, so the per-chunk nonce counter and AAD chaining are pinned cross-implementation
// (the single-chunk vectors never exercise them). Plaintext byte i is (i * 31 + 7) & 0xFF.
const MULTICHUNK_VECTOR: &str =
    "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";

#[test]
fn decrypts_dotnet_multichunk_vector() {
    let container = decode(MULTICHUNK_VECTOR);
    let plaintext = decrypt_bytes(&container, PASSPHRASE).expect("multi-chunk vector must decrypt");
    let expected: Vec<u8> = (0..3000usize).map(|i| (i * 31 + 7) as u8).collect();
    assert_eq!(plaintext, expected);
}

// The PQKF v1 encrypted key file (docs/KEY-FILE-FORMAT.md, TEST-VECTORS.md Vector 5): a
// 5-byte framing (`PQKF` + version) around a standard v2 passphrase container whose plaintext
// is KeyType(1) ‖ private-key bytes. The Rust core has no key-file API — this test proves the
// embedded container is a plain conforming v2 container, which is the format's whole claim.
const PQKF_VECTOR: &str =
    "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";

const PQKF_EXPECTED_PRIVATE_KEY: &str =
    "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";

#[test]
fn decrypts_dotnet_pqkf_key_file_body() {
    let key_file = decode(PQKF_VECTOR);
    assert_eq!(&key_file[..4], b"PQKF", "PQKF magic");
    assert_eq!(key_file[4], 1, "PQKF version");

    let plaintext = decrypt_bytes(&key_file[5..], b"key-file-vector-passphrase")
        .expect("PQKF embedded container must decrypt as a plain v2 container");

    let expected_key = decode(PQKF_EXPECTED_PRIVATE_KEY);
    assert_eq!(plaintext[0], 1, "KeyType: hybrid recipient private key");
    assert_eq!(&plaintext[1..], &expected_key[..]);
}

#[test]
fn wrong_passphrase_fails_closed() {
    let container = decode(PBKDF2_VECTOR);
    assert_eq!(
        decrypt_bytes(&container, b"wrong"),
        Err(PqError::Decryption)
    );
}

#[test]
fn round_trip_small_and_multichunk() {
    for size in [0usize, 1, 100, 64 * 1024, 64 * 1024 + 5, 200_000] {
        let data: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
        let container = encrypt_bytes(&data, b"a-good-passphrase");
        let restored = decrypt_bytes(&container, b"a-good-passphrase").expect("round-trip");
        assert_eq!(restored, data, "round-trip failed for size {size}");
    }
}

#[test]
fn tampering_is_detected() {
    let data = b"some confidential bytes";
    let mut container = encrypt_bytes(data, b"a-good-passphrase");
    let last = container.len() - 1;
    container[last] ^= 0xFF; // flip a bit in the final tag
    assert_eq!(
        decrypt_bytes(&container, b"a-good-passphrase"),
        Err(PqError::Decryption)
    );
}

#[test]
fn truncation_is_detected() {
    let data = vec![42u8; 5000];
    let container = encrypt_bytes(&data, b"a-good-passphrase");
    let truncated = &container[..container.len() - 20];
    assert_eq!(
        decrypt_bytes(truncated, b"a-good-passphrase"),
        Err(PqError::Decryption)
    );
}

#[test]
fn non_container_is_format_error() {
    let garbage = vec![0u8; 64];
    assert!(matches!(
        decrypt_bytes(&garbage, PASSPHRASE),
        Err(PqError::Format(_))
    ));
}

/// Byte-exact cross-check: with a fixed salt and nonce prefix, the Rust core must produce the
/// identical container the .NET library does (see DeterministicVectorTests.cs).
#[test]
fn deterministic_output_matches_dotnet() {
    let salt: Vec<u8> = (0u8..16).collect();
    let nonce_prefix = [0xA1u8, 0xB2, 0xC3, 0xD4];
    let container = encrypt_bytes_with(
        b"Deterministic conformance vector - byte for byte.",
        b"deterministic-conformance",
        &salt,
        &nonce_prefix,
        120_000,
        1024,
    );
    let expected = "UFFGRQIBAQAAAAQAobLD1AAWARAAAQIDBAUGBwgJCgsMDQ4PAAHUwAEAAAAx8LbT/vUWhAJzxG27tIWQK9TfelTH70vWt+4CuWNvi58E0J1kT46rSZnQgLQx7ndsXtTEuK5a8PFd/Geog1+9mN4=";
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(&container),
        expected
    );
}

// ----------------------------------------------------------------- hybrid recipient vectors
//
// These pin the X25519 + ML-KEM-768 hybrid path (KeySource 3/4) cross-implementation: the .NET
// `PostQuantum.FileEncryption.Hybrid` package produced the containers and exported the recipient
// private keys; the Rust core must recover the identical content key and plaintext. Hybrid
// encryption is randomized (ephemeral X25519, ML-KEM encapsulation, wrap nonce), but ML-KEM
// decapsulation and X25519 agreement are deterministic, so a fixed (private key, container) pair
// is a stable known-answer vector — the same guarantee the passphrase KATs give. Both vectors are
// the *same bytes* pinned on the .NET side: Vector 6 by HybridKnownAnswerVectorTests.cs and
// Vector 8 by HybridMultiRecipientKnownAnswerVectorTests.cs (docs/TEST-VECTORS.md).

// --- Vector 6: single recipient (KeySource 3). Canonical; identical to the .NET KAT bytes.
const HYBRID6_PLAINTEXT: &[u8] =
    b"PostQuantum.FileEncryption hybrid recipient known-answer vector (X25519 + ML-KEM-768).";

// Recipient private key: X25519(32) ‖ ML-KEM-768-dk(2400) = 2432 bytes (PqHybridPrivateKey.Export).
const HYBRID6_PRIVATE_KEY: &str = "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";

// KeySource 3 (single recipient): container encrypted to the key above.
const HYBRID6_KS3_VECTOR: &str = "UFFGRQIBAwAAAQAAbJ94MQSfAQRApwX6GPuwscQTlP7g05KlVuy/M0lS7//jpMdspyN6UiJyLux73Kx26roy6YKAHnxf/M03kxfMZBIgTKAEWyubzia26L60Z55pMt3vG2zzCSqJ6CwMfcEEAqbg6fyQii8aCByjGata8FTv42bTcA67O98YHiJEiuCwlLUBDaiUiVFtVU51giibidZC/GFbx4Xi+No4qR0wBeXDpCyI9EgJeumXJtpcjcQcxDauG/RzX+Pq1MpxCZw7sID7Dj2wLb6I/wn1/WGiHlwO4PkXf0FB7NH82+YyUDeww0ihS6vQ+JZeGAaULwfWeyb2eXT/OPLdcFr/cXpUMHzyzs4U8a2+C/hC5+GAP6f2R6+cLbNewJyHBhe7i6EOaDnJH+UkWFXl02t9jfM/iy1cAl0nkMICEgB7c7uVEQFkticzFL4/dUMShsbl6P0dKD0LWF8P8CSYnomqDOB7SewKBUTDZk+RsMJCgulK/V2a3Z57NbPbMnE12YKuemkNe68djbRzPQxdII610oFppQhArObbtv43Y64SlBrA13l/d6sTZBU7SxKYllV3B2G7An24ITVGtPZm1F3fSgjlr9UlbFztkR9LAIWJfYmmFsP6dNFDOzscrOtaPOCp0Nzd5j8/PJoPG89E6ozM0WWlRswmq55kKvrsEbplktQ7TxY4hie5IZPQa5q+YNANbxBz/ks5xUtMeEgAlEtDwJhEKlLt8oHTNQD4t/cUDR5iuTG1xECIfmi2g4vT4lZHtKY2Oa/H6KkZa4iJ51RAMVrmx6E2pKK7MJiNH9hR6KavrzpOpUH4ddHgO5vpWqN5uHWB2E2+fyDB+72Jj/mPeaiCfAulwPTv0jTp6Ni5RPhe/n0HK3GoXOB0Y2HFSIPzipxcPByBuXBWEdL0P3CtrAIRPIFgOIo9fxJmfwdBnIPU0SXlgaD4RxAbmbjyhmR0Xw7lihzORWu0U4AK3XKc64TOrwJlgdlPRUkAhQMIoO1VkiQtoC7BiITpSLRU/iLK+sZByy0FOdrah34OrPXXUZ5KJAU8/R11gL7yOKMk8xlg67OAZyw86xIINYDNF6q/xMxTYcqqy9w9/mqN1a7uPOFgcPJOnZZw5pCXLgeikqNWpbucUDqK5KchiU6nQZnFQHg2E7MxSgFayxGehSMGlif/ICXRl9JYX98Ov1RNdzzyaw9Q7XAVga3L6Mdu0XyRLnu2oeZeTV/tm5GR5+ish8Za6nBjOpcK8mdqwbtmQH3J6KUeog6t4uGngbnoCvTSHHj+WN7tL6EVsIHER4H3BT9XP+KIYmnSxzOkbO0RFhBps2dFSoMxFq2w0UKpW8ZcVJie+E/A1fW3SA0OgApV+/PkcmYBaurEsfVbAsaXpgCbxgviSpXyFfbbWZLXeJiWYANCVDeDad6d8MZxXSazLVJZOFf8W0uAlwf6djFmsowQ6MyK06dtkGIR926eeLt/lWIgcRawsIqy/MeOhfuPHtD+JMK3nijSwMmPeLT6JjxZvpxutNnoIaxbkSJv+lRqse1UTYZBKABzw80Tk2sHjgFVKbj6MRv1PnFPxQb/95NbcvvSUxFm+wEAAABWygDtr/evifS8gBJKj/O2k+GKMFzLToZcsXZ3ay6P64UH4p8fcrJix9J/Lbl7oQ3ELgXZFbEC2kBWu9UrJSvUkOAxdfHu9FVHoRuJqKlFwi2QdkP69z9sOAihwG427RV6tZ5O4C5x";

// --- Vector 8: multiple recipients (KeySource 4). The same content key wrapped to THREE
// recipients, with HYBRID8_PRIVATE_KEY as the MIDDLE one — a pass proves the block scan tried,
// and skipped, a non-matching block before reaching ours (the "try each block" path, not just
// the first). Distinct key pair from Vector 6.
const HYBRID8_PLAINTEXT: &[u8] = b"PostQuantum.FileEncryption hybrid known-answer vector v2.";

const HYBRID8_PRIVATE_KEY: &str = "KANLagbCqcE4CRZfku/X1v8Mn4oo3Xb0otts93huUXQih3lqA5mkRckFo1LAHAEcZsF+Sg27SCbx+SQpciNdMg+eKRi0gc2e27vaNMApV4QWulQPm545fCnL50HP7JEh9kDioHQBmTGaFlGIqz/nGQ4FC5A2lbfRaD0nqJVdsWSyVB929KlMVHE9RDSwBWr7FTSViz92NGc49KUlqkpQlDndQpX9oTqxlh1YPByWQXCok5yTEbVuWDzZcFRoPCrUO0fIiZU12QWw2kvm05LO0QaqxGT6rIoARk6+56Nq6iyRkR4GqjYu9yXAAIwrJRBeV6afZmFS3HgwUzB0NMPJfJCDVAJJE86kZVbi4zDfhUCsNyU42EAAUX5n2pXUgH8Q5Le6GpK/9oVzQlLGBHW9IMvWQZ3q2Cju8ay0wcohMl33zAQWlKXPa8YvqwquEof4ET0op1oj6KjsK3G2c0um+VzRaEhY+1f2HCxy5WsZqUL0lpISZl9iMUL7TH4bNSwwA4PcyGEyIcWKApKoeMf2cYKE+6jJtTb5l4GFa48lUsuPiByMVrREdmXjJWBgdIPzRobO1R2xg2lX7JcYSLBXCzMQ97FTxUn1rC2NuxRcln5s6nAdEpGn5IzMKBA97G5IdxoTs7KSuFMyMYWM6TKDYBPeKZKWicOe9m+NR595gRcHLFSKSmvAphcBAXjBw4uiagulV4Yo6HpauSuQdoJYJ1dbyjGMaUsJgEks9zUKUFgtIHciYKQmcwU98r3I+qVxo4eWJRbpYhBLomYlEs+zOycq9VxUcEoQARNNkyARMQy5wyyWppDxkEfsZZ9ilr65Zs0xnBYtZ77Tqs+vRVDMsQsXC7696GZKOTt8w1SmdohMuLeHR5qjErNMNBYorHpxuBAfZLNKiLsw9XC1eRevq4ZUVCWoKhi/wBcuZ4TUIhP6EzR55JK24Ihw4onn60Pl534rlIac2AR2gBh89AMZFV10Cbv+6wOVOihZw0uvlsujOwFbhSQV0X3EAgrhEgE7sSJI/FO2FIQWRb2SeaEHgDznSWhHsFtb653FBs9E85moJSpR1RRfNj2BmhbI2Wcylih8IzJ6JwIhID9DwmSSTF1OaCNC1rVGkU8T0xa6ZRWgU7Igs3s7RcPTa7LVQUfZtDFJ0p6aWne/IgJRsiUsOgN2xrTDxGV+inkgB4x7VcB3qUmLsI0iq5X9O5Wmu1+INn9cCgmuZ5Xp6wGo5atG1o6BYakkxSWOZVdfE5LiGL//O5XbF4jVV7rfkCXjinrlx41UskNG6JCoQpkwtIfQZJegdntJM4DbUkzWSU0ZiR3og79RuQp+uKsyBXj81b94AQo3aYDlEbXVS02Nc3dxMTvLA5qo+HxCey/0gFFw2MHDBLMxGJPZ4xu9SomZM02pE6aMk8rblbClTEfPxRNdAIYgSkW02cV3wDsW50vNoDI6ynheXK76RK0WhgtDmUh7iaqRGxLAKnTeWwgMBReGNlpiUbxFQBwhqZZwSMJT3Mk5MQEuoM1a1KQ30K2WRwyAmFdWPDynqcbwF6ycjGEACCOeZliZBy1YFLYZ96J665Qoc25ewQMzU5WC5SL1ZigftzPPaVxCcluAMDoVKbDkyR95q2TZY898dSCwJL17Ix1Lgx/WUTjWthjJxbjfIaZht3P6qqPvtigZ+ReSaq4x1KjnNcFSUkm/eTQI6bDUhseYQBLMxQhN9G+XYsQA4WDIsGizIlNo4ULEsZm3+kiph04dWTpQ8QdS40sgKkTRsTr9hbSh1IzbzFhxmz8Hhc1YO8Zk4BBl44V2pwlYV2PpSgut9xLys44QjA4ei4PEzImwoCNvgQvJawe5wG0Rdyox3EYywLSVRpb9VgIUKLit/DmQ2Eoa6Tr341MYsbgPU3QhyDGux1sulKReoZQPQ2ibg4xr4J0UjI2xUmpRYIPse0Vb1L5IRMOSAwnTjGtT6wPhgpLLe2Ho+yDkiA5OlMaUx807lz6jSH/FyE8giANPyAYza7Fy4K0csoADdJ8rxVShhCYUh4xhsaktR7HxymWBujm3zCmYE1PWWF6WlmFiYR5PYK7mmr5wRssy+J9C+0tzeQqsql08455jzJiNWUq1PFTGaF69Jk3Ywq/cZl2zY0pUi4ym6o1vyYRTcru9wJCnQFRc5GUYNE5fFcloxTDKsIrNZy9cp669FwOGpIEflgFvgnae1AUbmaFmpGPheYmwm8z2RomBwQTLcTs3eStA0jjgpawj6UD4QoXRy1qC4l1EuJFMjDulhCaSIT+aEVxJQackFhgKUpf3xXmfqHqIywp/FyGrSXBf0jOj2pP1ZiDN0RV32CJEg49BpE7EUWpo9mECOkFAWyg9M7kUZnl/QVacEBovE8uIaHpOtXM2wFHGmnR4yIebVyPTQW6MKGVEuMsHlSoOlQggHM5u0w40OaAxF0VKgC+d5se6E1D36HuNIZ0Qg79M4BLt1SveerG+Vwm9Kg2UYE7Ru8fTprDgJAkZNAdPHMk/xr+HOhFRl3c34bU46DU2+Gc2RcIeInfQqnOGxBIMdQEMwhvUihBsFhfmxcr4IkaP9RCHpLI55Q+nJINpZp3NBCRkCcTv6mqT0cpUCJrbJ4Gj44i0Js1T9qKX4xcSkq6szCdEZ73BMFj9eHmBU6OkhmP2gTNmNnScIJjL0kTWhDF4eJLFEpC05buZUH6OV0JA9iCuS8DwygUEBGNpkKzgKpCRPDFTa1kiBgpcYAz64jQGJxDdqg9aGGuLqsl45IPQkYxs9SKOJ0DVx4CchI0TXFlYZDx+a0DEckJBGSeBUFjvEgOoe3uehT88d3VdqxvGBwECOq1gK2VntnbPBQkEJ0C2CbgoXJhiYgCr1gVw8KFmgsUEJEEzipt0ebQG0rQ6wTIs3BWKAKuoc3+Ucs6BuawIBmSvxF4wBgjwiFq0k2tBTMkVul8QAxWtfEuO0EPORKCIkx5pOjL3twZ9hAVA8UuEEonVu8FcV0bIYq06sm/WwIQj188Ja8/7KjndM0xoISoHMYab1cOS3DnWhS/od44EBk/MMnon4yDa5svb/AU8VileBWC4s5J4iL4ZarhIa48JoaN4UJxXKir3uGEnwk5MkqC44g757CGL3qlqOo0rSIRYIB/DTar925EN8xVOKWu/kbXQVOYeWLSanYRmF2xtnIgZjURtmPZondrBp5ZIRlyhdVoze8EbDAUU2oV2uYJzKluOd8rHGFqGqkMpeW/wuubs0vg=";

const HYBRID8_KS4_VECTOR: &str = "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";

fn hybrid6_key() -> Vec<u8> {
    decode(HYBRID6_PRIVATE_KEY)
}

#[test]
fn decrypts_dotnet_hybrid_single_recipient_vector() {
    // Vector 6 — the same KeySource-3 bytes HybridKnownAnswerVectorTests.cs pins on the .NET side.
    let plaintext = decrypt_bytes_hybrid(&decode(HYBRID6_KS3_VECTOR), &hybrid6_key())
        .expect("hybrid KeySource-3 vector (Vector 6) must decrypt");
    assert_eq!(plaintext, HYBRID6_PLAINTEXT);
}

#[test]
fn decrypts_dotnet_hybrid_multi_recipient_vector() {
    // Vector 8 — KeySource 4, target is the MIDDLE of three recipients.
    let plaintext = decrypt_bytes_hybrid(&decode(HYBRID8_KS4_VECTOR), &decode(HYBRID8_PRIVATE_KEY))
        .expect("hybrid KeySource-4 vector (Vector 8) must decrypt from the middle recipient");
    assert_eq!(plaintext, HYBRID8_PLAINTEXT);
}

#[test]
fn hybrid_tampering_is_detected() {
    let mut container = decode(HYBRID6_KS3_VECTOR);
    let last = container.len() - 1;
    container[last] ^= 0xFF; // flip a bit in the final content tag
    assert_eq!(
        decrypt_bytes_hybrid(&container, &hybrid6_key()),
        Err(PqError::Decryption)
    );
}

#[test]
fn hybrid_wrong_key_fails_closed() {
    // Zero the X25519 half so the classical agreement no longer matches: the KEK differs and the
    // wrap tag mismatches — a wrong key must be indistinguishable from tampering.
    let mut key = hybrid6_key();
    for b in key.iter_mut().take(32) {
        *b = 0;
    }
    assert_eq!(
        decrypt_bytes_hybrid(&decode(HYBRID6_KS3_VECTOR), &key),
        Err(PqError::Decryption)
    );
}

#[test]
fn hybrid_bad_key_length_is_format_error() {
    assert!(matches!(
        decrypt_bytes_hybrid(&decode(HYBRID6_KS3_VECTOR), &[0u8; 100]),
        Err(PqError::Format(_))
    ));
}

#[test]
fn passphrase_decrypt_rejects_hybrid_container() {
    // A hybrid container needs a private key, not a passphrase.
    assert!(matches!(
        decrypt_bytes(&decode(HYBRID6_KS3_VECTOR), b"whatever"),
        Err(PqError::Unsupported(_))
    ));
}
