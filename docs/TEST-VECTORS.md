# Known-Answer Test Vectors — `.pqfe` v2

These fixed vectors pin the on-disk format. Any independent implementation that decrypts them
to the stated plaintext is reading the container correctly; any change to the format or
cryptography that breaks them is a **deliberate, breaking change** (bump `FormatVersion` and
regenerate).

They are exercised by:

- **.NET** — `tests/.../KnownAnswerVectorTests.cs` and `CrossImplementationTests.cs`
- **Rust → WASM** — `samples/pqfe-wasm/tests/vectors.rs`

The two implementations validate each other: the Rust core decrypts the .NET-produced vectors,
and the .NET library decrypts the Rust-produced vector. CI runs both suites on every change.

All containers are shown as **Base64**. See [FILE-FORMAT.md](FILE-FORMAT.md) for the byte layout.
The same bytes are committed as **ready-to-use binary artifacts** in
[`test-vectors/`](../test-vectors/) at the repository root, with pinned SHA-256 sums and a
30-second verification walkthrough — no decoding required.

---

## Vector 1 — passphrase, PBKDF2-HMAC-SHA256

| Field | Value |
| --- | --- |
| Key source | passphrase |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 100,000 |
| Salt length | 16 bytes |
| Chunk size | 1024 bytes |
| Passphrase (UTF-8) | `test-vector-passphrase` |
| Expected plaintext | `PostQuantum.FileEncryption known-answer vector v2.` |

```
UFFGRQIBAQAAAAQAJo6h8gAWARBX1MFqqxklHk56hMpD/FOOAAGGoAEAAAAyj/fP3REMAehh9VkK47SfhqQqgW68lRjDYDqIhW+b+6ytzaFAGCYaqA5JyaVkf24z17nYMoDST2h5xVdPtgEB23Fj
```

## Vector 2 — passphrase, Argon2id

| Field | Value |
| --- | --- |
| Key source | passphrase |
| KDF | Argon2id (version 0x13) |
| Memory | 8192 KiB (8 MiB) |
| Iterations (passes) | 1 |
| Parallelism (lanes) | 1 |
| Salt length | 16 bytes |
| Chunk size | 1024 bytes |
| Passphrase (UTF-8) | `test-vector-passphrase` |
| Expected plaintext | `PostQuantum.FileEncryption known-answer vector v2.` |

```
UFFGRQIBAQAAAAQAS7aXNQAbAhCZBPTffR0AgJ7we1bozxQOAAAgAAAAAAEBAQAAADJOzagbj5vUN9WHVWy1t7KN/pG9O5ab04z0IO4xyV5vRMxDN2TsXQGStrNyW5eC77skRpx0WhB0BC6SxsnfnwherIM=
```

> The Argon2id vector matters cross-implementation: the .NET library (Konscious) and the Rust
> core (RustCrypto `argon2`) must produce **identical** Argon2id output for the same parameters
> — and they do.

## Vector 3 — produced by the Rust/WASM core, read by .NET

| Field | Value |
| --- | --- |
| Produced by | `samples/pqfe-wasm` (browser core) |
| Key source | passphrase |
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 600,000 |
| Chunk size | 65536 bytes |
| Passphrase (UTF-8) | `cross-impl-passphrase` |
| Expected plaintext | `Encrypted by the Rust/WASM core, decrypted by .NET.` |

```
UFFGRQIBAQAAAQAAikYbOgAWARDAQkJamtz3O4G2K80C5ZtbAAknwAEAAAAzWyXs57NvJnc4YxIUzCNJW+xE9IyXeQ4Tt5MFvTwMC27G/Dry6A/4bdieeZmpXSTcNsrumLpyzzeTILIOh5eGh+nR9g==
```

---

## Vector 4 — detached signature (`.sig` sidecar v1, verify-only)

Pins the [SIGNATURE-FORMAT.md](SIGNATURE-FORMAT.md) sidecar: layout, domain-separation
context, and SHA-512 pre-hash. ML-DSA signing is **hedged** (randomized per FIPS 204), so the
vector is verify-only — implementations must verify it, not reproduce it byte-for-byte.
Exercised by `tests/.../SigningKnownAnswerVectorTests.cs`.

| Field | Value |
| --- | --- |
| Algorithm | Ed25519 + ML-DSA-65 hybrid (AlgorithmId 1) |
| Signed message (UTF-8) | `PostQuantum.FileEncryption.Signing known-answer vector v1.` |
| Public key | `Ed25519-pk(32) ‖ ML-DSA-65-pk(1952)`, Base64 below |
| Signature | 3,379-byte sidecar, Base64 below |

Public key:

```
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
```

Signature:

```
UFFTRwEByYLFVgX5YN338ctK45WQZzRf7A/67jJ0eq9g+KrpzwwtQjQAqU3CJuXeor5j2fPdCG/AqpQFPuu3y7iil7SdCQPtFyrhH4eKz1HTYdehISVygrnVrO9QA1KJjrX/lmaIkoLuaEvTP6T7JUokU32fBKU3o878Z25GwcVDhB3CCLkkgrtb10UTb9Y1jT93ixKdT6F/Gnh36+3wv7WNx8+u+PT2SUmIUlVvXghoOT/1H4Sx7MKyhXnIYoNg7eO4VhaY2TT2/t1LoB13wpp5rM4ifOoHubD5vszCrSzZnUU9tUrP6pVqdgnvwr7PwubXchTl+ssIWkY9ecOzCvTY0Xvq0XIbh41A/YYA16QdJXYVh9Au45B3MHe5xsqlhdi5cf3sBYe2q4gGadoQQVNNfyrKcjDBnD8keIoS018hQ0Kv503eqdh0AIKG9SmoXFZY8I4TFtqW5o4WB3/ToXpmxY7av+ywYXD/cQN29QZIK4p0P5BH4WAfQaSy2fqONaJfKCKdd+p86fMxY3paAs0IQ96fvpVRnAiSBKwq/0QXH8gy51X/HNHVo3tMAV1ipsQVIPgFV3NCLG2ZPZ3Y0OQ1vzwPwDUIDkC+uzlYb4OzFB//aj4BmTpFye6+K518wWu3CccP69dyNj1CJgmnYibk80bNrwch395XheRkYNJ3Ue413ePnjhPsg5963twhlaI7xOsvuF3rlTwAvyBWE1GCg9skl31TM8/GhO0EDzy19TYdqZsSAoS2bvB5joODnFqkU3G6oGm7uSV4u04jnA4bkTmRA0hJgURiPB+BWdtLcZ7ZdMoOp8bZer13n+ZoY1slWROFrpRjTJKUGCBS/vK7cP6+Jl15eW52DNsDg+q4xw19bZzqabiS99AoZI8znve2dqJ8kSTWHT7MzXfOiEOjbV4vTwGsHSoY/R48U1K88xzGCDJ+DwAEZAlP4Q0dh3NNDQf6pQbp3J4kGNmgsKYjV0UvlxDJvEP0z1TZS38sdzfpqnVHZbnMh5WI91AaIRyApT7Ux78PgDDkm9ldZE5OU4AGD1neN1PRdmSt6RZHhSpuIdvVCN3WB1YQDw/SPHicuYgXoxWq8aVV0TlH2VcU4afGv/BPNQOwLSkJgtelHr9rwfwWCAtV6joh8q3Sc/heNHtrpirnh+xqMO5+G3si2lB97X7tX3/MkSsRRgMKJOF0XszaLczHDbRzvDgoDqg1E38kU5omL14SZE1Vb5pxWulzMMwo3K8x9B21XJoDO4AdCD504VTLEdJjT+PZKosTv7p2+q4gNp4tWFYOo1QzGPv8gvUo0bbN8JL69ZnpwSrgI7oWMZeSwrHagc82Adyk/AM+ibNAw5l3M+LtDWbYm3ngqjDQBOwMk8+rbKCl7Vwq8DoXk75HIW9AKkWlyzL/GTmgQWkKWFbQCLnn4Phd7cCn9XQCvwDsS2z8o2baKIQWfX9eMDW8e6tW8h4sY3DYvLQZT9Hi+h44Z4qH6+vRelufIJeGTYdjm7PRUA4xRGfDkt0Jiuq/fV8u+Iy6MzqggbggKA5SJ66JsP8GblU0ThSkrZEMKwzzvO4vOcKVONPkfAmd0C22rVtozWqsdF9v/qSYmk7LVBglfJ5pOm9aAE+PBRZ3epbmcauaJptv8KHTfa9BFwLqhggaZ4cylgXwIB3A/0gHfWMXzQjmHrZfkWk5n4v+FFJbw3+5S4Op23rfGSBnimyD4ZThlGNMa2qwk6DZkZftGx7amsUBUCDLLY3oDW63iLUdekkblpwBuEH5sqP2xxGsb1tPoFkttxTG8MQTTAFqWbVCfPmfSeeYuKfMM/NfszBkP/u0v5Ol2HQOTcATZcllMK8kYygqjJUT2/kkjr9+2WwsQfnNXtL2xtesBrev3a1a3tEIgNf/QbAS6LKtwiFgYzbt1TVnnWhyAAnUVrkugdG0NptRg8yLDaH3R6jQSrk8rlNNJ1+Juj0m3GGSEBUAa8f+0hzfK4ozmy7+nLS6QIA9fmf4dnrWWHk6r08VhvsGTpRVUSlJZ2ljfv15spL9yP04eD3WZiUfGQtX1Qtm6j9i/FxvKEknsfUiA3B1Anfstl5zIT7dyLY9ou7fgJjnfzTa9lk6X5mEOy8iYrA7A++sGW/oMMFciQghECEPRPPi9uVX+uYTLBs9tc+3U/u6BfWR+UhL5FznQsKmKmpbwgWjFzH7tNqFuRc0qc95YoP9xwQk253/IxotqcTMzcJQ2nf3IMR1J+2XjNOg1dXjFPCU72bK2t0IQ5slXQgU198kXt6mXrUy8Uxy8q01jPXLS0kz8xhNO6ypdYLeg6TDjd+gf3YTxoJhl3WwX+XwA9BOTfZxDUDRgAUSUCO9YjAvsnidCkKSwNdfXHytSQwV6FLYEdIux2xfMtAiGj5wa8tRMKRDKbYh33DpWGXI1JAQjqgka/0DsfHp+zbAHwadbSlzOdubIPZlWNdAXyaWtNdcHCHw2beYC1yEged34WtORTdRimFCPWMWarwDn8OCVFSRTIhkr+RdeMraelNdaQAY3vMUoBfv5czgIEEsGuC3kH42b5/WzDvz74+khObvXAHaxvMF68Mnkm5lnYaDcoU/Go+FdOSchISFGlYnGkpM3aXGzhGZIjb+INRCmfziy3oW3TWujWVpDjvKMC29w0C2lw/JdHercdwNgavA7+CWXqLCaj0RNH1PBOXW8K/jitbNIXrpTRfwXkk80YWEczVYoEblDRI8PMPmu58SpcHycgy8gdkCzSQdG8bSuPI9jzE0aFXIIt2i3fXwOXULqr1wCnEJeLs8lgNdSuDBczIUcTZBPO02zO9FPOKoh3aHmjiUp9Ud8VXjI7kc/kzMAKAU1tBHQFjVmjEHSMxc3qjPomEAyGQVySfuXFn1WpcqmeFE02ysKynbLKa5In8Jo7NEERatgZzUFnjT7DkQlptn1r7/tWxrh+eyBAoSmPIBsOgvjkErAnXaAmgjFA9TKfItkELoNBSFy8pwGnsjp3mw/tvx3Brptx0P6T0wUruyV/ovud96TmAXYwpcrTb7ltODmVEqxjjE1db+CBX8zIbBLt0p14zWcAcn7JnPbATWnSo2/9/kG30iCjuEV6Vb78v6fx2o7cZBKCDsLPopnJET4MZth4TwH8Z5SHEHtDLKiD1XlFp9xLuMTdMdCZoszC4D0uaBcDUbG7Rm9U4GiJpE8dSt8r3sIye1n+c3z9jMM71vcy36+u+sxyGYAYQBj8fPHQaHw3UbeUkLEa/1Pjtb+fA/q4UPqQvn1MJh+YbF/V8KViuSrHPvNsVa++T64tqQPowE9PhDBdElSOp+EFEvNXvK3n1kwUFVK+67w+/bzc3+6do27Ol/kWlLamvW11i36aiXmzOWeHRjwDhjPBP8nvj90Ic3/wlZjTtF6AqgbahSEhTZ+y3zTZ56evysF1GfjK6f4+W6NhKYdw+BvER/1r00LL+GlHjGs8UideJj5zioQpWe2hC9TGzcjL1BSM4asg95FW316q+K4fTvA+OSWww9UPDsO4WonyoP6FENBuSan2sMF88aG5TP85Nrxaq8OOY/Ua8YYYqMZP56H/tGJjxvbh4w6VI5ZPpElg96fWr/3PBLrXjIa0MZ7nFYYpZECTxrhM6xpUsIeLKc3Y6UtctI8VvcW1qaoRK8w9zotBecR/sxSkXmW6/EpstdiTnE5ulDdIMCEGNIq8J6wubomJ5v6XAf0B+LvaNnFEEsmitvGpZ8clELld02PBnOnYqMVK3SYwNU6o7bkH40POnX608iG9fkGdgHCIVEgrbJf2JheEth7ufF9twp/NUXQ/gsTToL7329KgSos1CyMVN8A0edm+lvbJRkpa5Q57CygK7IKQMxl9IOE1+3p9OQ6kKsGxfd3U3Sg+pm0pQBGdKqmVs55lOuwKUOSOyNGD44Y+KFKlpyg+Sa3zODqZqUxR5C2h36tvD7uHjIqs/K2RpJzq4mh6jGVMEEBP5P4xPCSu0hB9xSLJ2H4xHHgwDmegnVScAI5bOwey8PWwZsBhrLNSSkxHqZHoN3XPdn21CfmV4hw/YKRY+xqDj5pkw02MBdY3nq+m+mPYVlmL0+OxP+VXFw2LnNG4KeDhHE3M89YKO2JYHoIbsmzA4C3hbeeAAml5qM2lnfHMaWwITBHWOUhdaLr5fCCwKVcs8mmVhCqlX+I+3eXpf3Bfxd/iHXiTD6Epsb16Eqeob040MLGaJg1PFPiJGY8w0NdA1m9PCs/e88fjjYj8JfjyjWH+t5JVDblRClRbwTXjxKULjEYhG6cvtiMD7RnZsxNrcCqgfNaUz2WWjgw2P0kqEjBusDnsQp23f2Kgj7DHdrTCJNWfVw1r2ourSYKni3Q82TbpNQyFy/pceehlRLtqQ0efB7vRBTIwEavVKjkfNpwecsUv37Z8jQFqVOAVt3f6XUEGyptsvi5CEzUGWKzPNQUVelK2l8zPf7IycrM1ekwuQUJlZekaYAAAAAAAAAAAAAAAAAAAAAAAcOEhggJg==
```

---

## Vector 5 — `PQKF` encrypted key file (hybrid private key)

Pins the [KEY-FILE-FORMAT.md](KEY-FILE-FORMAT.md) framing: the `PQKF` magic and version,
the embedded `.pqfe` v2 passphrase container, and the authenticated `KeyType` binding. An
implementation reads it correctly when decryption with the passphrase yields
`0x01 ‖ ExpectedPrivateKey` — and when the *same* file, with the *same* passphrase, is
rejected by a signing-key importer (the type byte is inside the authenticated plaintext).
Exercised by `tests/.../KeyFileKnownAnswerVectorTests.cs`, and cross-validated by the Rust
core (`samples/pqfe-wasm/tests/vectors.rs`), which decrypts the embedded body as a plain v2
container — proving the framing adds nothing the other implementation needs to know beyond
this document. The key pair was generated solely for this vector and protects nothing.

| Field | Value |
| --- | --- |
| Framing | `PQKF` v1 |
| Body | `.pqfe` v2 passphrase container, Argon2id (8 MiB, 1 pass, 1 lane), 16-byte salt |
| Passphrase (UTF-8) | `key-file-vector-passphrase` |
| KeyType | `1` (hybrid recipient private key) |
| Expected key bytes | `X25519(32) ‖ ML-KEM-dk(2400)` = 2,432 bytes, Base64 below |

Key file:

```
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
```

Expected private key (`PqHybridPrivateKey.Export()` bytes):

```
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
```

---

## Vector 6 — hybrid recipient (X25519 + ML-KEM-768, decrypt-only)

The only vector that pins the hybrid combiner byte-exactly: the KeySource-3 wrap block
layout, the X25519 agreement + ML-KEM-768 decapsulation, the `HKDF-SHA256(ss_pq ‖
ss_classical)` KEK derivation ([HYBRID-COMBINER.md](HYBRID-COMBINER.md)), and the AES-256-GCM
key unwrap. Encryption is randomized (a fresh KEM encapsulation and ephemeral X25519 key per
container), so the vector is decrypt-only — implementations must decrypt it, not reproduce
it. Exercised by `tests/.../HybridKnownAnswerVectorTests.cs`. The key pair was generated
solely for this vector and protects nothing.

| Field | Value |
| --- | --- |
| Key source | `3` (hybrid recipient) |
| Recipient private key | `X25519(32) ‖ ML-KEM-dk(2400)` = 2,432 bytes, Base64 below |
| Expected plaintext (UTF-8) | `PostQuantum.FileEncryption hybrid recipient known-answer vector (X25519 + ML-KEM-768).` |

Recipient private key (`PqHybridPrivateKey.Export()` bytes):

```
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
```

Container:

```
UFFGRQIBAwAAAQAAbJ94MQSfAQRApwX6GPuwscQTlP7g05KlVuy/M0lS7//jpMdspyN6UiJyLux73Kx26roy6YKAHnxf/M03kxfMZBIgTKAEWyubzia26L60Z55pMt3vG2zzCSqJ6CwMfcEEAqbg6fyQii8aCByjGata8FTv42bTcA67O98YHiJEiuCwlLUBDaiUiVFtVU51giibidZC/GFbx4Xi+No4qR0wBeXDpCyI9EgJeumXJtpcjcQcxDauG/RzX+Pq1MpxCZw7sID7Dj2wLb6I/wn1/WGiHlwO4PkXf0FB7NH82+YyUDeww0ihS6vQ+JZeGAaULwfWeyb2eXT/OPLdcFr/cXpUMHzyzs4U8a2+C/hC5+GAP6f2R6+cLbNewJyHBhe7i6EOaDnJH+UkWFXl02t9jfM/iy1cAl0nkMICEgB7c7uVEQFkticzFL4/dUMShsbl6P0dKD0LWF8P8CSYnomqDOB7SewKBUTDZk+RsMJCgulK/V2a3Z57NbPbMnE12YKuemkNe68djbRzPQxdII610oFppQhArObbtv43Y64SlBrA13l/d6sTZBU7SxKYllV3B2G7An24ITVGtPZm1F3fSgjlr9UlbFztkR9LAIWJfYmmFsP6dNFDOzscrOtaPOCp0Nzd5j8/PJoPG89E6ozM0WWlRswmq55kKvrsEbplktQ7TxY4hie5IZPQa5q+YNANbxBz/ks5xUtMeEgAlEtDwJhEKlLt8oHTNQD4t/cUDR5iuTG1xECIfmi2g4vT4lZHtKY2Oa/H6KkZa4iJ51RAMVrmx6E2pKK7MJiNH9hR6KavrzpOpUH4ddHgO5vpWqN5uHWB2E2+fyDB+72Jj/mPeaiCfAulwPTv0jTp6Ni5RPhe/n0HK3GoXOB0Y2HFSIPzipxcPByBuXBWEdL0P3CtrAIRPIFgOIo9fxJmfwdBnIPU0SXlgaD4RxAbmbjyhmR0Xw7lihzORWu0U4AK3XKc64TOrwJlgdlPRUkAhQMIoO1VkiQtoC7BiITpSLRU/iLK+sZByy0FOdrah34OrPXXUZ5KJAU8/R11gL7yOKMk8xlg67OAZyw86xIINYDNF6q/xMxTYcqqy9w9/mqN1a7uPOFgcPJOnZZw5pCXLgeikqNWpbucUDqK5KchiU6nQZnFQHg2E7MxSgFayxGehSMGlif/ICXRl9JYX98Ov1RNdzzyaw9Q7XAVga3L6Mdu0XyRLnu2oeZeTV/tm5GR5+ish8Za6nBjOpcK8mdqwbtmQH3J6KUeog6t4uGngbnoCvTSHHj+WN7tL6EVsIHER4H3BT9XP+KIYmnSxzOkbO0RFhBps2dFSoMxFq2w0UKpW8ZcVJie+E/A1fW3SA0OgApV+/PkcmYBaurEsfVbAsaXpgCbxgviSpXyFfbbWZLXeJiWYANCVDeDad6d8MZxXSazLVJZOFf8W0uAlwf6djFmsowQ6MyK06dtkGIR926eeLt/lWIgcRawsIqy/MeOhfuPHtD+JMK3nijSwMmPeLT6JjxZvpxutNnoIaxbkSJv+lRqse1UTYZBKABzw80Tk2sHjgFVKbj6MRv1PnFPxQb/95NbcvvSUxFm+wEAAABWygDtr/evifS8gBJKj/O2k+GKMFzLToZcsXZ3ay6P64UH4p8fcrJix9J/Lbl7oQ3ELgXZFbEC2kBWu9UrJSvUkOAxdfHu9FVHoRuJqKlFwi2QdkP69z9sOAihwG427RV6tZ5O4C5x
```

---

## Vector 7 — multi-chunk passphrase container

Three frames (two full 1 KiB data frames + a final frame), so this vector pins what the
single-chunk vectors cannot: the per-chunk nonce counter (`prefix ‖ big-endian counter`) and
the per-chunk AAD chaining (`header ‖ counter ‖ frameType`). An implementation with a broken
counter round-trips its *own* output happily — but can never decrypt this fixed container.
Exercised by `tests/.../KnownAnswerVectorTests.cs` (which also verifies that swapping the two
equal-size data frames fails closed) and by the Rust core's `tests/vectors.rs`.

| Field | Value |
| --- | --- |
| Key source | passphrase |
| KDF | PBKDF2-HMAC-SHA256, 100,000 iterations |
| Chunk size | 1024 bytes |
| Passphrase (UTF-8) | `test-vector-passphrase` |
| Expected plaintext | 3,000 bytes; byte *i* is `(i * 31 + 7) & 0xFF` |

The container is pinned in both test suites (`MultiChunkVector` / `MULTICHUNK_VECTOR`); it is
omitted here for length — the source constants are the normative copies.

---

## Vector 8 — hybrid multi-recipient (X25519 + ML-KEM-768, KeySource 4, decrypt-only)

Pins the multi-recipient path that Vector 6 (single recipient) cannot: the KeySource-4 body
layout (`RecipientCount ‖ (Mode ‖ BlockLength ‖ block)*`, [FILE-FORMAT.md](FILE-FORMAT.md))
and the block scan that tries, and skips, a non-matching recipient block before reaching the
caller's. The container wraps one content key to **three** recipients; the pinned private key
is the **middle** one, so a passing decrypt proves the reader advanced past an earlier block
that was not its own. As with Vector 6, encryption is randomized, so the vector is
decrypt-only. Exercised by `tests/.../HybridMultiRecipientKnownAnswerVectorTests.cs` and,
cross-implementation, by the Rust core (`samples/pqfe-wasm/tests/vectors.rs`, `HYBRID8_*`) —
both pin the identical bytes. The key pairs were generated solely for this vector and protect
nothing.

| Field | Value |
| --- | --- |
| Key source | `4` (multiple recipients) |
| Recipients | 3 (hybrid, Mode 3); pinned key is recipient #2 of 3 |
| Recipient private key | `X25519(32) ‖ ML-KEM-dk(2400)` = 2,432 bytes |
| Expected plaintext (UTF-8) | `PostQuantum.FileEncryption hybrid known-answer vector v2.` |

The 2,432-byte private key and the ~3.6 KiB container are pinned as the normative copies in
the two test suites above (`PrivateKeyVector` / `ContainerVector` and `HYBRID8_PRIVATE_KEY` /
`HYBRID8_KS4_VECTOR`); they are omitted here for length.

---

## Vector 9 — inline ML-KEM-768 recipient (KeySource 2, deprecated, decrypt-only)

Pins the deprecated inline recipient path byte-exactly: the KeySource-2 wrap layout
(`KemId ‖ C ‖ KemCiphertext ‖ WrapNonce ‖ WrapTag ‖ WrappedKey`), the ML-KEM-768
decapsulation, the `HKDF-SHA256` KEK derivation, and the AES-256-GCM key unwrap — the one
key-establishment path no other vector covered (its randomized round-trip tests self-skip on
hosts without platform ML-KEM). Encryption is randomized, so the vector is decrypt-only.
Generated once on a Linux host with OpenSSL 3.5 (platform ML-KEM) and frozen. The artifacts
are committed files rather than inline Base64, hash-pinned by `VectorArtifactTests` and
`test-vectors/SHA256SUMS`; the decrypt is exercised by
`tests/.../RecipientKnownAnswerVectorTests.cs` wherever `PqKeyPair.IsSupported`. The key pair
was generated solely for this vector and protects nothing. The Rust core does not implement
this mode, so the vector is not in the cross-implementation manifest.

| Field | Value |
| --- | --- |
| Key source | `2` (inline ML-KEM-768 recipient, deprecated `PQFE001`/`PQFE002`) |
| Container | [`test-vectors/mlkem-recipient.pqfe`](../test-vectors/mlkem-recipient.pqfe), SHA-256 `02d3614753172b9eb9690cb35325794fac5e9a67faf5f81377b708725ed00503` |
| Recipient private key | [`test-vectors/mlkem-recipient.key`](../test-vectors/mlkem-recipient.key) (`PqRecipientPrivateKey.Export()`, 2,400 bytes), SHA-256 `ff8599053e453e11aad3149736c7094484a39cf8d982ab9ab285956889ca5444` |
| Expected plaintext (UTF-8) | `PostQuantum.FileEncryption inline ML-KEM-768 recipient known-answer vector.` |

---

## How to verify

```bash
# .NET
dotnet test --filter "FullyQualifiedName~KnownAnswerVector|FullyQualifiedName~CrossImplementation"

# Rust
cd samples/pqfe-wasm && cargo test
```

## Negative vectors and the frozen leniencies — the committed corpus

Implementations must also **reject** corrupted input, and must **accept** exactly the inputs the
frozen v2 reader accepts — including its documented leniencies. Both are pinned as a committed,
machine-readable corpus at [`test-vectors/`](../test-vectors/), indexed by
[`test-vectors/manifest.json`](../test-vectors/manifest.json) and run in both implementations by
the .NET `ConformanceManifestTests` and the Rust core's `tests/conformance.rs`.

Each manifest entry declares the outcome a conforming reader must produce:

- **`reject-format`** — a structural error (`PqFormatException` / `PqError::Format`): bad magic,
  unsupported version, unknown AEAD or key source, out-of-range chunk size, or an out-of-range
  PBKDF2 iteration count (range-checked before any KDF work).
- **`reject-decryption`** — an authentication failure (`PqDecryptionException` /
  `PqError::Decryption`): a wrong passphrase, any flipped header/ciphertext/tag byte, or a
  truncation (dropped tag or any proper prefix). The error type stays consistent across these so
  the reader is not an oracle.
- **`accept`** — the positive vectors above, plus the **lenient** vectors that pin the frozen v2
  reader corners from [CONFORMANCE.md](CONFORMANCE.md) §2.2: a nonzero reserved `Flags` byte,
  trailing bytes in passphrase `KeyParams`, trailing bytes after the final frame, and a block
  past a multi-recipient count. A `1.x` reader must accept these; they are format-v3 candidates.

The negatives are deterministic single mutations of Vector 1, so any implementer can reproduce
and inspect them. Regenerate the corpus only as part of a deliberate major-version format
revision (`PQFE_REGEN_VECTORS=1`), never to make a failing test pass.

---

*To God be the glory — 1 Corinthians 10:31.*
