# API Documentation

The public types of **PostQuantum.FileEncryption**, generated from the library's XML docs.

Start here:

- `PqFileEncryptor` — encrypt files, streams, and in-memory buffers.
- `PqFileDecryptor` — decrypt them, fail-closed (including `DecryptAtomicAsync`).
- `PqEncryptionOptions`, `PqKdf` — configuration and key-derivation choice.
- `PqProgress` — progress reporting.

Experimental (ML-KEM recipient mode, `PQFE001`): `PqKeyPair`, `PqRecipientPublicKey`,
`PqRecipientPrivateKey`.
