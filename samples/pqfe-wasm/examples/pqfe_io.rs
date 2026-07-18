//! Native file-in/file-out driver for the Rust `.pqfe` core, used by the cross-implementation
//! interop CI job (`.github/workflows/ci.yml`, `interop`): the .NET side and this binary
//! round-trip fresh random payloads in both directions every run. Passphrase comes from the
//! `PQFE_PASS` environment variable. Exit codes mirror the .NET CLI (sysexits.h).
//!
//! Commands:
//!   pqfe_io encrypt        <in> <out>                 passphrase, $PQFE_PASS
//!   pqfe_io decrypt        <in> <out>                 passphrase, $PQFE_PASS
//!   pqfe_io keygen-hybrid  <pubfile> <privfile>       raw key bytes (1216 / 2432)
//!   pqfe_io encrypt-hybrid <in> <out> <pub> [pub...]  one or more recipient public keys
//!   pqfe_io decrypt-hybrid <in> <out> <priv>          recipient private key

use std::{env, fs, process::exit};

use pqfe_wasm::{
    decrypt_bytes, decrypt_bytes_hybrid, encrypt_bytes, encrypt_bytes_hybrid_multi,
    generate_hybrid_keypair,
};

fn read(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|e| {
        eprintln!("error: reading {path}: {e}");
        exit(66);
    })
}

fn write(path: &str, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|e| {
        eprintln!("error: writing {path}: {e}");
        exit(74);
    });
}

fn passphrase() -> String {
    match env::var("PQFE_PASS") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            eprintln!("error: environment variable 'PQFE_PASS' is empty or unset");
            exit(64);
        }
    }
}

fn die_decrypt(e: impl std::fmt::Debug) -> ! {
    eprintln!("error: decryption failed: {e:?}");
    exit(65);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let usage = || -> ! {
        eprintln!(
            "usage: pqfe_io <encrypt|decrypt|keygen-hybrid|encrypt-hybrid|decrypt-hybrid> ...\n\
             (passphrase in $PQFE_PASS for the passphrase commands)"
        );
        exit(64);
    };
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "encrypt" if args.len() == 4 => {
            write(
                &args[3],
                &encrypt_bytes(&read(&args[2]), passphrase().as_bytes()),
            );
        }
        "decrypt" if args.len() == 4 => {
            match decrypt_bytes(&read(&args[2]), passphrase().as_bytes()) {
                Ok(plaintext) => write(&args[3], &plaintext),
                Err(e) => die_decrypt(e),
            }
        }
        "keygen-hybrid" if args.len() == 4 => {
            let (public_key, private_key) = generate_hybrid_keypair();
            write(&args[2], &public_key);
            write(&args[3], &private_key);
        }
        "encrypt-hybrid" if args.len() >= 5 => {
            let input = read(&args[2]);
            let public_keys: Vec<Vec<u8>> = args[4..].iter().map(|p| read(p)).collect();
            let refs: Vec<&[u8]> = public_keys.iter().map(|k| k.as_slice()).collect();
            let container = encrypt_bytes_hybrid_multi(&input, &refs).unwrap_or_else(|e| {
                eprintln!("error: hybrid encryption failed: {e:?}");
                exit(65);
            });
            write(&args[3], &container);
        }
        "decrypt-hybrid" if args.len() == 5 => {
            let private_key = read(&args[4]);
            match decrypt_bytes_hybrid(&read(&args[2]), &private_key) {
                Ok(plaintext) => write(&args[3], &plaintext),
                Err(e) => die_decrypt(e),
            }
        }
        _ => usage(),
    }
}
