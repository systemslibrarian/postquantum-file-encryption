//! Native file-in/file-out driver for the Rust `.pqfe` core, used by the cross-implementation
//! interop CI job (`.github/workflows/ci.yml`, `interop`): the .NET CLI and this binary
//! round-trip fresh random payloads in both directions every run. Passphrase comes from the
//! `PQFE_PASS` environment variable. Exit codes mirror the .NET CLI (sysexits.h).

use std::{env, fs, process::exit};

use pqfe_wasm::{decrypt_bytes, encrypt_bytes};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: pqfe_io <encrypt|decrypt> <input> <output>   (passphrase in $PQFE_PASS)");
        exit(64);
    }

    let passphrase = match env::var("PQFE_PASS") {
        Ok(value) if !value.is_empty() => value,
        _ => {
            eprintln!("error: environment variable 'PQFE_PASS' is empty or unset");
            exit(64);
        }
    };

    let input = fs::read(&args[2]).unwrap_or_else(|e| {
        eprintln!("error: reading {}: {e}", args[2]);
        exit(66);
    });

    let output = match args[1].as_str() {
        "encrypt" => encrypt_bytes(&input, passphrase.as_bytes()),
        "decrypt" => match decrypt_bytes(&input, passphrase.as_bytes()) {
            Ok(plaintext) => plaintext,
            Err(e) => {
                eprintln!("error: decryption failed: {e:?}");
                exit(65);
            }
        },
        other => {
            eprintln!("error: unknown command: {other}");
            exit(64);
        }
    };

    fs::write(&args[3], output).unwrap_or_else(|e| {
        eprintln!("error: writing {}: {e}", args[3]);
        exit(74);
    });
}
