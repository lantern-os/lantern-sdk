//! Rebuilds a `.lpkg` around a different manifest, deliberately skipping everything
//! `lantern-sdk build` checks. It is for negative tests: packages that are validly signed but
//! that no honest build would produce (`lantern-boot/scripts/binder-matrix.sh`).
//!
//! `resign <in.lpkg> <manifest-file> <out.lpkg> <seed-byte-hex | keep>`
//!
//! The signing key is 32 repeats of the seed byte, so this only ever makes demo-key packages.
//! `keep` retains the original signature, which then no longer matches.

use lantern_crypto::signing::SigningKey;
use lantern_sdk::package::{decode_package, encode_package, sign_package};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, manifest, output, seed] = args.as_slice() else {
        return Err("usage: resign <in.lpkg> <manifest-file> <out.lpkg> <seed-byte-hex | keep>".into());
    };
    let package = std::fs::read(input).map_err(|e| format!("{input}: {e}"))?;
    let package = decode_package(&package).map_err(|_| format!("{input}: not a package"))?;
    let manifest = std::fs::read(manifest).map_err(|e| format!("{manifest}: {e}"))?;
    let signature = if seed == "keep" {
        package.signature
    } else {
        let seed = u8::from_str_radix(seed, 16).map_err(|e| format!("{seed}: {e}"))?;
        sign_package(&manifest, &package.cwasm_bytes, &SigningKey::from_random_bytes([seed; 32]))
    };
    let lpkg = encode_package(&manifest, &package.cwasm_bytes, &signature);
    std::fs::write(output, lpkg).map_err(|e| format!("{output}: {e}"))
}
