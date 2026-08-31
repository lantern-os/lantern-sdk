//! `lantern-sdk` CLI (feature `build`).
//!
//! ```text
//! lantern-sdk build --manifest <toml> --component <wasm> --out <lpkg>
//!                   [--seed <64-hex> | --ephemeral]
//! ```
//!
//! Validates the manifest, checks the component imports exactly what the manifest
//! declares, AOT-compiles + signs, and writes `<out>` (the `.lpkg` package) plus
//! `<out>.pub` (the Ed25519 verifying key, hex — a verifier needs it).

use std::process::ExitCode;

use lantern_crypto::signing::{SigningKey, SEED_LEN};
use lantern_sdk::build::build;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("lantern-sdk: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => {}
        Some("--help" | "-h") | None => {
            print_usage();
            return Ok(());
        }
        Some(other) => return Err(format!("unknown subcommand `{other}` (try `build`)")),
    }

    let (mut manifest, mut component, mut out, mut seed_hex, mut ephemeral) =
        (None, None, None, None, false);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--manifest" => manifest = args.next(),
            "--component" => component = args.next(),
            "--out" => out = args.next(),
            "--seed" => seed_hex = args.next(),
            "--ephemeral" => ephemeral = true,
            other => return Err(format!("unknown flag `{other}`")),
        }
    }
    let manifest = manifest.ok_or("--manifest <path> is required")?;
    let component = component.ok_or("--component <path> is required")?;
    let out = out.ok_or("--out <path> is required")?;

    let key = match (seed_hex, ephemeral) {
        (Some(_), true) => return Err("--seed and --ephemeral are mutually exclusive".into()),
        (Some(hex), false) => SigningKey::from_random_bytes(parse_seed(&hex)?),
        (None, true) => SigningKey::from_random_bytes(os_seed()?),
        (None, false) => return Err("one of --seed <64-hex> or --ephemeral is required".into()),
    };

    let manifest_toml =
        std::fs::read_to_string(&manifest).map_err(|e| format!("reading {manifest}: {e}"))?;
    let component_wasm =
        std::fs::read(&component).map_err(|e| format!("reading {component}: {e}"))?;

    let built = build(&manifest_toml, &component_wasm, &key).map_err(|e| e.to_string())?;

    std::fs::write(&out, &built.lpkg).map_err(|e| format!("writing {out}: {e}"))?;
    let pub_path = format!("{out}.pub");
    std::fs::write(&pub_path, hex(&built.verifying_key)).map_err(|e| format!("writing {pub_path}: {e}"))?;

    eprintln!(
        "lantern-sdk: built {} {} → {out} ({} bytes), key → {pub_path}",
        built.manifest.app.name,
        built.manifest.app.version,
        built.lpkg.len(),
    );
    Ok(())
}

fn print_usage() {
    eprintln!(
        "lantern-sdk build --manifest <toml> --component <wasm> --out <lpkg> [--seed <64-hex> | --ephemeral]"
    );
}

fn parse_seed(hex: &str) -> Result<[u8; SEED_LEN], String> {
    let hex = hex.trim();
    if hex.len() != SEED_LEN * 2 {
        return Err(format!("--seed must be {} hex chars", SEED_LEN * 2));
    }
    let mut seed = [0u8; SEED_LEN];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| "--seed is not hex")?;
    }
    Ok(seed)
}

fn os_seed() -> Result<[u8; SEED_LEN], String> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").map_err(|e| format!("/dev/urandom: {e}"))?;
    let mut seed = [0u8; SEED_LEN];
    f.read_exact(&mut seed).map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(seed)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
