//! RFC-0015/ADR-0020 SDK v0 tests.

use crate::manifest::{parse, ManifestError};
use crate::{plan::GrantPlan, wit};

const GOOD: &str = r#"
[app]
name    = "receipt-signer"
version = "0.3.1"

[[keystore.key]]
role          = "receipt-signing"
ops           = ["sign"]
justification = "Signs each exported receipt."

[[keystore.key]]
role          = "vault-at-rest"
ops           = ["encrypt", "decrypt"]
justification = "Encrypts the local archive."

[[filesystem.file]]
role          = "config"
ops           = ["read"]
justification = "Reads its config at startup."

[monotonic-clock]
justification = "Stamps each receipt with a monotonic sequence number."
"#;

// -------------------------------------------------------------------------------------
// manifest parsing + validation
// -------------------------------------------------------------------------------------

#[test]
fn parses_a_full_manifest() {
    let m = parse(GOOD).unwrap();
    assert_eq!(m.app.name, "receipt-signer");
    assert_eq!(m.app.version, "0.3.1");

    assert_eq!(m.keystore.len(), 2);
    assert_eq!(m.keystore[0].role, "receipt-signing");
    assert_eq!(m.keystore[0].ops, ["sign"]);
    assert_eq!(m.keystore[1].role, "vault-at-rest");
    assert_eq!(m.keystore[1].ops, ["encrypt", "decrypt"]);

    assert_eq!(m.filesystem.len(), 1);
    assert_eq!(m.filesystem[0].role, "config");
    assert_eq!(m.filesystem[0].ops, ["read"]);

    assert!(m.monotonic_clock.is_some());
}

#[test]
fn a_minimal_manifest_declaring_nothing_is_valid() {
    let m = parse("[app]\nname = \"bare\"\nversion = \"1.0.0\"\n").unwrap();
    assert!(m.keystore.is_empty() && m.filesystem.is_empty() && m.monotonic_clock.is_none());
}

fn err(src: &str) -> ManifestError {
    parse(src).expect_err("expected a validation error")
}

#[test]
fn missing_app_is_rejected() {
    assert!(matches!(err("[monotonic-clock]\njustification = \"x\"\n"), ManifestError::MissingApp));
}

#[test]
fn a_bad_app_name_is_rejected() {
    let e = err("[app]\nname = \"Receipt Signer\"\nversion = \"1.0.0\"\n");
    assert!(matches!(e, ManifestError::BadAppField { field: "name", .. }));
}

#[test]
fn an_unknown_interface_is_rejected() {
    let e = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[[network.socket]]\nrole=\"x\"\nops=[\"connect\"]\njustification=\"y\"\n");
    assert!(matches!(e, ManifestError::UnknownInterface(n) if n == "network"));
}

#[test]
fn an_unknown_op_is_rejected() {
    let e = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[[keystore.key]]\nrole=\"k\"\nops=[\"sign\",\"exfiltrate\"]\njustification=\"y\"\n");
    assert!(matches!(e, ManifestError::UnknownOp { op, .. } if op == "exfiltrate"));
}

#[test]
fn empty_ops_is_rejected() {
    let e = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[[keystore.key]]\nrole=\"k\"\nops=[]\njustification=\"y\"\n");
    assert!(matches!(e, ManifestError::BadResourceEntry { why, .. } if why.contains("empty")));
}

#[test]
fn a_duplicate_role_is_rejected() {
    let e = err(concat!(
        "[app]\nname=\"a\"\nversion=\"1.0.0\"\n",
        "[[keystore.key]]\nrole=\"k\"\nops=[\"sign\"]\njustification=\"y\"\n",
        "[[keystore.key]]\nrole=\"k\"\nops=[\"encrypt\"]\njustification=\"z\"\n",
    ));
    assert!(matches!(e, ManifestError::DuplicateRole { role, .. } if role == "k"));
}

#[test]
fn a_missing_justification_is_rejected() {
    let e = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[[keystore.key]]\nrole=\"k\"\nops=[\"sign\"]\n");
    assert!(matches!(e, ManifestError::MissingField { field, .. } if field == "justification"));
}

#[test]
fn an_empty_or_oversized_justification_is_rejected() {
    let blank = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[monotonic-clock]\njustification=\"   \"\n");
    assert!(matches!(blank, ManifestError::BadJustification { .. }));

    let long = format!(
        "[app]\nname=\"a\"\nversion=\"1.0.0\"\n[monotonic-clock]\njustification=\"{}\"\n",
        "x".repeat(281)
    );
    assert!(matches!(err(&long), ManifestError::BadJustification { .. }));
}

#[test]
fn an_unexpected_key_is_rejected() {
    let link = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[monotonic-clock]\njustification=\"y\"\nprecision=\"high\"\n");
    assert!(matches!(link, ManifestError::UnknownKey { key, .. } if key == "precision"));

    let res = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[[keystore.key]]\nrole=\"k\"\nops=[\"sign\"]\njustification=\"y\"\npriority=1\n");
    assert!(matches!(res, ManifestError::UnknownKey { key, .. } if key == "priority"));
}

#[test]
fn wrong_shape_for_an_interface_is_rejected() {
    // keystore is resource-scoped; giving it a bare `[keystore]` table is a shape error.
    let e = err("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[keystore]\njustification=\"y\"\n");
    assert!(matches!(e, ManifestError::UnknownKey { .. } | ManifestError::ShapeMismatch { .. }));
}

#[test]
fn not_toml_is_rejected() {
    assert!(matches!(err("this is not = = toml"), ManifestError::Toml(_)));
}

// -------------------------------------------------------------------------------------
// wit generation
// -------------------------------------------------------------------------------------

#[test]
fn declared_imports_are_exactly_the_declared_interfaces_sorted() {
    let m = parse(GOOD).unwrap();
    assert_eq!(
        wit::declared_imports(&m),
        [
            "lantern:host/filesystem@0.1.0",
            "lantern:host/keystore@0.1.0",
            "lantern:host/monotonic-clock@0.1.0",
        ]
    );

    let just_clock = parse("[app]\nname=\"a\"\nversion=\"1.0.0\"\n[monotonic-clock]\njustification=\"y\"\n").unwrap();
    assert_eq!(wit::declared_imports(&just_clock), ["lantern:host/monotonic-clock@0.1.0"]);
}

#[test]
fn generated_world_imports_exactly_the_declared_interfaces() {
    let m = parse(GOOD).unwrap();
    let world = wit::generate_world(&m);
    for import in wit::declared_imports(&m) {
        assert!(world.contains(&format!("import {import};")), "missing {import}");
    }
    // nothing undeclared
    assert!(!world.contains("wasi:"));
    assert!(world.contains("package receipt-signer:app;"));
}

// -------------------------------------------------------------------------------------
// plan
// -------------------------------------------------------------------------------------

#[test]
fn the_plan_numbers_slots_in_declaration_order() {
    let GrantPlan { keystore, filesystem, monotonic_clock, .. } = parse(GOOD).unwrap().plan();
    assert_eq!(keystore.iter().map(|r| r.slot).collect::<Vec<_>>(), [0, 1]);
    assert_eq!(keystore[0].role, "receipt-signing");
    assert_eq!(keystore[1].role, "vault-at-rest");
    assert_eq!(filesystem[0].slot, 0);
    assert_eq!(filesystem[0].ops, ["read"]);
    assert!(monotonic_clock.is_some());
}

// -------------------------------------------------------------------------------------
// package signing
// -------------------------------------------------------------------------------------

mod package {
    use crate::package::{package_digest, sign_package, verify_cwasm, verify_package, PackageError};
    use lantern_crypto::hash;
    use lantern_crypto::signing::{SigningKey, SEED_LEN};

    const MANIFEST: &[u8] = b"[app]\nname = \"x\"\nversion = \"1.0.0\"\n";
    const CWASM: &[u8] = b"pretend this is a .cwasm";

    #[test]
    fn a_valid_signature_verifies_both_ways() {
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let sig = sign_package(MANIFEST, CWASM, &key);
        verify_package(MANIFEST, CWASM, &key.verifying_key(), &sig).unwrap();
        verify_cwasm(hash::hash(MANIFEST).as_bytes(), CWASM, &key.verifying_key(), &sig).unwrap();
    }

    #[test]
    fn a_tampered_manifest_fails() {
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let sig = sign_package(MANIFEST, CWASM, &key);
        let mut tampered = MANIFEST.to_vec();
        tampered.extend_from_slice(b"\n[[keystore.key]]\n");
        assert_eq!(
            verify_package(&tampered, CWASM, &key.verifying_key(), &sig),
            Err(PackageError::BadSignature),
        );
    }

    #[test]
    fn a_manifest_paired_with_a_different_cwasm_fails() {
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let sig = sign_package(MANIFEST, CWASM, &key);
        assert_eq!(
            verify_package(MANIFEST, b"a different cwasm", &key.verifying_key(), &sig),
            Err(PackageError::BadSignature),
        );
    }

    #[test]
    fn the_digest_is_the_two_hashes_concatenated() {
        let d = package_digest(MANIFEST, CWASM);
        assert_eq!(&d[..32], hash::hash(MANIFEST).as_bytes());
        assert_eq!(&d[32..], hash::hash(CWASM).as_bytes());
    }

    #[test]
    fn an_lpkg_blob_round_trips() {
        use crate::package::{decode_package, encode_package, PackageError};
        let sig = [7u8; 64];
        let blob = encode_package(MANIFEST, CWASM, &sig);
        let p = decode_package(&blob).unwrap();
        assert_eq!(p.manifest_bytes, MANIFEST);
        assert_eq!(p.cwasm_bytes, CWASM);
        assert_eq!(p.signature, sig);

        assert!(matches!(decode_package(&blob[..blob.len() - 1]), Err(PackageError::Malformed)));
        assert!(matches!(decode_package(b"LPK9\0\0\0\0"), Err(PackageError::Malformed)));
    }

    #[test]
    fn the_borrowed_decoder_agrees_with_the_owned_one_and_borrows() {
        use crate::package::{decode_package_ref, encode_package, PackageError};
        let sig = [7u8; 64];
        let blob = encode_package(MANIFEST, CWASM, &sig);
        let p = decode_package_ref(&blob).unwrap();
        assert_eq!(p.manifest_bytes, MANIFEST);
        assert_eq!(p.cwasm_bytes, CWASM);
        assert_eq!(p.signature, &sig);
        // Zero-copy: the `.cwasm` slice points into the blob itself.
        assert!(blob.as_ptr_range().contains(&p.cwasm_bytes.as_ptr()));

        assert!(matches!(decode_package_ref(&blob[..blob.len() - 1]), Err(PackageError::Malformed)));
        // A launcher-mapped Frame is zero-padded past the package: the caller must pass
        // the exact length, never the whole mapping.
        let mut padded = blob.clone();
        padded.extend_from_slice(&[0u8; 16]);
        assert!(matches!(decode_package_ref(&padded), Err(PackageError::Malformed)));
        // A length header pointing past the end is malformed, not a panic.
        let mut lying = blob.clone();
        lying[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(decode_package_ref(&lying), Err(PackageError::Malformed)));
    }

    #[test]
    fn package_ref_verify_rejects_a_flipped_cwasm_byte() {
        use crate::package::{decode_package_ref, encode_package, sign_package, PackageError};
        let key = SigningKey::from_random_bytes([9u8; SEED_LEN]);
        let blob = encode_package(MANIFEST, CWASM, &sign_package(MANIFEST, CWASM, &key));
        decode_package_ref(&blob).unwrap().verify(&key.verifying_key()).unwrap();

        let mut tampered = blob.clone();
        let last_cwasm_byte = blob.len() - 64 - 1;
        tampered[last_cwasm_byte] ^= 1;
        let p = decode_package_ref(&tampered).unwrap();
        assert_eq!(p.verify(&key.verifying_key()), Err(PackageError::BadSignature));
    }
}

// -------------------------------------------------------------------------------------
// bind (feature `bind`)
// -------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------
// build (feature `build`)
// -------------------------------------------------------------------------------------

#[cfg(feature = "build")]
mod build {
    use crate::build::{build, BuildError};
    use crate::package::{decode_package, verify_package};
    use lantern_crypto::signing::{SigningKey, SEED_LEN};

    /// A component importing exactly `lantern:host/monotonic-clock@0.1.0`.
    const CLOCK_IMPORTER: &str = r#"
        (component
          (import "lantern:host/monotonic-clock@0.1.0" (instance $c
            (export "now" (func (result u64)))))
          (core func $now (canon lower (func $c "now")))
          (core module $m (import "" "now" (func (result i64)))
            (func (export "run") (result i64) call 0))
          (core instance $i (instantiate $m (with "" (instance (export "now" (func $now))))))
          (func (export "run") (result u64) (canon lift (core func $i "run"))))
    "#;

    const MANIFEST_CLOCK: &str =
        "[app]\nname = \"clocker\"\nversion = \"1.0.0\"\n[monotonic-clock]\njustification = \"reads the clock\"\n";

    #[test]
    fn build_produces_a_verifiable_lpkg_when_imports_match_declarations() {
        let key = SigningKey::from_random_bytes([4u8; SEED_LEN]);
        let built = build(MANIFEST_CLOCK, CLOCK_IMPORTER.as_bytes(), &key).unwrap();

        let pkg = decode_package(&built.lpkg).unwrap();
        assert_eq!(pkg.manifest_bytes, MANIFEST_CLOCK.as_bytes());
        verify_package(&pkg.manifest_bytes, &pkg.cwasm_bytes, &built.verifying_key, &pkg.signature).unwrap();
    }

    #[test]
    fn build_rejects_a_component_importing_more_than_the_manifest_declares() {
        let key = SigningKey::from_random_bytes([4u8; SEED_LEN]);
        // manifest declares nothing, component imports the clock.
        let bare = "[app]\nname = \"x\"\nversion = \"1.0.0\"\n";
        let e = build(bare, CLOCK_IMPORTER.as_bytes(), &key).unwrap_err();
        assert!(matches!(e, BuildError::UndeclaredImports(v) if v == ["lantern:host/monotonic-clock@0.1.0"]));
    }

    #[test]
    fn build_rejects_a_manifest_that_over_asks() {
        let key = SigningKey::from_random_bytes([4u8; SEED_LEN]);
        // manifest declares keystore + clock; component imports only the clock.
        let over = concat!(
            "[app]\nname = \"x\"\nversion = \"1.0.0\"\n",
            "[[keystore.key]]\nrole = \"k\"\nops = [\"sign\"]\njustification = \"y\"\n",
            "[monotonic-clock]\njustification = \"y\"\n",
        );
        let e = build(over, CLOCK_IMPORTER.as_bytes(), &key).unwrap_err();
        assert!(matches!(e, BuildError::DeclaredButNotImported(v) if v == ["lantern:host/keystore@0.1.0"]));
    }
}

#[cfg(feature = "bind")]
mod bind {
    use std::cell::RefCell;

    use crate::bind::{bind, Bound};
    use lantern_runtime::MonotonicClock;

    #[test]
    fn bind_walks_requests_in_slot_order_and_assembles_a_sparse_manifest() {
        let p = crate::parse(super::GOOD).unwrap().plan();
        let seen = RefCell::new(Vec::new());

        // Decline every resource request — this exercises the ordering and the `None`
        // assembly without needing a service-minted handle. (`Granted(x) → Some(x)` is a
        // one-line match; `lantern-runtime`'s tests cover the handle types themselves.)
        let gm = bind(
            &p,
            |req| {
                seen.borrow_mut().push(("keystore", req.slot));
                Bound::Declined
            },
            |req| {
                seen.borrow_mut().push(("filesystem", req.slot));
                Bound::Declined
            },
            |_req| None::<MonotonicClock>,
        );

        assert_eq!(
            *seen.borrow(),
            [("keystore", 0), ("keystore", 1), ("filesystem", 0)],
            "requests walked in declaration order",
        );
        assert_eq!(gm.keystore_keys.len(), 2);
        assert!(gm.keystore_keys.iter().all(Option::is_none), "declared but all declined → linked, all None");
        assert_eq!(gm.filesystem_files.len(), 1);
        assert!(gm.filesystem_files[0].is_none());
        assert!(gm.monotonic_clock.is_none(), "clock closure returned None → refused");
    }
}
