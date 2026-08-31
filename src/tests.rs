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
}

// -------------------------------------------------------------------------------------
// bind (feature `bind`)
// -------------------------------------------------------------------------------------

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
