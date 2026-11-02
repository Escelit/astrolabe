//! Conformance test vector runner for `astrolabe-core` (ACF Spec Section 12).

use astrolabe_core::{decode_fp, decode_fr, decode_g1, decode_g2, AcfError};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    ok: bool,
    output_hex: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestVector {
    id: String,
    description: String,
    operation: String,
    input_hex: String,
    expected: Expected,
    tags: Vec<String>,
    #[allow(dead_code)]
    tx_hash: Option<String>,
}

fn collect_vector_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read spec/vectors directory")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();

    for path in entries {
        if path.is_dir() {
            collect_vector_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("json")
            && path.file_name().and_then(|n| n.to_str()) != Some("schema.json")
        {
            out.push(path);
        }
    }
}

fn decode_hex_lowercase(hex: &str) -> Vec<u8> {
    assert!(
        hex.len().is_multiple_of(2),
        "vector hex must have even length: {hex}"
    );
    assert!(
        hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "vector hex must be lowercase hex without 0x prefix: {hex}"
    );
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex byte"))
        .collect()
}

fn encode_hex_lowercase(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn run_primitive_op(operation: &str, input: &[u8]) -> Option<Result<Vec<u8>, AcfError>> {
    match operation {
        "decode_fp" => Some(decode_fp(input).map(|fp| fp.encode().to_vec())),
        "decode_fr" => Some(decode_fr(input).map(|fr| fr.encode().to_vec())),
        "decode_g1" => Some(decode_g1(input).map(|g1| g1.encode().to_vec())),
        "decode_g2" => Some(decode_g2(input).map(|g2| g2.encode().to_vec())),
        // Phase 3 Groth16 object operations seeded in Phase 1 fixtures:
        "decode_proof" | "decode_vk" | "decode_public_inputs" => None,
        other => panic!("unknown vector operation '{other}'"),
    }
}

#[test]
fn conformance_vectors_pass_in_rust() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_root = manifest_dir.join("../../spec/vectors");
    let mut files = Vec::new();
    collect_vector_files(&vectors_root, &mut files);
    assert!(!files.is_empty(), "expected conformance vector files");

    let mut seen_ids = BTreeSet::new();
    let mut executed = 0usize;

    for file in &files {
        let raw = fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("failed reading {}: {e}", file.display()));
        let vectors: Vec<TestVector> = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("invalid vector JSON in {}: {e}", file.display()));
        assert!(
            !vectors.is_empty(),
            "vector file {} must not be empty",
            file.display()
        );

        for vec_case in vectors {
            assert!(
                seen_ids.insert(vec_case.id.clone()),
                "duplicate vector id '{}'",
                vec_case.id
            );
            assert!(
                !vec_case.description.trim().is_empty(),
                "vector '{}' must record description and source",
                vec_case.id
            );
            assert!(
                !vec_case.tags.is_empty(),
                "vector '{}' must have at least one tag",
                vec_case.id
            );

            let input = decode_hex_lowercase(&vec_case.input_hex);
            let Some(result) = run_primitive_op(&vec_case.operation, &input) else {
                continue;
            };
            executed += 1;

            if vec_case.expected.ok {
                assert!(
                    vec_case.expected.error.is_none(),
                    "vector '{}' has ok=true with error field",
                    vec_case.id
                );
                let encoded = result.unwrap_or_else(|err| {
                    panic!(
                        "vector '{}' ({}) expected ok=true, got error {}",
                        vec_case.id,
                        file.display(),
                        err.code()
                    )
                });
                // Round-trip determinism: re-encoding must match canonical input bytes.
                assert_eq!(
                    encoded, input,
                    "vector '{}' failed decode->encode round-trip",
                    vec_case.id
                );
                if let Some(expected_hex) = &vec_case.expected.output_hex {
                    assert_eq!(
                        &encode_hex_lowercase(&encoded),
                        expected_hex,
                        "vector '{}' output_hex mismatch",
                        vec_case.id
                    );
                }
            } else {
                let expected_err =
                    vec_case.expected.error.as_deref().unwrap_or_else(|| {
                        panic!("vector '{}' missing expected.error", vec_case.id)
                    });
                let err = result.expect_err(&format!(
                    "vector '{}' ({}) expected error {}, but succeeded",
                    vec_case.id,
                    file.display(),
                    expected_err
                ));
                assert_eq!(
                    err.code(),
                    expected_err,
                    "vector '{}' ({}) error code mismatch",
                    vec_case.id,
                    file.display()
                );
            }
        }
    }

    assert!(
        executed >= 60,
        "expected at least 60 primitive conformance vectors, executed {executed}"
    );
}
