use astrolabe_core::noir::{
    parse_noir_bundle, parse_noir_proof, parse_noir_proof_envelope, parse_noir_public_inputs,
    parse_noir_public_inputs_envelope, parse_noir_vk, parse_noir_vk_envelope, NoirMetadata,
};
use astrolabe_core::AcfError;
use std::fs;
use std::path::PathBuf;

fn fixture_path(circuit: &str, file: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/snarkjs")
        .join(circuit)
        .join(file);
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("Failed to read {}: {e}", p.display()))
}

#[test]
fn test_noir_snarkjs_compatible_artifacts() {
    let proof_str = fixture_path("multiplier2", "proof.json");
    let vk_str = fixture_path("multiplier2", "verification_key.json");
    let pub_str = fixture_path("multiplier2", "public.json");

    let proof = parse_noir_proof(&proof_str).expect("parse_noir_proof failed");
    let vk = parse_noir_vk(&vk_str).expect("parse_noir_vk failed");
    let pub_inputs = parse_noir_public_inputs(&pub_str).expect("parse_noir_public_inputs failed");

    assert_eq!(vk.n_public(), 2);
    assert_eq!(pub_inputs.inputs.len(), 2);
    assert!(vk.validate_public_inputs(&pub_inputs).is_ok());

    let proof_env = parse_noir_proof_envelope(&proof_str).unwrap();
    let vk_env = parse_noir_vk_envelope(&vk_str).unwrap();
    let pub_env = parse_noir_public_inputs_envelope(&pub_str).unwrap();

    assert_eq!(proof_env.payload.encode(), proof.encode());
    assert_eq!(vk_env.payload.encode(), vk.encode());
    assert_eq!(pub_env.payload.encode(), pub_inputs.encode());
}

#[test]
fn test_noir_bundle_with_metadata_and_hex() {
    let proof_raw = fixture_path("square", "proof.json");
    let vk_raw = fixture_path("square", "verification_key.json");

    let bundle_json = format!(
        r#"{{
            "noir_version": "0.33.0",
            "backend": "sunspot",
            "circuit": "noir_square_circuit",
            "proof": {proof_raw},
            "verification_key": {vk_raw},
            "public_inputs": ["0x09"]
        }}"#
    );

    let bundle = parse_noir_bundle(&bundle_json).expect("bundle parse failed");

    assert_eq!(
        bundle.metadata,
        NoirMetadata {
            noir_version: Some("0.33.0".to_string()),
            backend: Some("sunspot".to_string()),
            circuit_name: Some("noir_square_circuit".to_string()),
        }
    );

    let proof = bundle.proof.expect("proof should be present");
    let vk = bundle.vk.expect("vk should be present");
    let pub_inputs = bundle
        .public_inputs
        .expect("public_inputs should be present");

    assert_eq!(vk.n_public(), 1);
    assert_eq!(pub_inputs.inputs.len(), 1);
    assert_eq!(pub_inputs.inputs[0].encode()[31], 9);
    assert!(vk.validate_public_inputs(&pub_inputs).is_ok());

    assert!(!proof.a.is_infinity());
    assert!(!proof.b.is_infinity());
    assert!(!proof.c.is_infinity());
}

#[test]
fn test_noir_rejections() {
    // Malformed JSON
    assert_eq!(
        parse_noir_proof("not json").unwrap_err(),
        AcfError::MalformedInput
    );

    // Unsupported protocol
    let bad_proto = r#"{"protocol": "honk", "curve": "bn128"}"#;
    assert_eq!(
        parse_noir_proof(bad_proto).unwrap_err(),
        AcfError::Unsupported
    );

    // Bad scalar
    let bad_scalar = r#"["0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"]"#;
    assert_eq!(
        parse_noir_public_inputs(bad_scalar).unwrap_err(),
        AcfError::NonCanonicalField
    );
}

#[test]
fn test_noir_standalone_bn254_curve_alias() {
    let proof_str = fixture_path("multiplier2", "proof.json").replace("\"bn128\"", "\"bn254\"");
    let vk_str =
        fixture_path("multiplier2", "verification_key.json").replace("\"bn128\"", "\"bn254\"");

    let proof = parse_noir_proof(&proof_str).expect("standalone Noir proof with bn254 should pass");
    let vk = parse_noir_vk(&vk_str).expect("standalone Noir vk with bn254 should pass");

    assert!(!proof.a.is_infinity());
    assert_eq!(vk.n_public(), 2);
}
