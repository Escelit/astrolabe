use astrolabe_core::{
    parse_dec_fp, parse_dec_fr, parse_snarkjs_proof, parse_snarkjs_proof_envelope,
    parse_snarkjs_public_inputs, parse_snarkjs_public_inputs_envelope, parse_snarkjs_vk,
    parse_snarkjs_vk_envelope, AcfError,
};
use std::fs;
use std::path::PathBuf;

fn fixture_path(subpath: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/snarkjs")
        .join(subpath)
}

#[test]
fn test_parse_valid_circuits() {
    let circuits = [("multiplier2", 2, 3), ("square", 1, 2), ("linear3", 3, 4)];

    for (name, expected_pub, expected_ic) in circuits {
        let dir = fixture_path(name);
        let proof_str = fs::read_to_string(dir.join("proof.json"))
            .unwrap_or_else(|e| panic!("failed to read proof.json for {name}: {e}"));
        let vk_str = fs::read_to_string(dir.join("verification_key.json"))
            .unwrap_or_else(|e| panic!("failed to read vk.json for {name}: {e}"));
        let pub_str = fs::read_to_string(dir.join("public.json"))
            .unwrap_or_else(|e| panic!("failed to read public.json for {name}: {e}"));

        let proof = parse_snarkjs_proof(&proof_str)
            .unwrap_or_else(|e| panic!("proof parsing failed for {name}: {e}"));
        let vk = parse_snarkjs_vk(&vk_str)
            .unwrap_or_else(|e| panic!("vk parsing failed for {name}: {e}"));
        let public_inputs = parse_snarkjs_public_inputs(&pub_str)
            .unwrap_or_else(|e| panic!("public inputs parsing failed for {name}: {e}"));

        assert_eq!(vk.n_public(), expected_pub);
        assert_eq!(vk.n_ic(), expected_ic);
        assert_eq!(public_inputs.inputs.len(), expected_pub);
        assert!(vk.validate_public_inputs(&public_inputs).is_ok());

        assert!(!proof.a.is_infinity());
        assert!(!proof.b.is_infinity());
        assert!(!proof.c.is_infinity());

        // Envelope parsers
        let proof_env = parse_snarkjs_proof_envelope(&proof_str).unwrap();
        let vk_env = parse_snarkjs_vk_envelope(&vk_str).unwrap();
        let pub_env = parse_snarkjs_public_inputs_envelope(&pub_str).unwrap();

        assert_eq!(proof_env.payload.encode(), proof.encode());
        assert_eq!(vk_env.payload.encode(), vk.encode());
        assert_eq!(pub_env.payload.encode(), public_inputs.encode());
    }
}

#[test]
fn test_parse_invalid_fixtures() {
    let invalid_dir = fixture_path("invalid");

    // Unsupported protocol
    let s = fs::read_to_string(invalid_dir.join("unsupported_protocol.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::Unsupported));
    assert_eq!(parse_snarkjs_vk(&s), Err(AcfError::Unsupported));

    // Unsupported curve
    let s = fs::read_to_string(invalid_dir.join("unsupported_curve.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::Unsupported));
    assert_eq!(parse_snarkjs_vk(&s), Err(AcfError::Unsupported));

    // Malformed proof A length
    let s = fs::read_to_string(invalid_dir.join("malformed_proof_a_len.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::MalformedInput));

    // Malformed proof A trailing
    let s = fs::read_to_string(invalid_dir.join("malformed_proof_a_trailing.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::MalformedInput));

    // Malformed proof B trailing
    let s = fs::read_to_string(invalid_dir.join("malformed_proof_b_trailing.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::MalformedInput));

    // Malformed decimal
    let s = fs::read_to_string(invalid_dir.join("malformed_decimal.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::MalformedInput));

    // Non-canonical field in proof
    let s = fs::read_to_string(invalid_dir.join("non_canonical_field.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::NonCanonicalField));

    // Non-canonical scalar in public.json
    let s = fs::read_to_string(invalid_dir.join("public_non_canonical_scalar.json")).unwrap();
    assert_eq!(
        parse_snarkjs_public_inputs(&s),
        Err(AcfError::NonCanonicalField)
    );

    // VK IC count mismatch
    let s = fs::read_to_string(invalid_dir.join("vk_ic_count_mismatch.json")).unwrap();
    assert_eq!(parse_snarkjs_vk(&s), Err(AcfError::PublicInputCount));

    // Degenerate proof infinity
    let s = fs::read_to_string(invalid_dir.join("degenerate_proof_infinity.json")).unwrap();
    assert_eq!(parse_snarkjs_proof(&s), Err(AcfError::InvalidProof));
}

#[test]
fn test_parse_dec_helpers() {
    assert_eq!(parse_dec_fp(""), Err(AcfError::MalformedInput));
    assert_eq!(parse_dec_fp("abc"), Err(AcfError::MalformedInput));
    assert_eq!(parse_dec_fr(""), Err(AcfError::MalformedInput));
    assert_eq!(parse_dec_fr("xyz"), Err(AcfError::MalformedInput));

    // BN254 field modulus p
    let p_str = "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    assert_eq!(parse_dec_fp(p_str), Err(AcfError::NonCanonicalField));

    // BN254 scalar modulus r
    let r_str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    assert_eq!(parse_dec_fr(r_str), Err(AcfError::NonCanonicalField));
}
