use astrolabe_core::risc0::{
    map_risc0_journal_and_image_id, map_risc0_seal, parse_risc0_proof_envelope,
    parse_risc0_public_inputs_envelope, parse_risc0_receipt_json, sha256, Risc0PublicInputsMode,
};
use astrolabe_core::snarkjs::parse_snarkjs_proof;
use astrolabe_core::AcfError;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

#[test]
fn test_sha256_nist_vectors() {
    // Vector 1: empty string
    let h_empty = sha256(b"");
    assert_eq!(
        to_hex(&h_empty),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    // Vector 2: "abc"
    let h_abc = sha256(b"abc");
    assert_eq!(
        to_hex(&h_abc),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn test_risc0_seal_and_receipt_mapping() {
    let p_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/snarkjs/multiplier2/proof.json");
    let proof_json = fs::read_to_string(p_path).unwrap();
    let original_proof = parse_snarkjs_proof(&proof_json).unwrap();
    let seal_bytes = original_proof.encode();
    let seal_hex = to_hex(&seal_bytes);

    // 1. map_risc0_seal
    let mapped_proof = map_risc0_seal(&seal_bytes).expect("map_risc0_seal failed");
    assert_eq!(mapped_proof.encode(), seal_bytes);

    // 2. map_risc0_journal_and_image_id
    let image_id = [0x11u8; 32];
    let journal = b"test guest execution journal output";
    let journal_digest = sha256(journal);

    // Mode: Limb16 (4 scalars)
    let pub_inputs_4 =
        map_risc0_journal_and_image_id(&image_id, &journal_digest, Risc0PublicInputsMode::Limb16)
            .unwrap();
    assert_eq!(pub_inputs_4.inputs.len(), 4);
    // First scalar should have upper 16 bytes zero and lower 16 bytes matching image_id[0..16]
    let s0_bytes = pub_inputs_4.inputs[0].encode();
    assert_eq!(&s0_bytes[0..16], &[0u8; 16]);
    assert_eq!(&s0_bytes[16..32], &image_id[0..16]);

    // Mode: Direct (2 scalars)
    let valid_direct_id = [0x01u8; 32];
    let valid_direct_jd = [0x02u8; 32];
    let pub_inputs_2 = map_risc0_journal_and_image_id(
        &valid_direct_id,
        &valid_direct_jd,
        Risc0PublicInputsMode::Direct,
    )
    .unwrap();
    assert_eq!(pub_inputs_2.inputs.len(), 2);
    assert_eq!(&pub_inputs_2.inputs[0].encode(), &valid_direct_id);
    assert_eq!(&pub_inputs_2.inputs[1].encode(), &valid_direct_jd);

    // 3. parse_risc0_receipt_json (flat receipt)
    let receipt_json = format!(
        r#"{{
            "seal": "0x{seal_hex}",
            "image_id": "0x{}",
            "journal": "0x{}"
        }}"#,
        to_hex(&image_id),
        to_hex(journal)
    );
    let receipt = parse_risc0_receipt_json(&receipt_json, Risc0PublicInputsMode::Limb16)
        .expect("receipt json parsing failed");
    assert_eq!(receipt.proof.encode(), seal_bytes);
    assert_eq!(receipt.image_id, image_id);
    assert_eq!(receipt.journal_digest, journal_digest);
    assert_eq!(receipt.public_inputs.inputs.len(), 4);

    // 4. Envelope parsers
    let p_env = parse_risc0_proof_envelope(&receipt_json, Risc0PublicInputsMode::Limb16).unwrap();
    let pi_env =
        parse_risc0_public_inputs_envelope(&receipt_json, Risc0PublicInputsMode::Limb16).unwrap();
    assert_eq!(p_env.payload.encode(), seal_bytes);
    assert_eq!(pi_env.payload.encode(), pub_inputs_4.encode());
}

#[test]
fn test_risc0_rejections() {
    // Bad seal length
    assert_eq!(
        map_risc0_seal(&[0u8; 128]).unwrap_err(),
        AcfError::BadLength
    );

    // Non-canonical direct scalar (modulus r as image_id)
    let r_be = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    let err = map_risc0_journal_and_image_id(&r_be, &[0u8; 32], Risc0PublicInputsMode::Direct)
        .unwrap_err();
    assert_eq!(err, AcfError::NonCanonicalField);

    // Odd-length hex in journal string must be rejected as MalformedInput
    let p_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/snarkjs/multiplier2/proof.json");
    let proof_json = fs::read_to_string(p_path).unwrap();
    let seal_hex = to_hex(&parse_snarkjs_proof(&proof_json).unwrap().encode());
    let odd_journal_json = format!(
        r#"{{"seal":"0x{seal_hex}","image_id":"0x{}","journal":"0xabc"}}"#,
        "11".repeat(32)
    );
    assert_eq!(
        parse_risc0_receipt_json(&odd_journal_json, Risc0PublicInputsMode::Limb16).unwrap_err(),
        AcfError::MalformedInput
    );

    // Out-of-range byte (> 255) in journal array must be rejected as MalformedInput
    let bad_array_json = format!(
        r#"{{"seal":"0x{seal_hex}","image_id":"0x{}","journal":[256, 1, 2]}}"#,
        "11".repeat(32)
    );
    assert_eq!(
        parse_risc0_receipt_json(&bad_array_json, Risc0PublicInputsMode::Limb16).unwrap_err(),
        AcfError::MalformedInput
    );
}
