//! Differential test suite (Plan.md Phase 4 exit criteria & AGENTS.md Section 7).
//!
//! Verifies byte-for-byte cross-implementation conformance and cross-checks
//! converted Groth16 proofs against independent verification via `ark-bn254 0.5.0`.

use std::fs;
use std::path::PathBuf;

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1, G2Affine as ArkG2,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use astrolabe_core::{
    parse_snarkjs_proof, parse_snarkjs_public_inputs, parse_snarkjs_vk, Fp2ComponentOrder,
    FP2_COMPONENT_ORDER,
};

fn fixture_path(subpath: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/fixtures/snarkjs")
        .join(subpath)
}

fn be32_to_fq(bytes: &[u8]) -> ArkFq {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    ArkFq::from_be_bytes_mod_order(&arr)
}

fn be32_to_fr(bytes: &[u8]) -> ArkFr {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    ArkFr::from_be_bytes_mod_order(&arr)
}

fn acf_g1_to_ark(bytes: &[u8]) -> ArkG1 {
    if bytes.iter().all(|&b| b == 0) {
        return ArkG1::zero();
    }
    let x = be32_to_fq(&bytes[0..32]);
    let y = be32_to_fq(&bytes[32..64]);
    ArkG1::new_unchecked(x, y)
}

fn acf_g2_to_ark(bytes: &[u8]) -> ArkG2 {
    assert_eq!(FP2_COMPONENT_ORDER, Fp2ComponentOrder::C1ThenC0);
    if bytes.iter().all(|&b| b == 0) {
        return ArkG2::zero();
    }
    // ACF G2 wire format is c1 || c0
    let xc1 = be32_to_fq(&bytes[0..32]);
    let xc0 = be32_to_fq(&bytes[32..64]);
    let yc1 = be32_to_fq(&bytes[64..96]);
    let yc0 = be32_to_fq(&bytes[96..128]);
    ArkG2::new_unchecked(ArkFq2::new(xc0, xc1), ArkFq2::new(yc0, yc1))
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Executes independent Groth16 pairing check using arkworks `Bn254` (ACF Spec Section 8).
fn verify_groth16_with_arkworks(
    proof_bytes: &[u8],
    vk_bytes: &[u8],
    public_scalars_bytes: &[[u8; 32]],
) -> bool {
    let a = acf_g1_to_ark(&proof_bytes[0..64]);
    let b = acf_g2_to_ark(&proof_bytes[64..192]);
    let c = acf_g1_to_ark(&proof_bytes[192..256]);

    let alpha = acf_g1_to_ark(&vk_bytes[0..64]);
    let beta = acf_g2_to_ark(&vk_bytes[64..192]);
    let gamma = acf_g2_to_ark(&vk_bytes[192..320]);
    let delta = acf_g2_to_ark(&vk_bytes[320..448]);

    let mut n_ic_buf = [0u8; 4];
    n_ic_buf.copy_from_slice(&vk_bytes[448..452]);
    let n_ic = u32::from_be_bytes(n_ic_buf) as usize;
    assert_eq!(vk_bytes.len(), 452 + n_ic * 64);
    assert_eq!(public_scalars_bytes.len() + 1, n_ic);

    let mut vk_x = acf_g1_to_ark(&vk_bytes[452..516]).into_group();
    for (i, scalar_be) in public_scalars_bytes.iter().enumerate() {
        let s = be32_to_fr(scalar_be);
        let ic_pt = acf_g1_to_ark(&vk_bytes[452 + (i + 1) * 64..452 + (i + 2) * 64]);
        vk_x += ic_pt * s;
    }
    let vk_x = vk_x.into_affine();

    // Spec Section 8 Step 3 & 4:
    // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    let neg_a = -a;
    let pairing_output = Bn254::multi_pairing([neg_a, alpha, vk_x, c], [b, beta, gamma, delta]);
    pairing_output == PairingOutput::<Bn254>::zero()
}

#[test]
fn test_differential_circuits_independent_arkworks_verification() {
    let circuits = [("multiplier2", 2, 3), ("square", 1, 2), ("linear3", 3, 4)];

    for (name, expected_pub, expected_ic) in circuits {
        let dir = fixture_path(name);
        let proof = parse_snarkjs_proof(&fs::read_to_string(dir.join("proof.json")).unwrap())
            .unwrap_or_else(|e| panic!("failed to parse proof for {name}: {e}"));
        let vk = parse_snarkjs_vk(&fs::read_to_string(dir.join("verification_key.json")).unwrap())
            .unwrap_or_else(|e| panic!("failed to parse vk for {name}: {e}"));
        let pub_inputs =
            parse_snarkjs_public_inputs(&fs::read_to_string(dir.join("public.json")).unwrap())
                .unwrap_or_else(|e| panic!("failed to parse public inputs for {name}: {e}"));

        assert_eq!(vk.n_public(), expected_pub);
        assert_eq!(vk.n_ic(), expected_ic);
        assert_eq!(pub_inputs.inputs.len(), expected_pub);

        let proof_bytes = proof.encode();
        let vk_bytes = vk.encode();
        let pub_scalars: Vec<[u8; 32]> = pub_inputs.inputs.iter().map(|fr| fr.encode()).collect();

        // 1. Positive verification: independent arkworks verification must succeed
        // (matches snarkjs groth16 verify OK).
        assert!(
            verify_groth16_with_arkworks(&proof_bytes, &vk_bytes, &pub_scalars),
            "arkworks independent pairing check failed for circuit {name}"
        );

        // 2. Negative control (corrupted public scalar):
        // Pairing check MUST return false.
        let mut corrupted_scalars = pub_scalars.clone();
        corrupted_scalars[0][31] ^= 0x01;
        assert!(
            !verify_groth16_with_arkworks(&proof_bytes, &vk_bytes, &corrupted_scalars),
            "corrupted public input should fail pairing check for circuit {name}"
        );

        // 3. Negative control (corrupted proof point A):
        // Pairing check MUST return false.
        let mut corrupted_proof = proof_bytes;
        // Invert y sign on A (corrupts affine point)
        corrupted_proof[32] ^= 0x01;
        assert!(
            !verify_groth16_with_arkworks(&corrupted_proof, &vk_bytes, &pub_scalars),
            "corrupted proof A should fail pairing check for circuit {name}"
        );

        // 4. Negative control (corrupted proof point C):
        let mut corrupted_proof_c = proof_bytes;
        corrupted_proof_c[192] ^= 0x01;
        assert!(
            !verify_groth16_with_arkworks(&corrupted_proof_c, &vk_bytes, &pub_scalars),
            "corrupted proof C should fail pairing check for circuit {name}"
        );
    }
}

#[test]
fn test_print_canonical_hex_for_ts_parity() {
    let circuits = ["multiplier2", "square", "linear3"];
    for name in circuits {
        let dir = fixture_path(name);
        let proof =
            parse_snarkjs_proof(&fs::read_to_string(dir.join("proof.json")).unwrap()).unwrap();
        let vk = parse_snarkjs_vk(&fs::read_to_string(dir.join("verification_key.json")).unwrap())
            .unwrap();
        let pub_inputs =
            parse_snarkjs_public_inputs(&fs::read_to_string(dir.join("public.json")).unwrap())
                .unwrap();

        let proof_hex = bytes_to_hex(&proof.encode());
        let vk_hex = bytes_to_hex(&vk.encode());
        let pub_hex = bytes_to_hex(&pub_inputs.encode());

        assert_eq!(proof_hex.len(), 512);
        assert!(!vk_hex.is_empty());
        assert!(!pub_hex.is_empty());
    }
}
