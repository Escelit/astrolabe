//! Independent differential cross-check against `ark-bn254 0.5.0`
//! (Plan.md Phase 2 exit criteria & AGENTS.md Section 7).

use ark_bn254::{Fq as ArkFq, Fq2 as ArkFq2, Fr as ArkFr, G1Affine as ArkG1, G2Affine as ArkG2};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use astrolabe_core::{
    decode_fp, decode_fr, decode_g1, decode_g2, AcfError, Fp2ComponentOrder, BN254_P_BE,
    BN254_R_BE, FP2_COMPONENT_ORDER, G1, G2,
};

fn ark_fq_to_be32(fq: ArkFq) -> [u8; 32] {
    let be = fq.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

fn ark_fr_to_be32(fr: ArkFr) -> [u8; 32] {
    let be = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

fn ark_g1_to_acf(pt: ArkG1) -> [u8; 64] {
    if pt.is_zero() {
        return [0u8; 64];
    }
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&ark_fq_to_be32(pt.x));
    out[32..64].copy_from_slice(&ark_fq_to_be32(pt.y));
    out
}

fn ark_g2_to_acf(pt: ArkG2) -> [u8; 128] {
    assert_eq!(FP2_COMPONENT_ORDER, Fp2ComponentOrder::C1ThenC0);
    if pt.is_zero() {
        return [0u8; 128];
    }
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&ark_fq_to_be32(pt.x.c1));
    out[32..64].copy_from_slice(&ark_fq_to_be32(pt.x.c0));
    out[64..96].copy_from_slice(&ark_fq_to_be32(pt.y.c1));
    out[96..128].copy_from_slice(&ark_fq_to_be32(pt.y.c0));
    out
}

#[test]
fn moduli_match_ark_bn254() {
    let mut p_ark = [0u8; 32];
    let p_bytes = ArkFq::MODULUS.to_bytes_be();
    p_ark[32 - p_bytes.len()..].copy_from_slice(&p_bytes);
    assert_eq!(BN254_P_BE, p_ark);

    let mut r_ark = [0u8; 32];
    let r_bytes = ArkFr::MODULUS.to_bytes_be();
    r_ark[32 - r_bytes.len()..].copy_from_slice(&r_bytes);
    assert_eq!(BN254_R_BE, r_ark);
}

#[test]
fn fp_and_fr_round_trip_against_ark_bn254() {
    for k in 0u64..128 {
        let fq = ArkFq::from(k) * ArkFq::from(0x9e37_79b9_7f4a_7c15u64) - ArkFq::from(k * 7);
        let fq_bytes = ark_fq_to_be32(fq);
        let decoded_fp = decode_fp(&fq_bytes).expect("valid Fp from arkworks");
        assert_eq!(decoded_fp.encode(), fq_bytes);

        let fr = ArkFr::from(k) * ArkFr::from(0xbf58_476d_1ce4_e5b9u64) - ArkFr::from(k * 13);
        let fr_bytes = ark_fr_to_be32(fr);
        let decoded_fr = decode_fr(&fr_bytes).expect("valid Fr from arkworks");
        assert_eq!(decoded_fr.encode(), fr_bytes);
    }

    assert_eq!(decode_fp(&BN254_P_BE), Err(AcfError::NonCanonicalField));
    assert_eq!(decode_fr(&BN254_R_BE), Err(AcfError::NonCanonicalField));
}

#[test]
fn g1_scalar_multiples_match_ark_bn254() {
    let mut cur = ArkG1::zero().into_group();
    let step = ArkG1::generator().into_group();

    for i in 0..64 {
        let aff = cur.into_affine();
        let bytes = ark_g1_to_acf(aff);
        let decoded = decode_g1(&bytes).expect("arkworks G1 multiple must decode");
        assert_eq!(decoded.is_infinity(), i == 0);
        assert_eq!(decoded.encode(), bytes);

        if i > 0 {
            // Perturbing y by +1 (mod p) must fail on-curve check
            let mut bad = bytes;
            let bad_y = ark_fq_to_be32(aff.y + ArkFq::from(1u64));
            bad[32..64].copy_from_slice(&bad_y);
            assert_eq!(decode_g1(&bad), Err(AcfError::NotOnCurve));
        }

        cur += step;
    }

    assert_eq!(G1::GENERATOR.encode(), ark_g1_to_acf(ArkG1::generator()));
}

#[test]
fn g2_subgroup_and_curve_checks_match_ark_bn254() {
    // 1. Valid subgroup multiples [0..32] * G2_gen
    let mut cur = ArkG2::zero().into_group();
    let step = ArkG2::generator().into_group();

    for i in 0..32 {
        let aff = cur.into_affine();
        let bytes = ark_g2_to_acf(aff);
        let decoded = decode_g2(&bytes).expect("arkworks G2 subgroup multiple must decode");
        assert_eq!(decoded.is_infinity(), i == 0);
        assert_eq!(decoded.encode(), bytes);
        cur += step;
    }

    assert_eq!(G2::INFINITY.encode(), [0u8; 128]);

    // 2. Twist points `x = k + 1*u`: compare subgroup decision directly against arkworks
    let mut checked_twist_points = 0usize;
    for k in 0u64..64 {
        let x = ArkFq2::new(ArkFq::from(k), ArkFq::from(1u64));
        if let Some(pt) = ArkG2::get_point_from_x_unchecked(x, true) {
            checked_twist_points += 1;
            let bytes = ark_g2_to_acf(pt);
            let ark_in_sub = pt.is_in_correct_subgroup_assuming_on_curve();
            let acf_res = decode_g2(&bytes);
            if ark_in_sub {
                assert!(acf_res.is_ok(), "expected k={k} twist point in subgroup");
            } else {
                assert_eq!(
                    acf_res,
                    Err(AcfError::NotInSubgroup),
                    "expected k={k} twist point to fail with ERR_NOT_IN_SUBGROUP"
                );
            }

            // Perturbing y.c0 by +1 makes the point off-curve -> ERR_NOT_ON_CURVE (preceding subgroup)
            let mut off_curve = bytes;
            off_curve[96..128].copy_from_slice(&ark_fq_to_be32(pt.y.c0 + ArkFq::from(1u64)));
            assert_eq!(decode_g2(&off_curve), Err(AcfError::NotOnCurve));
        }
    }
    assert!(
        checked_twist_points >= 20,
        "expected at least 20 twist points sampled, got {checked_twist_points}"
    );
}
