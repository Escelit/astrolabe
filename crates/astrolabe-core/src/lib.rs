//! Core types, encodings, and validators for the Astrolabe Canonical Format (`acf/1.0`).
//!
//! Implements BN254 field elements ([`Fp`], [`Fr`], [`Fp2`]), affine curve points
//! ([`G1`], [`G2`]), strict validation rules, and canonical error codes per ACF
//! Specification Sections 2, 3, 9, and 11.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

extern crate alloc;

mod canonical_json;
mod curve;
mod envelope;
mod field;
mod groth16;
pub mod noir;
pub mod snarkjs;
mod uint256;

use core::fmt;

pub use canonical_json::{parse_canonical_json, to_canonical_json};
pub use curve::{decode_g1, decode_g2, encode_g1, encode_g2, G1, G1_BYTE_LEN, G2, G2_BYTE_LEN};
pub use envelope::{
    decode_envelope, encode_envelope, ArtifactKind, CurveId, Envelope, EnvelopePayload,
    ProofSystemId, ENVELOPE_HEADER_BYTE_LEN, ENVELOPE_MAGIC, ENVELOPE_SPEC_VER_0_1,
};
pub use field::{
    decode_fp, decode_fr, encode_fp, encode_fr, Fp, Fp2, Fp2ComponentOrder, Fr, BN254_P_BE,
    BN254_R_BE, FP2_BYTE_LEN, FP2_COMPONENT_ORDER, FP_BYTE_LEN, FR_BYTE_LEN,
};
pub use groth16::{
    decode_proof, decode_public_inputs, decode_vk, encode_proof, encode_public_inputs, encode_vk,
    Proof, PublicInputs, VerificationKey, PROOF_BYTE_LEN, VK_HEADER_BYTE_LEN,
};
pub use noir::{
    extract_noir_metadata, parse_noir_bundle, parse_noir_proof, parse_noir_proof_envelope,
    parse_noir_public_inputs, parse_noir_public_inputs_envelope, parse_noir_vk,
    parse_noir_vk_envelope, NoirBundle, NoirMetadata,
};
pub use snarkjs::{
    parse_dec_fp, parse_dec_fr, parse_hex_bytes_32, parse_num_fp, parse_num_fr,
    parse_snarkjs_proof, parse_snarkjs_proof_envelope, parse_snarkjs_public_inputs,
    parse_snarkjs_public_inputs_envelope, parse_snarkjs_vk, parse_snarkjs_vk_envelope,
};

/// Canonical error codes defined by ACF Specification Section 11.
///
/// Each variant maps one-to-one to a stable string error code returned by
/// [`AcfError::code`] and formatted via [`core::fmt::Display`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AcfError {
    /// `ERR_BAD_LENGTH`: Byte length does not match the expected size (Spec Section 11).
    BadLength,
    /// `ERR_NON_CANONICAL_FIELD`: Value is not below the field modulus (Spec Section 11).
    NonCanonicalField,
    /// `ERR_NOT_ON_CURVE`: Point does not satisfy the curve equation (Spec Section 11).
    NotOnCurve,
    /// `ERR_NOT_IN_SUBGROUP`: G2 point is not in the order-`r` subgroup (Spec Section 11).
    NotInSubgroup,
    /// `ERR_PUBLIC_INPUT_COUNT`: Public-input count does not match the VK (Spec Section 11).
    PublicInputCount,
    /// `ERR_INVALID_PROOF`: Degenerate proof element or failed pairing check (Spec Section 11).
    InvalidProof,
    /// `ERR_UNSUPPORTED`: Unknown version, kind, curve, system, or protocol (Spec Section 11).
    Unsupported,
    /// `ERR_TRAILING_BYTES`: Extra bytes after the declared payload (Spec Section 11).
    TrailingBytes,
    /// `ERR_MALFORMED_INPUT`: Source file is not parseable (bad JSON, bad decimal) (Spec Section 11).
    MalformedInput,
}

impl AcfError {
    /// Returns the stable string error code specified in ACF Specification Section 11.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadLength => "ERR_BAD_LENGTH",
            Self::NonCanonicalField => "ERR_NON_CANONICAL_FIELD",
            Self::NotOnCurve => "ERR_NOT_ON_CURVE",
            Self::NotInSubgroup => "ERR_NOT_IN_SUBGROUP",
            Self::PublicInputCount => "ERR_PUBLIC_INPUT_COUNT",
            Self::InvalidProof => "ERR_INVALID_PROOF",
            Self::Unsupported => "ERR_UNSUPPORTED",
            Self::TrailingBytes => "ERR_TRAILING_BYTES",
            Self::MalformedInput => "ERR_MALFORMED_INPUT",
        }
    }
}

impl fmt::Display for AcfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl core::error::Error for AcfError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{G2Jacobian, G2_TWIST_COEFF_B};

    #[test]
    fn error_codes_match_spec_section_11() {
        let cases = [
            (AcfError::BadLength, "ERR_BAD_LENGTH"),
            (AcfError::NonCanonicalField, "ERR_NON_CANONICAL_FIELD"),
            (AcfError::NotOnCurve, "ERR_NOT_ON_CURVE"),
            (AcfError::NotInSubgroup, "ERR_NOT_IN_SUBGROUP"),
            (AcfError::PublicInputCount, "ERR_PUBLIC_INPUT_COUNT"),
            (AcfError::InvalidProof, "ERR_INVALID_PROOF"),
            (AcfError::Unsupported, "ERR_UNSUPPORTED"),
            (AcfError::TrailingBytes, "ERR_TRAILING_BYTES"),
            (AcfError::MalformedInput, "ERR_MALFORMED_INPUT"),
        ];

        for (err, expected) in cases {
            assert_eq!(err.code(), expected);
        }
    }

    #[test]
    fn twist_coeff_b_satisfies_nine_plus_u_times_b_equals_three() {
        let nine = Fp::from_limbs_unchecked([9, 0, 0, 0]);
        let three = Fp::from_limbs_unchecked([3, 0, 0, 0]);
        let xi = Fp2::new(nine, Fp::ONE);
        assert_eq!(xi.mul(G2_TWIST_COEFF_B), Fp2::new(three, Fp::ZERO));
    }

    #[test]
    fn g1_generator_and_infinity_round_trip() {
        let gen_bytes = G1::GENERATOR.encode();
        let decoded = G1::decode(&gen_bytes).unwrap();
        assert_eq!(decoded, G1::GENERATOR);
        assert!(!decoded.is_infinity());
        assert_eq!(decoded.encode(), gen_bytes);

        let inf_bytes = G1::INFINITY.encode();
        assert_eq!(inf_bytes, [0u8; 64]);
        let decoded_inf = G1::decode(&inf_bytes).unwrap();
        assert_eq!(decoded_inf, G1::INFINITY);
        assert!(decoded_inf.is_infinity());
        assert_eq!(decoded_inf.coordinates(), None);
    }

    #[test]
    fn g2_jacobian_edge_cases_are_complete() {
        // Test identity, P + P == 2P, P + (-P) == O, and 2-torsion (Y == 0) -> O.
        let inf = G2Jacobian::INFINITY;
        assert!(inf.double().is_infinity());
        assert!(inf.add(inf).is_infinity());

        let two_torsion_like = G2Jacobian::from_affine(Fp2::ONE, Fp2::ZERO);
        assert!(two_torsion_like.double().is_infinity());

        let p = G2Jacobian::from_affine(Fp2::ONE, Fp2::new(Fp::ONE, Fp::ONE));
        let neg_p = G2Jacobian::from_affine(Fp2::ONE, Fp2::new(Fp::ONE.neg(), Fp::ONE.neg()));
        assert!(p.add(neg_p).is_infinity());
        assert_eq!(p.add(inf).x, p.x);
        assert_eq!(inf.add(p).x, p.x);

        let doubled = p.double();
        let added_self = p.add(p);
        // Check projective equality: X1 * Z2^2 == X2 * Z1^2 and Y1 * Z2^3 == Y2 * Z1^3
        let z1_sq = doubled.z.square();
        let z2_sq = added_self.z.square();
        assert_eq!(doubled.x.mul(z2_sq), added_self.x.mul(z1_sq));
        assert_eq!(
            doubled.y.mul(z2_sq).mul(added_self.z),
            added_self.y.mul(z1_sq).mul(doubled.z)
        );
    }

    #[test]
    fn groth16_objects_and_envelope_round_trip() {
        let proof = Proof {
            a: G1::GENERATOR,
            b: G2::GENERATOR,
            c: G1::GENERATOR,
        };
        let proof_enc = proof.encode();
        let proof_dec = Proof::decode(&proof_enc).unwrap();
        assert_eq!(proof, proof_dec);

        let vk = VerificationKey {
            alpha_g1: G1::GENERATOR,
            beta_g2: G2::GENERATOR,
            gamma_g2: G2::GENERATOR,
            delta_g2: G2::GENERATOR,
            ic: alloc::vec![G1::GENERATOR, G1::GENERATOR],
        };
        assert_eq!(vk.n_ic(), 2);
        assert_eq!(vk.n_public(), 1);
        let vk_enc = vk.encode();
        let vk_dec = VerificationKey::decode(&vk_enc).unwrap();
        assert_eq!(vk, vk_dec);

        let pi = PublicInputs {
            inputs: alloc::vec![Fr::ONE],
        };
        assert_eq!(pi.len(), 1);
        assert!(!pi.is_empty());
        let pi_enc = pi.encode();
        let pi_dec = PublicInputs::decode(&pi_enc).unwrap();
        assert_eq!(pi, pi_dec);

        assert!(vk.validate_public_inputs(&pi).is_ok());
        assert!(pi.validate_with_vk(&vk).is_ok());

        let wrong_pi = PublicInputs {
            inputs: alloc::vec![Fr::ONE, Fr::ONE],
        };
        assert_eq!(
            vk.validate_public_inputs(&wrong_pi),
            Err(AcfError::PublicInputCount)
        );

        let env = Envelope::new(EnvelopePayload::Proof(proof));
        let env_enc = env.encode();
        let env_dec = Envelope::decode(&env_enc).unwrap();
        assert_eq!(env, env_dec);

        let json_str = to_canonical_json(&env);
        let parsed_env = parse_canonical_json(&json_str).unwrap();
        assert_eq!(env, parsed_env);
    }
}
