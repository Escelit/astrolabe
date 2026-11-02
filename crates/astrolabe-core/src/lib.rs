//! Core types, encodings, and validators for the Astrolabe Canonical Format (`acf/0.1`).
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

mod curve;
mod field;
mod uint256;

use core::fmt;

pub use curve::{decode_g1, decode_g2, encode_g1, encode_g2, G1, G1_BYTE_LEN, G2, G2_BYTE_LEN};
pub use field::{
    decode_fp, decode_fr, encode_fp, encode_fr, Fp, Fp2, Fp2ComponentOrder, Fr, BN254_P_BE,
    BN254_R_BE, FP2_BYTE_LEN, FP2_COMPONENT_ORDER, FP_BYTE_LEN, FR_BYTE_LEN,
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
}
