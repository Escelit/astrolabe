//! Core types for the Astrolabe Canonical Format (`acf/0.1`).
//!
//! Phase 0 scaffold: defines only [`AcfError`] per ACF Specification Section 11.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

use core::fmt;

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
    use super::AcfError;

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
}
