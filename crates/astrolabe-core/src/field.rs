//! BN254 prime fields (`Fp`, `Fr`) and quadratic extension field (`Fp2`).
//!
//! Implements ACF Specification Section 2, Section 3.1, Section 3.3 (`Fp2` wire
//! ordering), Section 3.4, and Section 9 Rules 1–2.

use crate::uint256::{
    add_mod_254, from_be_bytes_32, is_zero_limbs, lt_limbs, mul_mod_254, neg_mod, sub_mod_254,
    to_be_bytes_32,
};
use crate::AcfError;

/// Canonical byte length of an encoded [`Fp`] element (`be32`, ACF Spec Section 3.1).
pub const FP_BYTE_LEN: usize = 32;

/// Canonical byte length of an encoded [`Fr`] scalar (`be32`, ACF Spec Section 3.1 & 3.4).
pub const FR_BYTE_LEN: usize = 32;

/// Canonical byte length of an encoded [`Fp2`] element (`2 * 32` bytes, ACF Spec Section 3.3).
pub const FP2_BYTE_LEN: usize = 64;

/// BN254 base field modulus `p` in 32-byte big-endian form (ACF Spec Section 2).
///
/// Decimal: `21888242871839275222246405745257275088696311157297823662689037894645226208583`.
pub const BN254_P_BE: [u8; FP_BYTE_LEN] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// BN254 scalar field modulus (group order) `r` in 32-byte big-endian form (ACF Spec Section 2).
///
/// Decimal: `21888242871839275222246405745257275088548364400416034343698204186575808495617`.
pub const BN254_R_BE: [u8; FR_BYTE_LEN] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// BN254 base field modulus `p` in little-endian `u64` limbs.
pub(crate) const BN254_P_LIMBS: [u64; 4] = from_be_bytes_32(&BN254_P_BE);

/// BN254 scalar field modulus `r` in little-endian `u64` limbs.
pub(crate) const BN254_R_LIMBS: [u64; 4] = from_be_bytes_32(&BN254_R_BE);

/// Wire component ordering for [`Fp2`] coordinates inside [`crate::G2`] points
/// (ACF Specification Section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fp2ComponentOrder {
    /// Imaginary component first, real component second (`be32(c1) ‖ be32(c0)`),
    /// matching CAP-0074 and Ethereum EIP-197 (ACF Spec Section 3.3).
    C1ThenC0,
    /// Real component first, imaginary component second (`be32(c0) ‖ be32(c1)`).
    C0ThenC1,
}

/// Single named constant defining [`Fp2`] wire component ordering for ACF `v0.1`
/// (ACF Specification Section 3.3; verified in Phase 1 against CAP-0074,
/// `soroban-sdk 29.0.1`, and Stellar Testnet TX `3d5683f2...`).
pub const FP2_COMPONENT_ORDER: Fp2ComponentOrder = Fp2ComponentOrder::C1ThenC0;

#[inline]
pub(crate) fn split_64_into_32s(bytes: &[u8]) -> Result<(&[u8; 32], &[u8; 32]), AcfError> {
    let arr: &[u8; 64] = bytes.try_into().map_err(|_| AcfError::BadLength)?;
    let (first, rest) = arr.split_first_chunk::<32>().ok_or(AcfError::BadLength)?;
    let second: &[u8; 32] = rest.try_into().map_err(|_| AcfError::BadLength)?;
    Ok((first, second))
}

#[inline]
pub(crate) fn concat_32(first: [u8; 32], second: [u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    if let Some((head, tail)) = out.split_first_chunk_mut::<32>() {
        *head = first;
        if let Some((next, _)) = tail.split_first_chunk_mut::<32>() {
            *next = second;
        }
    }
    out
}

/// Canonical element of the BN254 base field `Fp = Z/pZ` in `[0, p)`
/// (ACF Specification Section 2 and Section 3.1).
///
/// Values `>= p` cannot be constructed and are rejected with
/// [`AcfError::NonCanonicalField`] without modular reduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fp {
    limbs: [u64; 4],
}

impl Fp {
    /// Additive identity `0` in `Fp` (ACF Specification Section 2).
    pub const ZERO: Self = Self {
        limbs: [0, 0, 0, 0],
    };

    /// Multiplicative identity `1` in `Fp` (ACF Specification Section 2).
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };

    #[inline]
    pub(crate) const fn from_limbs_unchecked(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    /// Decodes and validates a canonical 32-byte big-endian [`Fp`] element
    /// (ACF Specification Section 3.1 and Section 9 Rules 1–2).
    ///
    /// # Errors
    ///
    /// - [`AcfError::BadLength`] if `bytes.len() != 32`.
    /// - [`AcfError::NonCanonicalField`] if the decoded integer is `>= p`.
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        let arr: &[u8; FP_BYTE_LEN] = bytes.try_into().map_err(|_| AcfError::BadLength)?;
        Self::from_be_bytes(arr)
    }

    /// Decodes a canonical [`Fp`] element from a fixed 32-byte big-endian array
    /// (ACF Specification Section 3.1 and Section 9 Rule 2).
    ///
    /// # Errors
    ///
    /// Returns [`AcfError::NonCanonicalField`] if the integer is `>= p`.
    pub const fn from_be_bytes(bytes: &[u8; FP_BYTE_LEN]) -> Result<Self, AcfError> {
        let limbs = from_be_bytes_32(bytes);
        // Security hotspot: enforce strict `< p` canonical range; never reduce modulo `p`.
        if !lt_limbs(limbs, BN254_P_LIMBS) {
            return Err(AcfError::NonCanonicalField);
        }
        Ok(Self { limbs })
    }

    /// Encodes this [`Fp`] element as 32 big-endian bytes (`be32`, ACF Spec Section 3.1).
    #[must_use]
    pub const fn encode(self) -> [u8; FP_BYTE_LEN] {
        to_be_bytes_32(self.limbs)
    }

    /// Returns `true` iff this element is `0` (ACF Specification Section 2).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        is_zero_limbs(self.limbs)
    }

    #[inline]
    pub(crate) const fn add(self, rhs: Self) -> Self {
        Self {
            limbs: add_mod_254(self.limbs, rhs.limbs, BN254_P_LIMBS),
        }
    }

    #[inline]
    pub(crate) const fn double(self) -> Self {
        self.add(self)
    }

    #[inline]
    pub(crate) const fn sub(self, rhs: Self) -> Self {
        Self {
            limbs: sub_mod_254(self.limbs, rhs.limbs, BN254_P_LIMBS),
        }
    }

    #[inline]
    pub(crate) const fn neg(self) -> Self {
        Self {
            limbs: neg_mod(self.limbs, BN254_P_LIMBS),
        }
    }

    #[inline]
    pub(crate) const fn mul(self, rhs: Self) -> Self {
        Self {
            limbs: mul_mod_254(self.limbs, rhs.limbs, BN254_P_LIMBS),
        }
    }

    #[inline]
    pub(crate) const fn square(self) -> Self {
        self.mul(self)
    }
}

/// Canonical element of the BN254 scalar field `Fr = Z/rZ` in `[0, r)`
/// (ACF Specification Section 2, Section 3.1, and Section 3.4).
///
/// Values `>= r` cannot be constructed and are rejected with
/// [`AcfError::NonCanonicalField`], never silently reduced modulo `r`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fr {
    limbs: [u64; 4],
}

impl Fr {
    /// Additive identity `0` in `Fr` (ACF Specification Section 2).
    pub const ZERO: Self = Self {
        limbs: [0, 0, 0, 0],
    };

    /// Multiplicative identity `1` in `Fr` (ACF Specification Section 2).
    pub const ONE: Self = Self {
        limbs: [1, 0, 0, 0],
    };

    /// Decodes and validates a canonical 32-byte big-endian [`Fr`] scalar
    /// (ACF Specification Section 3.1, Section 3.4, and Section 9 Rules 1–2).
    ///
    /// # Errors
    ///
    /// - [`AcfError::BadLength`] if `bytes.len() != 32`.
    /// - [`AcfError::NonCanonicalField`] if the decoded integer is `>= r`.
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        let arr: &[u8; FR_BYTE_LEN] = bytes.try_into().map_err(|_| AcfError::BadLength)?;
        Self::from_be_bytes(arr)
    }

    /// Decodes a canonical [`Fr`] scalar from a fixed 32-byte big-endian array
    /// (ACF Specification Section 3.4 and Section 9 Rule 2).
    ///
    /// # Errors
    ///
    /// Returns [`AcfError::NonCanonicalField`] if the integer is `>= r`.
    pub const fn from_be_bytes(bytes: &[u8; FR_BYTE_LEN]) -> Result<Self, AcfError> {
        let limbs = from_be_bytes_32(bytes);
        // Security hotspot: enforce strict `< r` canonical range; never reduce modulo `r`.
        if !lt_limbs(limbs, BN254_R_LIMBS) {
            return Err(AcfError::NonCanonicalField);
        }
        Ok(Self { limbs })
    }

    /// Encodes this [`Fr`] scalar as 32 big-endian bytes (`be32`, ACF Spec Section 3.1 & 3.4).
    #[must_use]
    pub const fn encode(self) -> [u8; FR_BYTE_LEN] {
        to_be_bytes_32(self.limbs)
    }

    /// Returns `true` iff this scalar is `0` (ACF Specification Section 2).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        is_zero_limbs(self.limbs)
    }
}

/// Element `c0 + c1·u` of the BN254 quadratic extension field `Fp[u]/(u^2 + 1)`
/// (ACF Specification Section 2 and Section 3.3).
///
/// Wire encoding order is controlled exclusively by [`FP2_COMPONENT_ORDER`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fp2 {
    /// Real component (`c0` in `c0 + c1·u`).
    pub c0: Fp,
    /// Imaginary component (`c1` in `c0 + c1·u`, where `u^2 = -1`).
    pub c1: Fp,
}

impl Fp2 {
    /// Additive identity `0 + 0·u` in `Fp2` (ACF Specification Section 2).
    pub const ZERO: Self = Self {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };

    /// Multiplicative identity `1 + 0·u` in `Fp2` (ACF Specification Section 2).
    pub const ONE: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };

    /// Constructs an [`Fp2`] element from canonical real (`c0`) and imaginary (`c1`)
    /// components (ACF Specification Section 2).
    #[must_use]
    pub const fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    /// Decodes a 64-byte [`Fp2`] element according to [`FP2_COMPONENT_ORDER`]
    /// (ACF Specification Section 3.3 and Section 9 Rules 1–2).
    ///
    /// # Errors
    ///
    /// - [`AcfError::BadLength`] if `bytes.len() != 64`.
    /// - [`AcfError::NonCanonicalField`] if either component is `>= p`.
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        let (first_bytes, second_bytes) = split_64_into_32s(bytes)?;
        let first = Fp::from_be_bytes(first_bytes)?;
        let second = Fp::from_be_bytes(second_bytes)?;

        // Security hotspot: single central switch on `FP2_COMPONENT_ORDER`.
        Ok(match FP2_COMPONENT_ORDER {
            Fp2ComponentOrder::C1ThenC0 => Self {
                c0: second,
                c1: first,
            },
            Fp2ComponentOrder::C0ThenC1 => Self {
                c0: first,
                c1: second,
            },
        })
    }

    /// Encodes this [`Fp2`] element as 64 bytes according to [`FP2_COMPONENT_ORDER`]
    /// (ACF Specification Section 3.3).
    #[must_use]
    pub fn encode(self) -> [u8; FP2_BYTE_LEN] {
        // Security hotspot: single central switch on `FP2_COMPONENT_ORDER`.
        match FP2_COMPONENT_ORDER {
            Fp2ComponentOrder::C1ThenC0 => concat_32(self.c1.encode(), self.c0.encode()),
            Fp2ComponentOrder::C0ThenC1 => concat_32(self.c0.encode(), self.c1.encode()),
        }
    }

    /// Returns `true` iff both `c0` and `c1` are zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    #[inline]
    pub(crate) const fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    #[inline]
    pub(crate) const fn double(self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    #[inline]
    pub(crate) const fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) const fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    /// Multiplies `(a0 + a1·u)(b0 + b1·u) = (a0·b0 - a1·b1) + (a0·b1 + a1·b0)·u`
    /// in `Fp[u]/(u^2 + 1)`.
    #[inline]
    pub(crate) const fn mul(self, rhs: Self) -> Self {
        let a0b0 = self.c0.mul(rhs.c0);
        let a1b1 = self.c1.mul(rhs.c1);
        let c0 = a0b0.sub(a1b1);
        let c1 = self
            .c0
            .add(self.c1)
            .mul(rhs.c0.add(rhs.c1))
            .sub(a0b0)
            .sub(a1b1);
        Self { c0, c1 }
    }

    /// Squares `(a0 + a1·u)^2 = (a0 - a1)(a0 + a1) + (2·a0·a1)·u` in `Fp[u]/(u^2 + 1)`.
    #[inline]
    pub(crate) const fn square(self) -> Self {
        let c0 = self.c0.sub(self.c1).mul(self.c0.add(self.c1));
        let c1 = self.c0.mul(self.c1).double();
        Self { c0, c1 }
    }
}

/// Decodes a canonical 32-byte [`Fp`] element (`decode_fp`, ACF Spec Section 3.1 & Section 9).
///
/// # Errors
///
/// Returns [`AcfError::BadLength`] or [`AcfError::NonCanonicalField`].
pub fn decode_fp(bytes: &[u8]) -> Result<Fp, AcfError> {
    Fp::decode(bytes)
}

/// Encodes a canonical [`Fp`] element as 32 big-endian bytes (ACF Spec Section 3.1).
#[must_use]
pub const fn encode_fp(fp: Fp) -> [u8; FP_BYTE_LEN] {
    fp.encode()
}

/// Decodes a canonical 32-byte [`Fr`] scalar (`decode_fr`, ACF Spec Section 3.1, 3.4 & Section 9).
///
/// # Errors
///
/// Returns [`AcfError::BadLength`] or [`AcfError::NonCanonicalField`].
pub fn decode_fr(bytes: &[u8]) -> Result<Fr, AcfError> {
    Fr::decode(bytes)
}

/// Encodes a canonical [`Fr`] scalar as 32 big-endian bytes (ACF Spec Section 3.1 & 3.4).
#[must_use]
pub const fn encode_fr(fr: Fr) -> [u8; FR_BYTE_LEN] {
    fr.encode()
}
