//! BN254 affine curve points [`G1`] (64 bytes) and [`G2`] (128 bytes).
//!
//! Implements ACF Specification Section 2, Section 3.2, Section 3.3, and
//! Section 9 Rules 1–4.

use crate::field::{concat_32, split_64_into_32s, Fp, Fp2, BN254_R_LIMBS};
use crate::AcfError;

/// Canonical byte length of an uncompressed [`G1`] point (ACF Spec Section 3.2).
pub const G1_BYTE_LEN: usize = 64;

/// Canonical byte length of an uncompressed [`G2`] point (ACF Spec Section 3.3).
pub const G2_BYTE_LEN: usize = 128;

/// Curve constant `b = 3` for BN254 `G1: y^2 = x^3 + 3` over `Fp` (ACF Spec Section 2).
const G1_COEFF_B: Fp = Fp::from_limbs_unchecked([3, 0, 0, 0]);

/// Twist curve constant `b' = 3 / (9 + u)` for BN254 `G2: y^2 = x^3 + b'` over
/// `Fp2 = Fp[u]/(u^2 + 1)` (CAP-0074 / Ethereum EIP-197 D-twist; sourced from
/// `ark_bn254::g2::Config::COEFF_B` and verified via `(9 + u) * b' == 3`).
pub(crate) const G2_TWIST_COEFF_B: Fp2 = Fp2 {
    c0: Fp::from_limbs_unchecked([
        0x3267_e6dc_24a1_38e5,
        0xb5b4_c5e5_59db_efa3,
        0x81be_1899_1be0_6ac3,
        0x2b14_9d40_ceb8_aaae,
    ]),
    c1: Fp::from_limbs_unchecked([
        0xe4a2_bd06_85c3_15d2,
        0xa74f_a084_e52d_1852,
        0xcd2c_afad_eed8_fdf4,
        0x0097_13b0_3af0_fed4,
    ]),
};

#[inline]
fn split_128_into_64s(bytes: &[u8]) -> Result<(&[u8; 64], &[u8; 64]), AcfError> {
    let arr: &[u8; 128] = bytes.try_into().map_err(|_| AcfError::BadLength)?;
    let (first, rest) = arr.split_first_chunk::<64>().ok_or(AcfError::BadLength)?;
    let second: &[u8; 64] = rest.try_into().map_err(|_| AcfError::BadLength)?;
    Ok((first, second))
}

#[inline]
fn concat_64(first: [u8; 64], second: [u8; 64]) -> [u8; 128] {
    let mut out = [0u8; 128];
    if let Some((head, tail)) = out.split_first_chunk_mut::<64>() {
        *head = first;
        if let Some((next, _)) = tail.split_first_chunk_mut::<64>() {
            *next = second;
        }
    }
    out
}

/// Validated BN254 [`G1`] point on `y^2 = x^3 + 3` over [`Fp`], or the point at
/// infinity (ACF Specification Section 3.2 and Section 9 Rules 1–3).
///
/// `G1` over `Fp` has cofactor `1`, so every on-curve point lies in the
/// prime-order-`r` subgroup (ACF Specification Section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct G1 {
    coords: Option<(Fp, Fp)>,
}

impl G1 {
    /// Point at infinity, encoded as 64 zero bytes (ACF Specification Section 3.2).
    pub const INFINITY: Self = Self { coords: None };

    /// Standard BN254 `G1` generator `(1, 2)` (ACF Specification Section 12).
    pub const GENERATOR: Self = Self {
        coords: Some((Fp::ONE, Fp::from_limbs_unchecked([2, 0, 0, 0]))),
    };

    /// Constructs a validated [`G1`] point from canonical coordinates `(x, y)`
    /// (ACF Specification Section 3.2 and Section 9 Rule 3).
    ///
    /// Per Section 3.2, `(0, 0)` represents [`G1::INFINITY`]. Any other `(x, y)`
    /// must satisfy `y^2 = x^3 + 3` in [`Fp`].
    ///
    /// # Errors
    ///
    /// Returns [`AcfError::NotOnCurve`] if `(x, y) != (0, 0)` does not satisfy
    /// `y^2 = x^3 + 3`.
    pub fn from_coordinates(x: Fp, y: Fp) -> Result<Self, AcfError> {
        if x.is_zero() && y.is_zero() {
            return Ok(Self::INFINITY);
        }
        let lhs = y.square();
        let rhs = x.square().mul(x).add(G1_COEFF_B);
        if lhs != rhs {
            return Err(AcfError::NotOnCurve);
        }
        Ok(Self {
            coords: Some((x, y)),
        })
    }

    /// Decodes and validates a 64-byte uncompressed [`G1`] point
    /// (ACF Specification Section 3.2 and Section 9 Rules 1–3).
    ///
    /// Validation order strictly follows Section 9:
    /// 1. Exact 64-byte length (`ERR_BAD_LENGTH`)
    /// 2. Canonical `Fp` coordinates `< p` (`ERR_NON_CANONICAL_FIELD`)
    /// 3. All-zero infinity check, else `y^2 = x^3 + 3` (`ERR_NOT_ON_CURVE`)
    ///
    /// # Errors
    ///
    /// Returns [`AcfError::BadLength`], [`AcfError::NonCanonicalField`], or
    /// [`AcfError::NotOnCurve`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        let (x_bytes, y_bytes) = split_64_into_32s(bytes)?;
        let x = Fp::from_be_bytes(x_bytes)?;
        let y = Fp::from_be_bytes(y_bytes)?;
        Self::from_coordinates(x, y)
    }

    /// Encodes this [`G1`] point as 64 bytes (`be32(x) ‖ be32(y)`, or 64 zero
    /// bytes for infinity; ACF Specification Section 3.2).
    #[must_use]
    pub fn encode(self) -> [u8; G1_BYTE_LEN] {
        match self.coords {
            None => [0u8; G1_BYTE_LEN],
            Some((x, y)) => concat_32(x.encode(), y.encode()),
        }
    }

    /// Returns `true` iff this point is the point at infinity (ACF Spec Section 3.2).
    #[must_use]
    pub const fn is_infinity(self) -> bool {
        self.coords.is_none()
    }

    /// Returns the affine coordinates `(x, y)` if finite, or `None` for infinity
    /// (ACF Specification Section 3.2).
    #[must_use]
    pub const fn coordinates(self) -> Option<(Fp, Fp)> {
        self.coords
    }
}

/// Jacobian point `(X : Y : Z)` representing affine `(X / Z^2, Y / Z^3)` on the
/// short Weierstrass twist curve `y^2 = x^3 + b'` (`a = 0`) over [`Fp2`].
///
/// Infinity is represented by `Z = 0`. Both [`Self::double`] and [`Self::add`]
/// handle all edge cases (`O`, `P + P`, `P + (-P)`, and 2-torsion `Y = 0`), making
/// the group law complete over [`Fp2`].
#[derive(Clone, Copy)]
pub(crate) struct G2Jacobian {
    pub(crate) x: Fp2,
    pub(crate) y: Fp2,
    pub(crate) z: Fp2,
}

impl G2Jacobian {
    pub(crate) const INFINITY: Self = Self {
        x: Fp2::ONE,
        y: Fp2::ONE,
        z: Fp2::ZERO,
    };

    #[inline]
    pub(crate) const fn from_affine(x: Fp2, y: Fp2) -> Self {
        Self { x, y, z: Fp2::ONE }
    }

    #[inline]
    pub(crate) const fn is_infinity(self) -> bool {
        self.z.is_zero()
    }

    /// Complete Jacobian point doubling for `y^2 = x^3 + b'` (`a = 0`, EFD `dbl-2009-l`).
    pub(crate) fn double(self) -> Self {
        if self.z.is_zero() || self.y.is_zero() {
            return Self::INFINITY;
        }

        let a = self.x.square(); // X1^2
        let b = self.y.square(); // Y1^2
        let c = b.square(); // Y1^4
                            // D = 2 * ((X1 + B)^2 - A - C) = 4 * X1 * Y1^2
        let d = self.x.add(b).square().sub(a).sub(c).double();
        // E = 3 * A = 3 * X1^2
        let e = a.double().add(a);
        let f = e.square();
        // X3 = F - 2 * D
        let x3 = f.sub(d.double());
        // Y3 = E * (D - X3) - 8 * C
        let eight_c = c.double().double().double();
        let y3 = e.mul(d.sub(x3)).sub(eight_c);
        // Z3 = 2 * Y1 * Z1 (non-zero since Y1 != 0, Z1 != 0 in field Fp2 of char p > 2)
        let z3 = self.y.mul(self.z).double();

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete Jacobian point addition for `y^2 = x^3 + b'` (`a = 0`, EFD `add-2007-bl`).
    pub(crate) fn add(self, rhs: Self) -> Self {
        if self.z.is_zero() {
            return rhs;
        }
        if rhs.z.is_zero() {
            return self;
        }

        let z1z1 = self.z.square();
        let z2z2 = rhs.z.square();
        let u1 = self.x.mul(z2z2);
        let u2 = rhs.x.mul(z1z1);
        let s1 = self.y.mul(rhs.z).mul(z2z2);
        let s2 = rhs.y.mul(self.z).mul(z1z1);

        if u1 == u2 {
            // Same affine x-coordinate: either equal points (`y1 == y2`) or inverses (`y1 == -y2`).
            return if s1 == s2 {
                self.double()
            } else {
                Self::INFINITY
            };
        }

        let h = u2.sub(u1); // non-zero since u1 != u2
        let i = h.double().square(); // (2 * H)^2 = 4 * H^2
        let j = h.mul(i); // 4 * H^3
        let r = s2.sub(s1).double(); // 2 * (S2 - S1)
        let v = u1.mul(i); // 4 * U1 * H^2

        let x3 = r.square().sub(j).sub(v.double());
        let y3 = r.mul(v.sub(x3)).sub(s1.mul(j).double());
        let z3 = self.z.mul(rhs.z).mul(h).double();

        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

/// Security hotspot (AGENTS.md Section 11): checks whether an on-curve twist point
/// `P = (x, y)` lies in the prime-order-`r` [`G2`] subgroup by verifying `[r]P == O`.
///
/// Because `r` is prime and coprime to the BN254 twist cofactor `h_2 = 2p - r`,
/// a point on `E'(Fp2)` belongs to the `G2` subgroup if and only if `[r]P == O`.
fn is_in_g2_subgroup(x: Fp2, y: Fp2) -> bool {
    let base = G2Jacobian::from_affine(x, y);
    let [r0, r1, r2, r3] = BN254_R_LIMBS;
    let limbs_be = [r3, r2, r1, r0];

    let mut acc = G2Jacobian::INFINITY;
    for limb in limbs_be {
        let mut shift = 64u32;
        while shift > 0 {
            shift -= 1;
            acc = acc.double();
            if ((limb >> shift) & 1) == 1 {
                acc = acc.add(base);
            }
        }
    }

    acc.is_infinity()
}

/// Validated BN254 [`G2`] point in the prime-order-`r` subgroup of the twist
/// curve `y^2 = x^3 + 3/(9 + u)` over [`Fp2`], or the point at infinity
/// (ACF Specification Section 3.3 and Section 9 Rules 1–4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct G2 {
    coords: Option<(Fp2, Fp2)>,
}

impl G2 {
    /// Point at infinity, encoded as 128 zero bytes (ACF Specification Section 3.3).
    pub const INFINITY: Self = Self { coords: None };

    /// Canonical BN254 G2 generator point (ACF Spec Section 3.3 and Section 12).
    pub const GENERATOR: Self = Self {
        coords: Some((
            Fp2 {
                c0: Fp::from_limbs_unchecked([
                    0x46de_bd5c_d992_f6ed,
                    0x6743_22d4_f75e_dadd,
                    0x426a_0066_5e5c_4479,
                    0x1800_deef_121f_1e76,
                ]),
                c1: Fp::from_limbs_unchecked([
                    0x97e4_85b7_aef3_12c2,
                    0xf1aa_4933_35a9_e712,
                    0x7260_bfb7_31fb_5d25,
                    0x198e_9393_920d_483a,
                ]),
            },
            Fp2 {
                c0: Fp::from_limbs_unchecked([
                    0x4ce6_cc01_66fa_7daa,
                    0xe3d1_e769_0c43_d37b,
                    0x4aab_7180_8dcb_408f,
                    0x12c8_5ea5_db8c_6deb,
                ]),
                c1: Fp::from_limbs_unchecked([
                    0x55ac_dadc_d122_975b,
                    0xbc4b_3133_70b3_8ef3,
                    0xec9e_99ad_690c_3395,
                    0x0906_89d0_585f_f075,
                ]),
            },
        )),
    };

    /// Constructs a validated [`G2`] point from canonical [`Fp2`] coordinates `(x, y)`
    /// (ACF Specification Section 3.3 and Section 9 Rules 3–4).
    ///
    /// Per Section 3.3, `(0, 0)` represents [`G2::INFINITY`]. Any non-infinity
    /// point must satisfy the twist curve equation (`ERR_NOT_ON_CURVE`) AND lie
    /// in the prime-order-`r` subgroup (`ERR_NOT_IN_SUBGROUP`).
    ///
    /// # Errors
    ///
    /// - [`AcfError::NotOnCurve`] if `(x, y) != (0, 0)` fails `y^2 = x^3 + 3/(9 + u)`.
    /// - [`AcfError::NotInSubgroup`] if `(x, y)` is on the twist curve but `[r](x, y) != O`.
    pub fn from_coordinates(x: Fp2, y: Fp2) -> Result<Self, AcfError> {
        if x.is_zero() && y.is_zero() {
            return Ok(Self::INFINITY);
        }

        // Spec Section 9 Rule 3: twist curve equation check precedes subgroup check.
        let lhs = y.square();
        let rhs = x.square().mul(x).add(G2_TWIST_COEFF_B);
        if lhs != rhs {
            return Err(AcfError::NotOnCurve);
        }

        // Spec Section 9 Rule 4: mandatory prime-order-`r` subgroup membership check.
        if !is_in_g2_subgroup(x, y) {
            return Err(AcfError::NotInSubgroup);
        }

        Ok(Self {
            coords: Some((x, y)),
        })
    }

    /// Decodes and validates a 128-byte uncompressed [`G2`] point
    /// (ACF Specification Section 3.3 and Section 9 Rules 1–4).
    ///
    /// Validation order strictly follows Section 9:
    /// 1. Exact 128-byte length (`ERR_BAD_LENGTH`)
    /// 2. Canonical `Fp` components `< p` via [`crate::FP2_COMPONENT_ORDER`] (`ERR_NON_CANONICAL_FIELD`)
    /// 3. All-zero infinity check, else twist curve equation (`ERR_NOT_ON_CURVE`)
    /// 4. Prime-order-`r` subgroup membership (`ERR_NOT_IN_SUBGROUP`)
    ///
    /// # Errors
    ///
    /// Returns [`AcfError::BadLength`], [`AcfError::NonCanonicalField`],
    /// [`AcfError::NotOnCurve`], or [`AcfError::NotInSubgroup`].
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        let (x_bytes, y_bytes) = split_128_into_64s(bytes)?;
        let x = Fp2::decode(x_bytes)?;
        let y = Fp2::decode(y_bytes)?;
        Self::from_coordinates(x, y)
    }

    /// Encodes this [`G2`] point as 128 bytes according to [`crate::FP2_COMPONENT_ORDER`],
    /// or 128 zero bytes for infinity (ACF Specification Section 3.3).
    #[must_use]
    pub fn encode(self) -> [u8; G2_BYTE_LEN] {
        match self.coords {
            None => [0u8; G2_BYTE_LEN],
            Some((x, y)) => concat_64(x.encode(), y.encode()),
        }
    }

    /// Returns `true` iff this point is the point at infinity (ACF Spec Section 3.3).
    #[must_use]
    pub const fn is_infinity(self) -> bool {
        self.coords.is_none()
    }

    /// Returns the affine [`Fp2`] coordinates `(x, y)` if finite, or `None` for
    /// infinity (ACF Specification Section 3.3).
    #[must_use]
    pub const fn coordinates(self) -> Option<(Fp2, Fp2)> {
        self.coords
    }
}

/// Decodes and validates a 64-byte [`G1`] point (`decode_g1`, ACF Spec Section 3.2 & Section 9).
///
/// # Errors
///
/// Returns [`AcfError::BadLength`], [`AcfError::NonCanonicalField`], or [`AcfError::NotOnCurve`].
pub fn decode_g1(bytes: &[u8]) -> Result<G1, AcfError> {
    G1::decode(bytes)
}

/// Encodes a [`G1`] point as 64 uncompressed bytes (ACF Spec Section 3.2).
#[must_use]
pub fn encode_g1(point: G1) -> [u8; G1_BYTE_LEN] {
    point.encode()
}

/// Decodes and validates a 128-byte [`G2`] point (`decode_g2`, ACF Spec Section 3.3 & Section 9).
///
/// # Errors
///
/// Returns [`AcfError::BadLength`], [`AcfError::NonCanonicalField`],
/// [`AcfError::NotOnCurve`], or [`AcfError::NotInSubgroup`].
pub fn decode_g2(bytes: &[u8]) -> Result<G2, AcfError> {
    G2::decode(bytes)
}

/// Encodes a [`G2`] point as 128 uncompressed bytes (ACF Spec Section 3.3).
#[must_use]
pub fn encode_g2(point: G2) -> [u8; G2_BYTE_LEN] {
    point.encode()
}
