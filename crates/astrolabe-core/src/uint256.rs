//! Fixed-width 256-bit unsigned integer arithmetic for canonical BN254 fields.
//!
//! Internal representation is four little-endian `u64` limbs `[l0, l1, l2, l3]`
//! representing `l0 + l1·2^64 + l2·2^128 + l3·2^192`.
//!
//! All functions avoid slice indexing, panics, and heap allocation (`#![no_std]`).

use core::cmp::Ordering;

/// Converts a 32-byte big-endian buffer (`be32`) into four little-endian `u64` limbs.
#[inline]
pub(crate) const fn from_be_bytes_32(bytes: &[u8; 32]) -> [u64; 4] {
    let [b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31] =
        *bytes;

    [
        u64::from_be_bytes([b24, b25, b26, b27, b28, b29, b30, b31]),
        u64::from_be_bytes([b16, b17, b18, b19, b20, b21, b22, b23]),
        u64::from_be_bytes([b8, b9, b10, b11, b12, b13, b14, b15]),
        u64::from_be_bytes([b0, b1, b2, b3, b4, b5, b6, b7]),
    ]
}

/// Encodes four little-endian `u64` limbs as a 32-byte big-endian buffer (`be32`).
#[inline]
pub(crate) const fn to_be_bytes_32(limbs: [u64; 4]) -> [u8; 32] {
    let [l0, l1, l2, l3] = limbs;
    let [b0, b1, b2, b3, b4, b5, b6, b7] = l3.to_be_bytes();
    let [b8, b9, b10, b11, b12, b13, b14, b15] = l2.to_be_bytes();
    let [b16, b17, b18, b19, b20, b21, b22, b23] = l1.to_be_bytes();
    let [b24, b25, b26, b27, b28, b29, b30, b31] = l0.to_be_bytes();

    [
        b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19,
        b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31,
    ]
}

/// Returns `true` iff all four limbs are zero.
#[inline]
pub(crate) const fn is_zero_limbs(limbs: [u64; 4]) -> bool {
    let [l0, l1, l2, l3] = limbs;
    (l0 | l1 | l2 | l3) == 0
}

/// Compares two 256-bit integers from most-significant limb (`l3`) to least (`l0`).
#[inline]
pub(crate) const fn cmp_limbs(a: [u64; 4], b: [u64; 4]) -> Ordering {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;

    if a3 != b3 {
        return if a3 < b3 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if a2 != b2 {
        return if a2 < b2 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if a1 != b1 {
        return if a1 < b1 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if a0 != b0 {
        return if a0 < b0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    Ordering::Equal
}

/// Returns `true` iff `a < b`.
#[inline]
pub(crate) const fn lt_limbs(a: [u64; 4], b: [u64; 4]) -> bool {
    matches!(cmp_limbs(a, b), Ordering::Less)
}

/// Returns `true` iff `a >= b`.
#[inline]
pub(crate) const fn gte_limbs(a: [u64; 4], b: [u64; 4]) -> bool {
    !lt_limbs(a, b)
}

#[inline]
const fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
    let sum = (a as u128) + (b as u128) + (carry as u128);
    (sum as u64, (sum >> 64) as u64)
}

#[inline]
const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
    let subtrahend = (b as u128) + (borrow as u128);
    if (a as u128) >= subtrahend {
        (((a as u128) - subtrahend) as u64, 0)
    } else {
        ((((1u128 << 64) + (a as u128)) - subtrahend) as u64, 1)
    }
}

/// Computes `a + b` when `a + b < 2^256` (always holds when `a, b < 2^255`).
#[inline]
const fn add_limbs_no_overflow(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;
    let (r0, c0) = adc(a0, b0, 0);
    let (r1, c1) = adc(a1, b1, c0);
    let (r2, c2) = adc(a2, b2, c1);
    let (r3, _) = adc(a3, b3, c2);
    [r0, r1, r2, r3]
}

/// Computes `a - b` assuming `a >= b`.
#[inline]
const fn sub_limbs_unchecked(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;
    let (r0, br0) = sbb(a0, b0, 0);
    let (r1, br1) = sbb(a1, b1, br0);
    let (r2, br2) = sbb(a2, b2, br1);
    let (r3, _) = sbb(a3, b3, br2);
    [r0, r1, r2, r3]
}

/// Modular addition `(a + b) mod m` for canonical `a, b < m < 2^255`.
///
/// Because `m < 2^255` (BN254 `p, r < 2^254`), `a + b < 2m < 2^256` never
/// overflows 256 bits, and subtracting `m` at most once restores `[0, m)`.
#[inline]
pub(crate) const fn add_mod_254(a: [u64; 4], b: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
    let sum = add_limbs_no_overflow(a, b);
    if gte_limbs(sum, modulus) {
        sub_limbs_unchecked(sum, modulus)
    } else {
        sum
    }
}

/// Modular subtraction `(a - b) mod m` for canonical `a, b < m < 2^255`.
#[inline]
pub(crate) const fn sub_mod_254(a: [u64; 4], b: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
    if gte_limbs(a, b) {
        sub_limbs_unchecked(a, b)
    } else {
        let lifted = add_limbs_no_overflow(a, modulus);
        sub_limbs_unchecked(lifted, b)
    }
}

/// Modular negation `(-a) mod m` for canonical `a < m`.
#[inline]
pub(crate) const fn neg_mod(a: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
    if is_zero_limbs(a) {
        [0, 0, 0, 0]
    } else {
        sub_limbs_unchecked(modulus, a)
    }
}

#[inline]
const fn mac(acc: u64, x: u64, y: u64, carry: u64) -> (u64, u64) {
    let full = (acc as u128) + (x as u128) * (y as u128) + (carry as u128);
    (full as u64, (full >> 64) as u64)
}

/// Exact 512-bit product `a * b = high * 2^256 + low`.
#[inline]
const fn mul_wide(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], [u64; 4]) {
    let [a0, a1, a2, a3] = a;
    let [b0, b1, b2, b3] = b;

    let (r0, c) = mac(0, a0, b0, 0);
    let (r1, c) = mac(0, a0, b1, c);
    let (r2, c) = mac(0, a0, b2, c);
    let (r3, r4) = mac(0, a0, b3, c);

    let (r1, c) = mac(r1, a1, b0, 0);
    let (r2, c) = mac(r2, a1, b1, c);
    let (r3, c) = mac(r3, a1, b2, c);
    let (r4, r5) = mac(r4, a1, b3, c);

    let (r2, c) = mac(r2, a2, b0, 0);
    let (r3, c) = mac(r3, a2, b1, c);
    let (r4, c) = mac(r4, a2, b2, c);
    let (r5, r6) = mac(r5, a2, b3, c);

    let (r3, c) = mac(r3, a3, b0, 0);
    let (r4, c) = mac(r4, a3, b1, c);
    let (r5, c) = mac(r5, a3, b2, c);
    let (r6, r7) = mac(r6, a3, b3, c);

    ([r0, r1, r2, r3], [r4, r5, r6, r7])
}

#[inline]
const fn shift_left_1_and_reduce(rem: [u64; 4], bit: u64, modulus: [u64; 4]) -> [u64; 4] {
    let [r0, r1, r2, r3] = rem;
    // Invariant: `rem < modulus < 2^254`, so `rem << 1 < 2^255` never overflows `r3`.
    let shifted = [
        (r0 << 1) | (bit & 1),
        (r1 << 1) | (r0 >> 63),
        (r2 << 1) | (r1 >> 63),
        (r3 << 1) | (r2 >> 63),
    ];
    if gte_limbs(shifted, modulus) {
        sub_limbs_unchecked(shifted, modulus)
    } else {
        shifted
    }
}

#[inline]
const fn reduce_limb_bits(mut rem: [u64; 4], word: u64, modulus: [u64; 4]) -> [u64; 4] {
    let mut shift = 64u32;
    while shift > 0 {
        shift -= 1;
        rem = shift_left_1_and_reduce(rem, word >> shift, modulus);
    }
    rem
}

/// Modular multiplication `(a * b) mod m` for canonical `a, b < m < 2^254`.
///
/// Since `a, b < m < 2^254 < 2^256`, `a * b < m * 2^256`, so the upper 256-bit
/// half `high = (a * b) >> 256` already satisfies `high < m`. Folding the lower
/// 256 bits into `high` one bit at a time preserves `rem < m` with zero extra
/// modulus-dependent constants.
#[inline]
pub(crate) const fn mul_mod_254(a: [u64; 4], b: [u64; 4], modulus: [u64; 4]) -> [u64; 4] {
    let ([l0, l1, l2, l3], high) = mul_wide(a, b);
    let rem = reduce_limb_bits(high, l3, modulus);
    let rem = reduce_limb_bits(rem, l2, modulus);
    let rem = reduce_limb_bits(rem, l1, modulus);
    reduce_limb_bits(rem, l0, modulus)
}
