//! Groth16 proof, verification key, and public inputs types and codecs.
//!
//! Implements ACF Specification Section 4 and Section 9.

extern crate alloc;

use crate::curve::{decode_g1, decode_g2, G1, G1_BYTE_LEN, G2};
use crate::field::{decode_fr, Fr, FR_BYTE_LEN};
use crate::AcfError;
use alloc::vec::Vec;

/// Exact byte length of a Groth16 proof payload `A ‖ B ‖ C` (ACF Spec Section 4.1).
pub const PROOF_BYTE_LEN: usize = 256;

/// Exact byte length of the fixed header in a Groth16 verification key payload (ACF Spec Section 4.2).
pub const VK_HEADER_BYTE_LEN: usize = 452;

/// Validated Groth16 proof payload `A ‖ B ‖ C` (ACF Spec Section 4.1, Section 9).
///
/// Point `A` is not negated; negation is performed on-chain by the verifier
/// (ACF Spec Section 4.1, Section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// Proof point `A` in G1 (64 bytes).
    pub a: G1,
    /// Proof point `B` in G2 (128 bytes).
    pub b: G2,
    /// Proof point `C` in G1 (64 bytes).
    pub c: G1,
}

impl Proof {
    /// Decodes and strictly validates a 256-byte Groth16 proof payload (ACF Spec Section 4.1).
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        decode_proof(bytes)
    }

    /// Encodes this proof into its 256-byte canonical representation (ACF Spec Section 4.1).
    #[must_use]
    pub fn encode(&self) -> [u8; PROOF_BYTE_LEN] {
        encode_proof(self)
    }
}

/// Decodes and strictly validates a 256-byte Groth16 proof payload `A ‖ B ‖ C`
/// (ACF Spec Section 4.1 and Section 9 Rules 1–4, 6).
///
/// Order of validation:
/// 1. Exact length must be 256 bytes ([`AcfError::BadLength`]).
/// 2. Canonical field coordinates `< p` ([`AcfError::NonCanonicalField`]).
/// 3. Points satisfy curve equations ([`AcfError::NotOnCurve`]).
/// 4. Point `B` lies in the order-`r` subgroup ([`AcfError::NotInSubgroup`]).
/// 5. Points `A`, `B`, `C` MUST NOT be infinity ([`AcfError::InvalidProof`]).
pub fn decode_proof(bytes: &[u8]) -> Result<Proof, AcfError> {
    if bytes.len() != PROOF_BYTE_LEN {
        return Err(AcfError::BadLength);
    }

    let a_bytes = bytes.get(0..64).ok_or(AcfError::BadLength)?;
    let b_bytes = bytes.get(64..192).ok_or(AcfError::BadLength)?;
    let c_bytes = bytes.get(192..256).ok_or(AcfError::BadLength)?;

    let a = decode_g1(a_bytes)?;
    let b = decode_g2(b_bytes)?;
    let c = decode_g1(c_bytes)?;

    if a.is_infinity() || b.is_infinity() || c.is_infinity() {
        return Err(AcfError::InvalidProof);
    }

    Ok(Proof { a, b, c })
}

/// Encodes a Groth16 proof into its 256-byte canonical representation `A ‖ B ‖ C`
/// (ACF Spec Section 4.1).
///
/// The encoder does not negate `A`.
#[must_use]
pub fn encode_proof(proof: &Proof) -> [u8; PROOF_BYTE_LEN] {
    let mut out = [0u8; PROOF_BYTE_LEN];
    let a_enc = proof.a.encode();
    let b_enc = proof.b.encode();
    let c_enc = proof.c.encode();

    if let Some(slice) = out.get_mut(0..64) {
        slice.copy_from_slice(&a_enc);
    }
    if let Some(slice) = out.get_mut(64..192) {
        slice.copy_from_slice(&b_enc);
    }
    if let Some(slice) = out.get_mut(192..256) {
        slice.copy_from_slice(&c_enc);
    }
    out
}

/// Validated Groth16 verification key payload (ACF Spec Section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey {
    /// Verification key point `alpha_g1` in G1 (64 bytes).
    pub alpha_g1: G1,
    /// Verification key point `beta_g2` in G2 (128 bytes).
    pub beta_g2: G2,
    /// Verification key point `gamma_g2` in G2 (128 bytes).
    pub gamma_g2: G2,
    /// Verification key point `delta_g2` in G2 (128 bytes).
    pub delta_g2: G2,
    /// Ordered list of `n_ic` G1 points `IC[0..n_ic-1]` (64 bytes each).
    pub ic: Vec<G1>,
}

impl VerificationKey {
    /// Decodes and strictly validates a Groth16 verification key payload (ACF Spec Section 4.2).
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        decode_vk(bytes)
    }

    /// Encodes this verification key into its canonical byte representation (ACF Spec Section 4.2).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_vk(self)
    }

    /// Number of IC points (`n_ic = n_public + 1`).
    #[must_use]
    pub fn n_ic(&self) -> usize {
        self.ic.len()
    }

    /// Expected number of public inputs (`n_public = n_ic - 1`).
    #[must_use]
    pub fn n_public(&self) -> usize {
        self.ic.len().saturating_sub(1)
    }

    /// Validates that the number of public inputs matches `n_ic - 1`
    /// (ACF Spec Section 4.3 and Section 9 Rule 5).
    pub fn validate_public_inputs(&self, public_inputs: &PublicInputs) -> Result<(), AcfError> {
        if self.ic.len() != public_inputs.inputs.len().saturating_add(1) {
            return Err(AcfError::PublicInputCount);
        }
        Ok(())
    }
}

/// Decodes and strictly validates a Groth16 verification key payload (ACF Spec Section 4.2).
pub fn decode_vk(bytes: &[u8]) -> Result<VerificationKey, AcfError> {
    if bytes.len() < VK_HEADER_BYTE_LEN {
        return Err(AcfError::BadLength);
    }

    let n_ic_slice = bytes.get(448..452).ok_or(AcfError::BadLength)?;
    let mut n_ic_arr = [0u8; 4];
    n_ic_arr.copy_from_slice(n_ic_slice);
    let n_ic_u32 = u32::from_be_bytes(n_ic_arr);

    // ACF Spec §4.2: n_ic = n_public + 1. Since n_public >= 0, n_ic >= 1.
    if n_ic_u32 == 0 {
        return Err(AcfError::PublicInputCount);
    }

    let n_ic = usize::try_from(n_ic_u32).map_err(|_| AcfError::BadLength)?;
    let ic_len = n_ic.checked_mul(G1_BYTE_LEN).ok_or(AcfError::BadLength)?;
    let total_expected = VK_HEADER_BYTE_LEN
        .checked_add(ic_len)
        .ok_or(AcfError::BadLength)?;

    if bytes.len() != total_expected {
        return Err(AcfError::BadLength);
    }

    let alpha_bytes = bytes.get(0..64).ok_or(AcfError::BadLength)?;
    let beta_bytes = bytes.get(64..192).ok_or(AcfError::BadLength)?;
    let gamma_bytes = bytes.get(192..320).ok_or(AcfError::BadLength)?;
    let delta_bytes = bytes.get(320..448).ok_or(AcfError::BadLength)?;

    let alpha_g1 = decode_g1(alpha_bytes)?;
    let beta_g2 = decode_g2(beta_bytes)?;
    let gamma_g2 = decode_g2(gamma_bytes)?;
    let delta_g2 = decode_g2(delta_bytes)?;

    let mut ic = Vec::with_capacity(n_ic);
    for i in 0..n_ic {
        let offset = i.checked_mul(G1_BYTE_LEN).ok_or(AcfError::BadLength)?;
        let start = VK_HEADER_BYTE_LEN
            .checked_add(offset)
            .ok_or(AcfError::BadLength)?;
        let end = start.checked_add(G1_BYTE_LEN).ok_or(AcfError::BadLength)?;
        let ic_chunk = bytes.get(start..end).ok_or(AcfError::BadLength)?;
        let pt = decode_g1(ic_chunk)?;
        ic.push(pt);
    }

    Ok(VerificationKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

/// Encodes a Groth16 verification key into canonical byte representation (ACF Spec Section 4.2).
#[must_use]
pub fn encode_vk(vk: &VerificationKey) -> Vec<u8> {
    let n_ic = vk.ic.len();
    let total_len = VK_HEADER_BYTE_LEN.saturating_add(n_ic.saturating_mul(G1_BYTE_LEN));
    let mut out = Vec::with_capacity(total_len);

    out.extend_from_slice(&vk.alpha_g1.encode());
    out.extend_from_slice(&vk.beta_g2.encode());
    out.extend_from_slice(&vk.gamma_g2.encode());
    out.extend_from_slice(&vk.delta_g2.encode());
    let n_ic_u32 = u32::try_from(n_ic).unwrap_or(u32::MAX);
    out.extend_from_slice(&n_ic_u32.to_be_bytes());
    for pt in &vk.ic {
        out.extend_from_slice(&pt.encode());
    }
    out
}

/// Validated Groth16 public inputs payload (ACF Spec Section 4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicInputs {
    /// Public input scalars in circuit declaration order.
    pub inputs: Vec<Fr>,
}

impl PublicInputs {
    /// Decodes and strictly validates a Groth16 public inputs payload (ACF Spec Section 4.3).
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        decode_public_inputs(bytes)
    }

    /// Encodes these public inputs into canonical byte representation (ACF Spec Section 4.3).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_public_inputs(self)
    }

    /// Number of public input scalars.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Returns `true` if there are no public inputs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Validates count against verification key (ACF Spec Section 4.3 and Section 9 Rule 5).
    pub fn validate_with_vk(&self, vk: &VerificationKey) -> Result<(), AcfError> {
        vk.validate_public_inputs(self)
    }
}

/// Decodes and strictly validates Groth16 public inputs payload (ACF Spec Section 4.3).
///
/// Each 32-byte chunk is decoded as an [`Fr`] element; values `>= r` are rejected
/// as non-canonical ([`AcfError::NonCanonicalField`]).
pub fn decode_public_inputs(bytes: &[u8]) -> Result<PublicInputs, AcfError> {
    if !bytes.len().is_multiple_of(FR_BYTE_LEN) {
        return Err(AcfError::BadLength);
    }

    let count = bytes.len() / FR_BYTE_LEN;
    let mut inputs = Vec::with_capacity(count);
    for i in 0..count {
        let start = i.checked_mul(FR_BYTE_LEN).ok_or(AcfError::BadLength)?;
        let end = start.checked_add(FR_BYTE_LEN).ok_or(AcfError::BadLength)?;
        let chunk = bytes.get(start..end).ok_or(AcfError::BadLength)?;
        let fr = decode_fr(chunk)?;
        inputs.push(fr);
    }

    Ok(PublicInputs { inputs })
}

/// Encodes Groth16 public inputs into canonical byte representation (ACF Spec Section 4.3).
#[must_use]
pub fn encode_public_inputs(public_inputs: &PublicInputs) -> Vec<u8> {
    let mut out = Vec::with_capacity(public_inputs.inputs.len().saturating_mul(FR_BYTE_LEN));
    for fr in &public_inputs.inputs {
        out.extend_from_slice(&fr.encode());
    }
    out
}
