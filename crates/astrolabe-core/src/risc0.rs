//! RISC Zero Groth16 adapter conforming to ACF Spec Section 10.3.
//!
//! Provides parsing and conversion of RISC Zero Groth16 seals (256 bytes uncompressed
//! affine G1/G2/G1 points), image IDs, and journal digest mappings into canonical
//! ACF [`Proof`] and [`PublicInputs`] objects.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::envelope::{ArtifactKind, CurveId, Envelope, EnvelopePayload, ProofSystemId};
use crate::field::decode_fr;
use crate::groth16::{decode_proof, Proof, PublicInputs};
use crate::snarkjs::{parse_hex_bytes_32, parse_json, JsonValue};
use crate::AcfError;

/// Mapping scheme for converting RISC Zero `image_id` and `journal_digest` into [`PublicInputs`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Risc0PublicInputsMode {
    /// 4-scalar representation splitting each 32-byte digest into two 16-byte limbs
    /// (`[image_id_high, image_id_low, journal_high, journal_low]`).
    ///
    /// Matches the standard RISC Zero Bonsai / EVM recursion verifier circuit.
    /// Each 16-byte limb is guaranteed `< 2^128 < r`, ensuring canonical scalar range.
    #[default]
    Limb16,

    /// 2-scalar direct representation treating each 32-byte digest as a single [`Fr`] scalar.
    ///
    /// Both digests must be strictly below the BN254 scalar field modulus `r`.
    Direct,
}

/// Fully parsed and verified RISC Zero Groth16 receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Risc0Receipt {
    /// Canonical 256-byte Groth16 proof.
    pub proof: Proof,
    /// Derived canonical public inputs.
    pub public_inputs: PublicInputs,
    /// 32-byte guest image ID digest.
    pub image_id: [u8; 32],
    /// 32-byte journal SHA-256 digest.
    pub journal_digest: [u8; 32],
}

/// Computes the standard NIST SHA-256 hash of arbitrary bytes.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut buf = Vec::with_capacity(data.len() + 72);
    buf.extend_from_slice(data);
    buf.push(0x80);
    while (buf.len() % 64) != 56 {
        buf.push(0x00);
    }
    buf.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in buf.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let start = i * 4;
            if let Some(slice) = chunk.get(start..start + 4) {
                let mut b = [0u8; 4];
                b.copy_from_slice(slice);
                if let Some(entry) = w.get_mut(i) {
                    *entry = u32::from_be_bytes(b);
                }
            }
        }
        for i in 16..64 {
            let w_i15 = *w.get(i - 15).unwrap_or(&0);
            let s0 = w_i15.rotate_right(7) ^ w_i15.rotate_right(18) ^ (w_i15 >> 3);
            let w_i2 = *w.get(i - 2).unwrap_or(&0);
            let s1 = w_i2.rotate_right(17) ^ w_i2.rotate_right(19) ^ (w_i2 >> 10);
            let w_i16 = *w.get(i - 16).unwrap_or(&0);
            let w_i7 = *w.get(i - 7).unwrap_or(&0);
            if let Some(entry) = w.get_mut(i) {
                *entry = w_i16.wrapping_add(s0).wrapping_add(w_i7).wrapping_add(s1);
            }
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut h_var = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let k_i = *K.get(i).unwrap_or(&0);
            let w_i = *w.get(i).unwrap_or(&0);
            let temp1 = h_var
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k_i)
                .wrapping_add(w_i);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h_var = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(h_var);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        let b = val.to_be_bytes();
        let start = i * 4;
        if let Some(slice) = out.get_mut(start..start + 4) {
            slice.copy_from_slice(&b);
        }
    }
    out
}

/// Maps a 256-byte RISC Zero Groth16 seal into a canonical [`Proof`].
///
/// Enforces all validation rules: point length, canonical field range, curve equations,
/// G2 order-`r` subgroup check, and rejection of degenerate infinity points.
pub fn map_risc0_seal(seal_bytes: &[u8]) -> Result<Proof, AcfError> {
    if seal_bytes.len() != 256 {
        return Err(AcfError::BadLength);
    }
    decode_proof(seal_bytes)
}

/// Maps RISC Zero `image_id` and `journal_digest` into canonical [`PublicInputs`].
pub fn map_risc0_journal_and_image_id(
    image_id: &[u8; 32],
    journal_digest: &[u8; 32],
    mode: Risc0PublicInputsMode,
) -> Result<PublicInputs, AcfError> {
    match mode {
        Risc0PublicInputsMode::Limb16 => {
            // Split each 32-byte digest into high and low 16-byte limbs,
            // left-padded with 16 zeros to form a 32-byte big-endian Fr scalar.
            let mut inputs = Vec::with_capacity(4);

            let mut limb0 = [0u8; 32];
            let mut limb1 = [0u8; 32];
            let mut limb2 = [0u8; 32];
            let mut limb3 = [0u8; 32];

            if let Some(target) = limb0.get_mut(16..32) {
                if let Some(src) = image_id.get(0..16) {
                    target.copy_from_slice(src);
                }
            }
            if let Some(target) = limb1.get_mut(16..32) {
                if let Some(src) = image_id.get(16..32) {
                    target.copy_from_slice(src);
                }
            }
            if let Some(target) = limb2.get_mut(16..32) {
                if let Some(src) = journal_digest.get(0..16) {
                    target.copy_from_slice(src);
                }
            }
            if let Some(target) = limb3.get_mut(16..32) {
                if let Some(src) = journal_digest.get(16..32) {
                    target.copy_from_slice(src);
                }
            }

            inputs.push(decode_fr(&limb0)?);
            inputs.push(decode_fr(&limb1)?);
            inputs.push(decode_fr(&limb2)?);
            inputs.push(decode_fr(&limb3)?);

            Ok(PublicInputs { inputs })
        }
        Risc0PublicInputsMode::Direct => {
            let inputs = vec![decode_fr(image_id)?, decode_fr(journal_digest)?];
            Ok(PublicInputs { inputs })
        }
    }
}

/// Parses a hex-encoded string or byte array into a 32-byte array.
pub(crate) fn parse_digest_bytes(val: &JsonValue<'_>) -> Result<[u8; 32], AcfError> {
    match val {
        JsonValue::String(s) => parse_hex_bytes_32(s),
        JsonValue::Array(items) if items.len() == 32 => {
            let mut out = [0u8; 32];
            for (i, item) in items.iter().enumerate() {
                let byte_val = item.as_u32()?;
                if byte_val > 255 {
                    return Err(AcfError::MalformedInput);
                }
                if let Some(slot) = out.get_mut(i) {
                    *slot = byte_val as u8;
                }
            }
            Ok(out)
        }
        _ => Err(AcfError::MalformedInput),
    }
}

/// Parses a hex-encoded string or byte array into 256 bytes for a Groth16 seal.
fn parse_seal_bytes(val: &JsonValue<'_>) -> Result<[u8; 256], AcfError> {
    match val {
        JsonValue::String(s) => {
            let clean = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            if clean.len() != 512 {
                return Err(AcfError::BadLength);
            }
            let mut out = [0u8; 256];
            for i in 0..256 {
                let start = i * 2;
                let hex_pair = clean
                    .get(start..start + 2)
                    .ok_or(AcfError::MalformedInput)?;
                let byte_val =
                    u8::from_str_radix(hex_pair, 16).map_err(|_| AcfError::MalformedInput)?;
                if let Some(slot) = out.get_mut(i) {
                    *slot = byte_val;
                }
            }
            Ok(out)
        }
        JsonValue::Array(items) if items.len() == 256 => {
            let mut out = [0u8; 256];
            for (i, item) in items.iter().enumerate() {
                let byte_val = item.as_u32()?;
                if byte_val > 255 {
                    return Err(AcfError::MalformedInput);
                }
                if let Some(slot) = out.get_mut(i) {
                    *slot = byte_val as u8;
                }
            }
            Ok(out)
        }
        _ => Err(AcfError::MalformedInput),
    }
}

/// Parses a RISC Zero Groth16 receipt JSON artifact into a [`Risc0Receipt`].
pub fn parse_risc0_receipt_json(
    input: &str,
    mode: Risc0PublicInputsMode,
) -> Result<Risc0Receipt, AcfError> {
    let root = parse_json(input)?;

    // 1. Extract seal
    let seal_val = if let Ok(s) = root.get_field("seal") {
        s
    } else if let Ok(inner) = root.get_field("inner") {
        if let Ok(groth16) = inner.get_field("Groth16") {
            groth16.get_field("seal")?
        } else {
            return Err(AcfError::MalformedInput);
        }
    } else {
        return Err(AcfError::MalformedInput);
    };
    let seal_bytes = parse_seal_bytes(seal_val)?;
    let proof = map_risc0_seal(&seal_bytes)?;

    // 2. Extract image_id
    let image_id_val = if let Ok(id) = root.get_field("image_id") {
        id
    } else if let Ok(id) = root.get_field("imageId") {
        id
    } else if let Ok(post) = root.get_field("post") {
        if let Ok(claim) = post.get_field("claim") {
            claim.get_field("image_id")?
        } else {
            return Err(AcfError::MalformedInput);
        }
    } else {
        return Err(AcfError::MalformedInput);
    };
    let image_id = parse_digest_bytes(image_id_val)?;

    // 3. Extract journal or journal_digest
    let journal_digest = if let Ok(jd_val) = root
        .get_field("journal_digest")
        .or_else(|_| root.get_field("journalDigest"))
    {
        parse_digest_bytes(jd_val)?
    } else if let Ok(j_val) = root.get_field("journal") {
        match j_val {
            JsonValue::String(s) => {
                let clean = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                if clean.len() == 64 {
                    parse_hex_bytes_32(clean)?
                } else {
                    if !clean.len().is_multiple_of(2) {
                        return Err(AcfError::MalformedInput);
                    }
                    // Raw hex bytes of journal: hash with sha256
                    let mut raw_bytes = Vec::with_capacity(clean.len() / 2);
                    for i in 0..(clean.len() / 2) {
                        let start = i * 2;
                        let hex_pair = clean
                            .get(start..start + 2)
                            .ok_or(AcfError::MalformedInput)?;
                        let byte_val = u8::from_str_radix(hex_pair, 16)
                            .map_err(|_| AcfError::MalformedInput)?;
                        raw_bytes.push(byte_val);
                    }
                    sha256(&raw_bytes)
                }
            }
            JsonValue::Array(items) => {
                let mut raw_bytes = Vec::with_capacity(items.len());
                for item in items {
                    let b = item.as_u32()?;
                    if b > 255 {
                        return Err(AcfError::MalformedInput);
                    }
                    raw_bytes.push(b as u8);
                }
                sha256(&raw_bytes)
            }
            _ => return Err(AcfError::MalformedInput),
        }
    } else {
        return Err(AcfError::MalformedInput);
    };

    let public_inputs = map_risc0_journal_and_image_id(&image_id, &journal_digest, mode)?;

    Ok(Risc0Receipt {
        proof,
        public_inputs,
        image_id,
        journal_digest,
    })
}

/// Parses a RISC Zero Groth16 seal JSON and wraps it in a canonical [`Envelope`].
pub fn parse_risc0_proof_envelope(
    input: &str,
    mode: Risc0PublicInputsMode,
) -> Result<Envelope, AcfError> {
    let receipt = parse_risc0_receipt_json(input, mode)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::Proof,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::Proof(receipt.proof),
    })
}

/// Parses a RISC Zero Groth16 receipt JSON and wraps the public inputs in a canonical [`Envelope`].
pub fn parse_risc0_public_inputs_envelope(
    input: &str,
    mode: Risc0PublicInputsMode,
) -> Result<Envelope, AcfError> {
    let receipt = parse_risc0_receipt_json(input, mode)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::PublicInputs,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::PublicInputs(receipt.public_inputs),
    })
}
