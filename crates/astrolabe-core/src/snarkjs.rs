//! Adapter for snarkjs / Circom Groth16 BN254 artifacts (ACF Spec Section 10.1).
//!
//! Parses and converts public verification artifacts (`proof.json`, `verification_key.json`,
//! `public.json`) into canonical ACF types ([`Proof`], [`VerificationKey`], [`PublicInputs`]),
//! enforcing strict validation rules per ACF Spec Sections 9 and 10.1.

extern crate alloc;

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::curve::{G1, G2};
use crate::envelope::{ArtifactKind, CurveId, Envelope, EnvelopePayload, ProofSystemId};
use crate::field::{decode_fp, decode_fr, Fp, Fp2, Fr, BN254_P_BE, BN254_R_BE};
use crate::groth16::{Proof, PublicInputs, VerificationKey};
use crate::uint256::{cmp_limbs, from_be_bytes_32, to_be_bytes_32};
use crate::AcfError;

/// Lightweight AST for parsed JSON elements in `#![no_std]`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue<'a> {
    Object(Vec<(&'a str, JsonValue<'a>)>),
    Array(Vec<JsonValue<'a>>),
    String(&'a str),
    Number(&'a str),
    Bool(bool),
    Null,
}

impl<'a> JsonValue<'a> {
    fn as_object(&self) -> Result<&[(&'a str, JsonValue<'a>)], AcfError> {
        match self {
            Self::Object(entries) => Ok(entries),
            _ => Err(AcfError::MalformedInput),
        }
    }

    fn get_field(&self, key: &str) -> Result<&JsonValue<'a>, AcfError> {
        let entries = self.as_object()?;
        for entry in entries {
            if entry.0 == key {
                return Ok(&entry.1);
            }
        }
        Err(AcfError::MalformedInput)
    }

    fn as_array(&self) -> Result<&[JsonValue<'a>], AcfError> {
        match self {
            Self::Array(items) => Ok(items),
            _ => Err(AcfError::MalformedInput),
        }
    }

    fn as_str(&self) -> Result<&'a str, AcfError> {
        match self {
            Self::String(s) => Ok(s),
            _ => Err(AcfError::MalformedInput),
        }
    }

    fn as_u32(&self) -> Result<u32, AcfError> {
        match self {
            Self::Number(s) => parse_u32_ascii(s),
            Self::String(s) => parse_u32_ascii(s),
            _ => Err(AcfError::MalformedInput),
        }
    }
}

fn parse_u32_ascii(s: &str) -> Result<u32, AcfError> {
    if s.is_empty() {
        return Err(AcfError::MalformedInput);
    }
    let mut acc = 0u32;
    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return Err(AcfError::MalformedInput);
        }
        let digit = (b - b'0') as u32;
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(AcfError::MalformedInput)?;
    }
    Ok(acc)
}

struct JsonParser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            cursor: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(&b) = self.bytes.get(self.cursor) {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.cursor = self.cursor.saturating_add(1);
            } else {
                break;
            }
        }
    }

    fn peek_byte(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn consume_byte(&mut self, expected: u8) -> Result<(), AcfError> {
        match self.bytes.get(self.cursor) {
            Some(&b) if b == expected => {
                self.cursor = self.cursor.saturating_add(1);
                Ok(())
            }
            _ => Err(AcfError::MalformedInput),
        }
    }

    fn parse_value(&mut self) -> Result<JsonValue<'a>, AcfError> {
        self.skip_whitespace();
        let b = self.peek_byte().ok_or(AcfError::MalformedInput)?;
        match b {
            b'{' => self.parse_object(),
            b'[' => self.parse_array(),
            b'"' => self.parse_string(),
            b't' | b'f' => self.parse_bool(),
            b'n' => self.parse_null(),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(AcfError::MalformedInput),
        }
    }

    fn parse_string(&mut self) -> Result<JsonValue<'a>, AcfError> {
        self.consume_byte(b'"')?;
        let start = self.cursor;
        while let Some(&b) = self.bytes.get(self.cursor) {
            if b == b'"' {
                let s = self
                    .input
                    .get(start..self.cursor)
                    .ok_or(AcfError::MalformedInput)?;
                self.cursor = self.cursor.saturating_add(1);
                return Ok(JsonValue::String(s));
            }
            if b == b'\\' {
                // Skip escape character
                self.cursor = self.cursor.saturating_add(2);
            } else {
                self.cursor = self.cursor.saturating_add(1);
            }
        }
        Err(AcfError::MalformedInput)
    }

    fn parse_number(&mut self) -> Result<JsonValue<'a>, AcfError> {
        let start = self.cursor;
        while let Some(&b) = self.bytes.get(self.cursor) {
            if matches!(b, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E') {
                self.cursor = self.cursor.saturating_add(1);
            } else {
                break;
            }
        }
        let s = self
            .input
            .get(start..self.cursor)
            .ok_or(AcfError::MalformedInput)?;
        if s.is_empty() {
            return Err(AcfError::MalformedInput);
        }
        Ok(JsonValue::Number(s))
    }

    fn parse_bool(&mut self) -> Result<JsonValue<'a>, AcfError> {
        if self.bytes.get(self.cursor..self.cursor + 4) == Some(b"true") {
            self.cursor = self.cursor.saturating_add(4);
            Ok(JsonValue::Bool(true))
        } else if self.bytes.get(self.cursor..self.cursor + 5) == Some(b"false") {
            self.cursor = self.cursor.saturating_add(5);
            Ok(JsonValue::Bool(false))
        } else {
            Err(AcfError::MalformedInput)
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue<'a>, AcfError> {
        if self.bytes.get(self.cursor..self.cursor + 4) == Some(b"null") {
            self.cursor = self.cursor.saturating_add(4);
            Ok(JsonValue::Null)
        } else {
            Err(AcfError::MalformedInput)
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue<'a>, AcfError> {
        self.consume_byte(b'[')?;
        self.skip_whitespace();
        let mut items = Vec::new();
        if self.peek_byte() == Some(b']') {
            self.cursor = self.cursor.saturating_add(1);
            return Ok(JsonValue::Array(items));
        }

        loop {
            let val = self.parse_value()?;
            items.push(val);
            self.skip_whitespace();
            match self.peek_byte() {
                Some(b',') => {
                    self.cursor = self.cursor.saturating_add(1);
                    self.skip_whitespace();
                }
                Some(b']') => {
                    self.cursor = self.cursor.saturating_add(1);
                    break;
                }
                _ => return Err(AcfError::MalformedInput),
            }
        }
        Ok(JsonValue::Array(items))
    }

    fn parse_object(&mut self) -> Result<JsonValue<'a>, AcfError> {
        self.consume_byte(b'{')?;
        self.skip_whitespace();
        let mut entries = Vec::new();
        if self.peek_byte() == Some(b'}') {
            self.cursor = self.cursor.saturating_add(1);
            return Ok(JsonValue::Object(entries));
        }

        loop {
            self.skip_whitespace();
            let key = match self.parse_string()? {
                JsonValue::String(k) => k,
                _ => return Err(AcfError::MalformedInput),
            };
            self.skip_whitespace();
            self.consume_byte(b':')?;
            let val = self.parse_value()?;
            entries.push((key, val));
            self.skip_whitespace();
            match self.peek_byte() {
                Some(b',') => {
                    self.cursor = self.cursor.saturating_add(1);
                    self.skip_whitespace();
                }
                Some(b'}') => {
                    self.cursor = self.cursor.saturating_add(1);
                    break;
                }
                _ => return Err(AcfError::MalformedInput),
            }
        }
        Ok(JsonValue::Object(entries))
    }
}

fn parse_json(input: &str) -> Result<JsonValue<'_>, AcfError> {
    let mut parser = JsonParser::new(input);
    let val = parser.parse_value()?;
    parser.skip_whitespace();
    if parser.cursor != parser.bytes.len() {
        return Err(AcfError::MalformedInput);
    }
    Ok(val)
}

/// Parses an ASCII decimal string into four 64-bit limbs, checking for invalid digits
/// and 256-bit overflow.
fn parse_dec_to_limbs(s: &str) -> Result<([u64; 4], bool), AcfError> {
    if s.is_empty() {
        return Err(AcfError::MalformedInput);
    }
    let mut limbs = [0u64; 4];
    let mut overflow = false;

    for b in s.bytes() {
        if !b.is_ascii_digit() {
            return Err(AcfError::MalformedInput);
        }
        let digit = (b - b'0') as u64;

        let mut carry = digit;
        let mut i = 0;
        while i < 4 {
            if let Some(limb) = limbs.get_mut(i) {
                let prod = (*limb as u128)
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(carry as u128))
                    .ok_or(AcfError::MalformedInput)?;
                *limb = prod as u64;
                carry = (prod >> 64) as u64;
            }
            i = i.saturating_add(1);
        }
        if carry != 0 {
            overflow = true;
        }
    }
    Ok((limbs, overflow))
}

/// Parses a decimal string into a canonical [`Fp`] element (`< p`, ACF Spec Section 2 and 3.1).
///
/// # Errors
///
/// - [`AcfError::MalformedInput`] if the string is empty or contains non-decimal characters.
/// - [`AcfError::NonCanonicalField`] if the numeric value is `>= p`.
pub fn parse_dec_fp(s: &str) -> Result<Fp, AcfError> {
    let (limbs, overflow) = parse_dec_to_limbs(s)?;
    if overflow {
        return Err(AcfError::NonCanonicalField);
    }
    let p_limbs = from_be_bytes_32(&BN254_P_BE);
    if cmp_limbs(limbs, p_limbs) != Ordering::Less {
        return Err(AcfError::NonCanonicalField);
    }
    let be_bytes = to_be_bytes_32(limbs);
    decode_fp(&be_bytes)
}

/// Parses a decimal string into a canonical [`Fr`] scalar (`< r`, ACF Spec Section 2 and 3.4).
///
/// # Errors
///
/// - [`AcfError::MalformedInput`] if the string is empty or contains non-decimal characters.
/// - [`AcfError::NonCanonicalField`] if the numeric value is `>= r`.
pub fn parse_dec_fr(s: &str) -> Result<Fr, AcfError> {
    let (limbs, overflow) = parse_dec_to_limbs(s)?;
    if overflow {
        return Err(AcfError::NonCanonicalField);
    }
    let r_limbs = from_be_bytes_32(&BN254_R_BE);
    if cmp_limbs(limbs, r_limbs) != Ordering::Less {
        return Err(AcfError::NonCanonicalField);
    }
    let be_bytes = to_be_bytes_32(limbs);
    decode_fr(&be_bytes)
}

/// Parses a snarkjs G1 point `[x, y, "1"]` (ACF Spec Section 10.1).
///
/// Checks:
/// - Exact length must be 3 elements.
/// - The trailing element must equal `"1"`.
/// - Coordinates `x` and `y` must be canonical decimal strings `< p`.
/// - The resulting point must satisfy the BN254 curve equation `y^2 = x^3 + 3`.
fn parse_snarkjs_g1(val: &JsonValue<'_>) -> Result<G1, AcfError> {
    let items = val.as_array()?;
    if items.len() != 3 {
        return Err(AcfError::MalformedInput);
    }
    let trailing = items.get(2).ok_or(AcfError::MalformedInput)?.as_str()?;
    if trailing != "1" {
        return Err(AcfError::MalformedInput);
    }
    let x_str = items.first().ok_or(AcfError::MalformedInput)?.as_str()?;
    let y_str = items.get(1).ok_or(AcfError::MalformedInput)?.as_str()?;

    let x = parse_dec_fp(x_str)?;
    let y = parse_dec_fp(y_str)?;

    G1::from_coordinates(x, y)
}

/// Parses a snarkjs G2 point `[[x0, x1], [y0, y1], ["1", "0"]]` (ACF Spec Section 10.1).
///
/// snarkjs emits `[c0, c1]` (real, imaginary) order.
///
/// Checks:
/// - Outer array has 3 elements; trailing element equals `["1", "0"]`.
/// - Coordinate arrays each have 2 elements.
/// - All coordinates are canonical field elements `< p`.
/// - The resulting point satisfies the twist curve equation and order-`r` subgroup check.
fn parse_snarkjs_g2(val: &JsonValue<'_>) -> Result<G2, AcfError> {
    let items = val.as_array()?;
    if items.len() != 3 {
        return Err(AcfError::MalformedInput);
    }

    let trailing = items.get(2).ok_or(AcfError::MalformedInput)?.as_array()?;
    if trailing.len() != 2 {
        return Err(AcfError::MalformedInput);
    }
    let t0 = trailing.first().ok_or(AcfError::MalformedInput)?.as_str()?;
    let t1 = trailing.get(1).ok_or(AcfError::MalformedInput)?.as_str()?;
    if t0 != "1" || t1 != "0" {
        return Err(AcfError::MalformedInput);
    }

    let x_arr = items.first().ok_or(AcfError::MalformedInput)?.as_array()?;
    if x_arr.len() != 2 {
        return Err(AcfError::MalformedInput);
    }
    let x0 = parse_dec_fp(x_arr.first().ok_or(AcfError::MalformedInput)?.as_str()?)?;
    let x1 = parse_dec_fp(x_arr.get(1).ok_or(AcfError::MalformedInput)?.as_str()?)?;

    let y_arr = items.get(1).ok_or(AcfError::MalformedInput)?.as_array()?;
    if y_arr.len() != 2 {
        return Err(AcfError::MalformedInput);
    }
    let y0 = parse_dec_fp(y_arr.first().ok_or(AcfError::MalformedInput)?.as_str()?)?;
    let y1 = parse_dec_fp(y_arr.get(1).ok_or(AcfError::MalformedInput)?.as_str()?)?;

    let x = Fp2::new(x0, x1);
    let y = Fp2::new(y0, y1);

    G2::from_coordinates(x, y)
}

/// Parses and validates a snarkjs Groth16 BN254 `proof.json` string into a canonical [`Proof`]
/// (ACF Spec Section 4.1, Section 9, and Section 10.1).
///
/// # Validation Rules (ACF Spec Section 9 and 10.1)
///
/// 1. `protocol` MUST equal `"groth16"`, else [`AcfError::Unsupported`].
/// 2. `curve` MUST equal `"bn128"`, else [`AcfError::Unsupported`].
/// 3. Structure must match snarkjs affine format, else [`AcfError::MalformedInput`].
/// 4. Coordinates must be below `p`, else [`AcfError::NonCanonicalField`].
/// 5. Points must lie on the respective curves, else [`AcfError::NotOnCurve`].
/// 6. Point `B` must lie in the order-`r` G2 subgroup, else [`AcfError::NotInSubgroup`].
/// 7. Proof points `A`, `B`, `C` MUST NOT be infinity, else [`AcfError::InvalidProof`].
pub fn parse_snarkjs_proof(json_str: &str) -> Result<Proof, AcfError> {
    let root = parse_json(json_str)?;
    let protocol = root.get_field("protocol")?.as_str()?;
    if protocol != "groth16" {
        return Err(AcfError::Unsupported);
    }
    let curve = root.get_field("curve")?.as_str()?;
    if curve != "bn128" {
        return Err(AcfError::Unsupported);
    }

    let a = parse_snarkjs_g1(root.get_field("pi_a")?)?;
    let b = parse_snarkjs_g2(root.get_field("pi_b")?)?;
    let c = parse_snarkjs_g1(root.get_field("pi_c")?)?;

    // ACF Spec Section 9 Rule 6: degenerate proof points must be rejected.
    if a.is_infinity() || b.is_infinity() || c.is_infinity() {
        return Err(AcfError::InvalidProof);
    }

    Ok(Proof { a, b, c })
}

/// Parses and validates a snarkjs Groth16 BN254 `verification_key.json` string into a canonical
/// [`VerificationKey`] (ACF Spec Section 4.2, Section 9, and Section 10.1).
///
/// # Validation Rules (ACF Spec Section 9 and 10.1)
///
/// 1. `protocol` MUST equal `"groth16"`, else [`AcfError::Unsupported`].
/// 2. `curve` MUST equal `"bn128"`, else [`AcfError::Unsupported`].
/// 3. `nPublic` MUST equal `IC.len() - 1`, else [`AcfError::PublicInputCount`].
/// 4. All curve points must satisfy curve equations and subgroup checks.
pub fn parse_snarkjs_vk(json_str: &str) -> Result<VerificationKey, AcfError> {
    let root = parse_json(json_str)?;
    let protocol = root.get_field("protocol")?.as_str()?;
    if protocol != "groth16" {
        return Err(AcfError::Unsupported);
    }
    let curve = root.get_field("curve")?.as_str()?;
    if curve != "bn128" {
        return Err(AcfError::Unsupported);
    }

    let n_public = root.get_field("nPublic")?.as_u32()? as usize;
    let alpha_g1 = parse_snarkjs_g1(root.get_field("vk_alpha_1")?)?;
    let beta_g2 = parse_snarkjs_g2(root.get_field("vk_beta_2")?)?;
    let gamma_g2 = parse_snarkjs_g2(root.get_field("vk_gamma_2")?)?;
    let delta_g2 = parse_snarkjs_g2(root.get_field("vk_delta_2")?)?;

    let ic_entries = root.get_field("IC")?.as_array()?;
    let mut ic = Vec::with_capacity(ic_entries.len());
    for entry in ic_entries {
        ic.push(parse_snarkjs_g1(entry)?);
    }

    // Spec Section 10.1: nPublic MUST equal len(IC) - 1.
    if ic.len() != n_public.saturating_add(1) {
        return Err(AcfError::PublicInputCount);
    }

    Ok(VerificationKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}

/// Parses and validates a snarkjs Groth16 BN254 `public.json` string into a canonical
/// [`PublicInputs`] collection (ACF Spec Section 4.3, Section 9, and Section 10.1).
///
/// # Validation Rules (ACF Spec Section 9 and 10.1)
///
/// 1. Input must be a JSON array of decimal strings.
/// 2. Every scalar must be strictly below the BN254 scalar field modulus `r`
///    ([`AcfError::NonCanonicalField`]).
pub fn parse_snarkjs_public_inputs(json_str: &str) -> Result<PublicInputs, AcfError> {
    let root = parse_json(json_str)?;
    let items = root.as_array()?;
    let mut inputs = Vec::with_capacity(items.len());
    for item in items {
        let dec_str = item.as_str()?;
        let fr = parse_dec_fr(dec_str)?;
        inputs.push(fr);
    }
    Ok(PublicInputs { inputs })
}

/// Parses a snarkjs `proof.json` and wraps it in a canonical [`Envelope`] (ACF Spec Section 5 and 10.1).
pub fn parse_snarkjs_proof_envelope(json_str: &str) -> Result<Envelope, AcfError> {
    let proof = parse_snarkjs_proof(json_str)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::Proof,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::Proof(proof),
    })
}

/// Parses a snarkjs `verification_key.json` and wraps it in a canonical [`Envelope`]
/// (ACF Spec Section 5 and 10.1).
pub fn parse_snarkjs_vk_envelope(json_str: &str) -> Result<Envelope, AcfError> {
    let vk = parse_snarkjs_vk(json_str)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::VerificationKey,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::VerificationKey(vk),
    })
}

/// Parses a snarkjs `public.json` and wraps it in a canonical [`Envelope`]
/// (ACF Spec Section 5 and 10.1).
pub fn parse_snarkjs_public_inputs_envelope(json_str: &str) -> Result<Envelope, AcfError> {
    let public_inputs = parse_snarkjs_public_inputs(json_str)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::PublicInputs,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::PublicInputs(public_inputs),
    })
}
