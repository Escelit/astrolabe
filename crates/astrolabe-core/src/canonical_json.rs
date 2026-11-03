//! Canonical JSON form for ACF artifacts (ACF Spec Section 6).

extern crate alloc;

use crate::envelope::{ArtifactKind, CurveId, Envelope, EnvelopePayload, ProofSystemId};
use crate::groth16::{decode_proof, decode_public_inputs, decode_vk};
use crate::AcfError;
use alloc::string::String;
use alloc::vec::Vec;

/// Serializes an [`Envelope`] into its canonical JSON representation (ACF Spec Section 6).
///
/// Output format:
/// - UTF-8, no BOM, LF newlines, single trailing newline.
/// - Keys in exact order: `"acf"`, `"kind"`, `"curve"`, `"system"`, `"hex"`.
/// - Hex in lowercase, without `0x` prefix.
#[must_use]
pub fn to_canonical_json(envelope: &Envelope) -> String {
    let payload_bytes = envelope.payload.encode();
    let hex = bytes_to_hex_lowercase(&payload_bytes);

    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"acf\": \"0.1\",\n");
    out.push_str("  \"kind\": \"");
    out.push_str(envelope.kind.as_str());
    out.push_str("\",\n");
    out.push_str("  \"curve\": \"");
    out.push_str(envelope.curve.as_str());
    out.push_str("\",\n");
    out.push_str("  \"system\": \"");
    out.push_str(envelope.system.as_str());
    out.push_str("\",\n");
    out.push_str("  \"hex\": \"");
    out.push_str(&hex);
    out.push_str("\"\n");
    out.push_str("}\n");
    out
}

/// Parses an [`Envelope`] from its canonical JSON representation (ACF Spec Section 6).
///
/// Rejects:
/// - Malformed JSON or invalid string tokens ([`AcfError::MalformedInput`]).
/// - Unknown version, kind, curve, or system ([`AcfError::Unsupported`]).
/// - Non-lowercase, odd-length, or `0x`-prefixed hex ([`AcfError::MalformedInput`]).
/// - Invalid payload bytes (corresponding validation error).
pub fn parse_canonical_json(input: &str) -> Result<Envelope, AcfError> {
    let mut acf: Option<&str> = None;
    let mut kind: Option<&str> = None;
    let mut curve: Option<&str> = None;
    let mut system: Option<&str> = None;
    let mut hex: Option<&str> = None;

    let trimmed = input.trim();
    if !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(AcfError::MalformedInput);
    }

    let inner = trimmed
        .get(1..trimmed.len().saturating_sub(1))
        .ok_or(AcfError::MalformedInput)?;

    for entry in inner.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let mut colon_parts = entry.splitn(2, ':');
        let key_raw = colon_parts.next().ok_or(AcfError::MalformedInput)?.trim();
        let val_raw = colon_parts.next().ok_or(AcfError::MalformedInput)?.trim();

        let key = unquote_str(key_raw)?;
        let val = unquote_str(val_raw)?;

        match key {
            "acf" => acf = Some(val),
            "kind" => kind = Some(val),
            "curve" => curve = Some(val),
            "system" => system = Some(val),
            "hex" => hex = Some(val),
            _ => return Err(AcfError::Unsupported),
        }
    }

    let acf_val = acf.ok_or(AcfError::MalformedInput)?;
    if acf_val != "0.1" {
        return Err(AcfError::Unsupported);
    }

    let kind_val = kind.ok_or(AcfError::MalformedInput)?;
    let parsed_kind = match kind_val {
        "proof" => ArtifactKind::Proof,
        "verification_key" => ArtifactKind::VerificationKey,
        "public_inputs" => ArtifactKind::PublicInputs,
        _ => return Err(AcfError::Unsupported),
    };

    let curve_val = curve.ok_or(AcfError::MalformedInput)?;
    let parsed_curve = match curve_val {
        "bn254" => CurveId::Bn254,
        _ => return Err(AcfError::Unsupported),
    };

    let system_val = system.ok_or(AcfError::MalformedInput)?;
    let parsed_system = match system_val {
        "groth16" => ProofSystemId::Groth16,
        _ => return Err(AcfError::Unsupported),
    };

    let hex_val = hex.ok_or(AcfError::MalformedInput)?;
    let payload_bytes = hex_to_bytes_lowercase(hex_val)?;

    let payload = match parsed_kind {
        ArtifactKind::Proof => EnvelopePayload::Proof(decode_proof(&payload_bytes)?),
        ArtifactKind::VerificationKey => {
            EnvelopePayload::VerificationKey(decode_vk(&payload_bytes)?)
        }
        ArtifactKind::PublicInputs => {
            EnvelopePayload::PublicInputs(decode_public_inputs(&payload_bytes)?)
        }
    };

    Ok(Envelope {
        spec_ver: 0x01,
        kind: parsed_kind,
        curve: parsed_curve,
        system: parsed_system,
        payload,
    })
}

fn unquote_str(raw: &str) -> Result<&str, AcfError> {
    if raw.len() >= 2 && raw.starts_with('"') && raw.ends_with('"') {
        raw.get(1..raw.len() - 1).ok_or(AcfError::MalformedInput)
    } else {
        Err(AcfError::MalformedInput)
    }
}

pub(crate) fn bytes_to_hex_lowercase(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

pub(crate) fn hex_to_bytes_lowercase(hex: &str) -> Result<Vec<u8>, AcfError> {
    if !hex.len().is_multiple_of(2) {
        return Err(AcfError::MalformedInput);
    }
    // Must be lowercase without 0x prefix
    for b in hex.bytes() {
        if !matches!(b, b'0'..=b'9' | b'a'..=b'f') {
            return Err(AcfError::MalformedInput);
        }
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let slice = hex.get(i..i + 2).ok_or(AcfError::MalformedInput)?;
        let byte = u8::from_str_radix(slice, 16).map_err(|_| AcfError::MalformedInput)?;
        bytes.push(byte);
    }
    Ok(bytes)
}
