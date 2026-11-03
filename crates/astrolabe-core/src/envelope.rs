//! Artifact envelope for storing and tooling ACF payloads (ACF Spec Section 5).

extern crate alloc;

use crate::groth16::{
    decode_proof, decode_public_inputs, decode_vk, encode_proof, encode_public_inputs, encode_vk,
    Proof, PublicInputs, VerificationKey,
};
use crate::AcfError;
use alloc::vec::Vec;

/// 4-byte ASCII magic identifier `ASTR` (`0x41 0x53 0x54 0x52`) (ACF Spec Section 5).
pub const ENVELOPE_MAGIC: [u8; 4] = *b"ASTR";

/// Format version byte for ACF 0.x (`0x01`) (ACF Spec Section 5).
pub const ENVELOPE_SPEC_VER_0_1: u8 = 0x01;

/// Fixed length of an ACF envelope header in bytes (ACF Spec Section 5).
pub const ENVELOPE_HEADER_BYTE_LEN: usize = 12;

/// Artifact kind identifier (ACF Spec Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ArtifactKind {
    /// `0x01`: Groth16 proof (ACF Spec Section 4.1).
    Proof = 0x01,
    /// `0x02`: Groth16 verification key (ACF Spec Section 4.2).
    VerificationKey = 0x02,
    /// `0x03`: Groth16 public inputs (ACF Spec Section 4.3).
    PublicInputs = 0x03,
}

impl ArtifactKind {
    /// Returns the canonical string representation used in textual JSON form (ACF Spec Section 6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proof => "proof",
            Self::VerificationKey => "verification_key",
            Self::PublicInputs => "public_inputs",
        }
    }

    /// Parses an artifact kind from its 1-byte wire code (ACF Spec Section 5).
    pub const fn from_u8(val: u8) -> Result<Self, AcfError> {
        match val {
            0x01 => Ok(Self::Proof),
            0x02 => Ok(Self::VerificationKey),
            0x03 => Ok(Self::PublicInputs),
            _ => Err(AcfError::Unsupported),
        }
    }
}

/// Curve identifier (ACF Spec Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CurveId {
    /// `0x01`: BN254 (alt_bn128).
    Bn254 = 0x01,
}

impl CurveId {
    /// Returns the canonical string representation used in textual JSON form (ACF Spec Section 6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bn254 => "bn254",
        }
    }

    /// Parses a curve identifier from its 1-byte wire code (ACF Spec Section 5).
    pub const fn from_u8(val: u8) -> Result<Self, AcfError> {
        match val {
            0x01 => Ok(Self::Bn254),
            _ => Err(AcfError::Unsupported),
        }
    }
}

/// Proof system identifier (ACF Spec Section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProofSystemId {
    /// `0x01`: Groth16.
    Groth16 = 0x01,
}

impl ProofSystemId {
    /// Returns the canonical string representation used in textual JSON form (ACF Spec Section 6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Groth16 => "groth16",
        }
    }

    /// Parses a proof system identifier from its 1-byte wire code (ACF Spec Section 5).
    pub const fn from_u8(val: u8) -> Result<Self, AcfError> {
        match val {
            0x01 => Ok(Self::Groth16),
            _ => Err(AcfError::Unsupported),
        }
    }
}

/// Typed envelope payload.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopePayload {
    /// Groth16 proof payload (256 bytes).
    Proof(Proof),
    /// Groth16 verification key payload.
    VerificationKey(VerificationKey),
    /// Groth16 public inputs payload.
    PublicInputs(PublicInputs),
}

impl EnvelopePayload {
    /// Returns the corresponding artifact kind.
    #[must_use]
    pub const fn kind(&self) -> ArtifactKind {
        match self {
            Self::Proof(_) => ArtifactKind::Proof,
            Self::VerificationKey(_) => ArtifactKind::VerificationKey,
            Self::PublicInputs(_) => ArtifactKind::PublicInputs,
        }
    }

    /// Encodes the payload into raw canonical bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Proof(p) => encode_proof(p).to_vec(),
            Self::VerificationKey(vk) => encode_vk(vk),
            Self::PublicInputs(pi) => encode_public_inputs(pi),
        }
    }
}

/// Self-describing ACF artifact envelope (ACF Spec Section 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Format spec version (`0x01` for ACF 0.x).
    pub spec_ver: u8,
    /// Artifact kind (`proof`, `verification_key`, or `public_inputs`).
    pub kind: ArtifactKind,
    /// Curve identifier (`0x01` BN254).
    pub curve: CurveId,
    /// Proof system identifier (`0x01` Groth16).
    pub system: ProofSystemId,
    /// Typed payload.
    pub payload: EnvelopePayload,
}

impl Envelope {
    /// Creates a new envelope for a typed payload with canonical header defaults (`spec_ver = 0x01`, `curve = BN254`, `system = Groth16`).
    #[must_use]
    pub fn new(payload: EnvelopePayload) -> Self {
        Self {
            spec_ver: ENVELOPE_SPEC_VER_0_1,
            kind: payload.kind(),
            curve: CurveId::Bn254,
            system: ProofSystemId::Groth16,
            payload,
        }
    }

    /// Decodes and strictly validates an ACF artifact envelope (ACF Spec Section 5).
    pub fn decode(bytes: &[u8]) -> Result<Self, AcfError> {
        decode_envelope(bytes)
    }

    /// Encodes this envelope into canonical byte representation (ACF Spec Section 5).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        encode_envelope(self)
    }
}

/// Decodes and strictly validates an ACF artifact envelope (ACF Spec Section 5).
///
/// Order of validation:
/// 1. Minimum header length: at least 12 bytes ([`AcfError::BadLength`]).
/// 2. Header magic: must equal `b"ASTR"` ([`AcfError::Unsupported`]).
/// 3. Spec version: must equal `0x01` ([`AcfError::Unsupported`]).
/// 4. Artifact kind: must equal `0x01`, `0x02`, or `0x03` ([`AcfError::Unsupported`]).
/// 5. Curve ID: must equal `0x01` BN254 ([`AcfError::Unsupported`]).
/// 6. Proof system ID: must equal `0x01` Groth16 ([`AcfError::Unsupported`]).
/// 7. Payload length: payload bytes must match declared length without trailing bytes ([`AcfError::BadLength`] or [`AcfError::TrailingBytes`]).
/// 8. Payload validation: validated according to artifact kind.
pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, AcfError> {
    if bytes.len() < ENVELOPE_HEADER_BYTE_LEN {
        return Err(AcfError::BadLength);
    }

    let magic = bytes.get(0..4).ok_or(AcfError::BadLength)?;
    if magic != ENVELOPE_MAGIC {
        return Err(AcfError::Unsupported);
    }

    let spec_ver_byte = *bytes.get(4).ok_or(AcfError::BadLength)?;
    if spec_ver_byte != ENVELOPE_SPEC_VER_0_1 {
        return Err(AcfError::Unsupported);
    }

    let kind_byte = *bytes.get(5).ok_or(AcfError::BadLength)?;
    let kind = ArtifactKind::from_u8(kind_byte)?;

    let curve_byte = *bytes.get(6).ok_or(AcfError::BadLength)?;
    let curve = CurveId::from_u8(curve_byte)?;

    let system_byte = *bytes.get(7).ok_or(AcfError::BadLength)?;
    let system = ProofSystemId::from_u8(system_byte)?;

    let len_slice = bytes.get(8..12).ok_or(AcfError::BadLength)?;
    let mut len_arr = [0u8; 4];
    len_arr.copy_from_slice(len_slice);
    let payload_len_u32 = u32::from_be_bytes(len_arr);
    let payload_len = usize::try_from(payload_len_u32).map_err(|_| AcfError::BadLength)?;

    let total_expected = ENVELOPE_HEADER_BYTE_LEN
        .checked_add(payload_len)
        .ok_or(AcfError::BadLength)?;

    if bytes.len() < total_expected {
        return Err(AcfError::BadLength);
    }
    if bytes.len() > total_expected {
        return Err(AcfError::TrailingBytes);
    }

    let payload_slice = bytes
        .get(ENVELOPE_HEADER_BYTE_LEN..total_expected)
        .ok_or(AcfError::BadLength)?;

    let payload = match kind {
        ArtifactKind::Proof => EnvelopePayload::Proof(decode_proof(payload_slice)?),
        ArtifactKind::VerificationKey => {
            EnvelopePayload::VerificationKey(decode_vk(payload_slice)?)
        }
        ArtifactKind::PublicInputs => {
            EnvelopePayload::PublicInputs(decode_public_inputs(payload_slice)?)
        }
    };

    Ok(Envelope {
        spec_ver: spec_ver_byte,
        kind,
        curve,
        system,
        payload,
    })
}

/// Encodes an ACF artifact envelope into canonical byte representation (ACF Spec Section 5).
#[must_use]
pub fn encode_envelope(envelope: &Envelope) -> Vec<u8> {
    let payload_bytes = envelope.payload.encode();
    let payload_len_u32 = u32::try_from(payload_bytes.len()).unwrap_or(u32::MAX);

    let mut out = Vec::with_capacity(ENVELOPE_HEADER_BYTE_LEN.saturating_add(payload_bytes.len()));
    out.extend_from_slice(&ENVELOPE_MAGIC);
    out.push(envelope.spec_ver);
    out.push(envelope.kind as u8);
    out.push(envelope.curve as u8);
    out.push(envelope.system as u8);
    out.extend_from_slice(&payload_len_u32.to_be_bytes());
    out.extend_from_slice(&payload_bytes);
    out
}
