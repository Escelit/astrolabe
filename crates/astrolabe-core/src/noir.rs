//! Noir Groth16 BN254 adapter conforming to ACF Spec Section 10.2.
//!
//! Noir is supported via Groth16 backends (e.g. `sunspot`, `noir-groth16`, `garaga`)
//! that emit snarkjs-compatible artifacts or unified Noir bundles.
//! Toolchain and backend versions are recorded in [`NoirMetadata`] without modifying
//! canonical bytes.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::envelope::{ArtifactKind, CurveId, Envelope, EnvelopePayload, ProofSystemId};
use crate::groth16::{Proof, PublicInputs, VerificationKey};
use crate::snarkjs::{
    parse_json, parse_num_fr, parse_snarkjs_proof, parse_snarkjs_public_inputs, parse_snarkjs_vk,
    JsonValue,
};
use crate::AcfError;

/// Toolchain and backend provenance metadata for Noir proving artifacts (Spec Section 10.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoirMetadata {
    /// Noir compiler version (e.g., `"0.33.0"`), if specified.
    pub noir_version: Option<String>,
    /// Prover backend name (e.g., `"sunspot"`, `"barretenberg"`, `"noir-groth16"`), if specified.
    pub backend: Option<String>,
    /// Source circuit identifier or name, if specified.
    pub circuit_name: Option<String>,
}

/// Unified Noir Groth16 proving artifact bundle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoirBundle {
    /// Toolchain and circuit metadata.
    pub metadata: NoirMetadata,
    /// Groth16 proof element, if present in bundle.
    pub proof: Option<Proof>,
    /// Groth16 verification key, if present in bundle.
    pub vk: Option<VerificationKey>,
    /// Groth16 public inputs, if present in bundle.
    pub public_inputs: Option<PublicInputs>,
}

/// Extracts [`NoirMetadata`] from a JSON artifact string.
pub fn extract_noir_metadata(input: &str) -> Result<NoirMetadata, AcfError> {
    let root = parse_json(input)?;
    Ok(extract_metadata(&root))
}

/// Extracts [`NoirMetadata`] from a parsed JSON value if fields are present.
pub(crate) fn extract_metadata(root: &JsonValue<'_>) -> NoirMetadata {
    let mut meta = NoirMetadata::default();

    // Check direct fields or nested "metadata" object
    if let Ok(entries) = root.as_object() {
        for &(k, ref v) in entries {
            match k {
                "noir_version" | "noirVersion" => {
                    if let Ok(s) = v.as_str() {
                        meta.noir_version = Some(s.to_string());
                    }
                }
                "backend" | "prover" => {
                    if let Ok(s) = v.as_str() {
                        meta.backend = Some(s.to_string());
                    }
                }
                "circuit" | "circuit_name" | "circuitName" => {
                    if let Ok(s) = v.as_str() {
                        meta.circuit_name = Some(s.to_string());
                    }
                }
                "metadata" => {
                    if let Ok(nested_entries) = v.as_object() {
                        for &(nk, ref nv) in nested_entries {
                            match nk {
                                "noir_version" | "noirVersion" => {
                                    if let Ok(s) = nv.as_str() {
                                        meta.noir_version = Some(s.to_string());
                                    }
                                }
                                "backend" | "prover" => {
                                    if let Ok(s) = nv.as_str() {
                                        meta.backend = Some(s.to_string());
                                    }
                                }
                                "circuit" | "circuit_name" | "circuitName" => {
                                    if let Ok(s) = nv.as_str() {
                                        meta.circuit_name = Some(s.to_string());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    meta
}

/// Parses and converts a Noir Groth16 `proof.json` (or bundle) into a canonical [`Proof`].
///
/// Accepts either:
/// 1. A snarkjs-compatible `proof.json` emitted by a Noir Groth16 backend.
/// 2. A unified Noir bundle object with a `"proof"` field.
///
/// # Errors
///
/// Returns [`AcfError::MalformedInput`] if the JSON is malformed or invalid structure,
/// [`AcfError::Unsupported`] if curve or protocol do not match BN254 Groth16, or
/// [`AcfError::NonCanonicalField`]/[`AcfError::NotOnCurve`] if points violate curve rules.
pub fn parse_noir_proof(input: &str) -> Result<Proof, AcfError> {
    let root = parse_json(input)?;
    if let Ok(proof_val) = root.get_field("proof") {
        // Nested under "proof" in bundle
        parse_snarkjs_proof_value(proof_val)
    } else {
        parse_snarkjs_proof(input)
    }
}

/// Parses and converts a Noir Groth16 `verification_key.json` (or bundle) into a canonical [`VerificationKey`].
///
/// Accepts either:
/// 1. A snarkjs-compatible `verification_key.json` emitted by a Noir Groth16 backend.
/// 2. A unified Noir bundle object with a `"verification_key"` or `"vk"` field.
pub fn parse_noir_vk(input: &str) -> Result<VerificationKey, AcfError> {
    let root = parse_json(input)?;
    if let Ok(vk_val) = root
        .get_field("verification_key")
        .or_else(|_| root.get_field("vk"))
    {
        parse_snarkjs_vk_value(vk_val)
    } else {
        parse_snarkjs_vk(input)
    }
}

/// Parses and converts a Noir public inputs artifact (or bundle) into a canonical [`PublicInputs`].
///
/// Accepts either:
/// 1. A JSON array of decimal or hex scalar strings.
/// 2. A unified Noir bundle object with a `"public_inputs"` or `"public"` field.
pub fn parse_noir_public_inputs(input: &str) -> Result<PublicInputs, AcfError> {
    let root = parse_json(input)?;
    if let Ok(pi_val) = root
        .get_field("public_inputs")
        .or_else(|_| root.get_field("public"))
    {
        parse_noir_public_inputs_value(pi_val)
    } else if root.as_array().is_ok() {
        parse_snarkjs_public_inputs(input)
    } else {
        Err(AcfError::MalformedInput)
    }
}

fn parse_noir_public_inputs_value(val: &JsonValue<'_>) -> Result<PublicInputs, AcfError> {
    let items = val.as_array()?;
    let mut inputs = Vec::with_capacity(items.len());
    for item in items {
        let s = item.as_str()?;
        let fr = parse_num_fr(s)?;
        inputs.push(fr);
    }
    Ok(PublicInputs { inputs })
}

/// Parses a unified Noir Groth16 bundle containing metadata, proof, verification key, and/or public inputs.
pub fn parse_noir_bundle(input: &str) -> Result<NoirBundle, AcfError> {
    let root = parse_json(input)?;
    let metadata = extract_metadata(&root);

    let proof = if let Ok(proof_val) = root.get_field("proof") {
        Some(parse_snarkjs_proof_value(proof_val)?)
    } else {
        None
    };

    let vk = if let Ok(vk_val) = root
        .get_field("verification_key")
        .or_else(|_| root.get_field("vk"))
    {
        Some(parse_snarkjs_vk_value(vk_val)?)
    } else {
        None
    };

    let public_inputs = if let Ok(pi_val) = root
        .get_field("public_inputs")
        .or_else(|_| root.get_field("public"))
    {
        Some(parse_noir_public_inputs_value(pi_val)?)
    } else {
        None
    };

    Ok(NoirBundle {
        metadata,
        proof,
        vk,
        public_inputs,
    })
}

/// Parses a Noir `proof.json` and wraps it in a canonical [`Envelope`] (Spec Section 5 and 10.2).
pub fn parse_noir_proof_envelope(input: &str) -> Result<Envelope, AcfError> {
    let proof = parse_noir_proof(input)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::Proof,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::Proof(proof),
    })
}

/// Parses a Noir `verification_key.json` and wraps it in a canonical [`Envelope`] (Spec Section 5 and 10.2).
pub fn parse_noir_vk_envelope(input: &str) -> Result<Envelope, AcfError> {
    let vk = parse_noir_vk(input)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::VerificationKey,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::VerificationKey(vk),
    })
}

/// Parses a Noir public inputs artifact and wraps it in a canonical [`Envelope`] (Spec Section 5 and 10.2).
pub fn parse_noir_public_inputs_envelope(input: &str) -> Result<Envelope, AcfError> {
    let public_inputs = parse_noir_public_inputs(input)?;
    Ok(Envelope {
        spec_ver: 0x01,
        kind: ArtifactKind::PublicInputs,
        curve: CurveId::Bn254,
        system: ProofSystemId::Groth16,
        payload: EnvelopePayload::PublicInputs(public_inputs),
    })
}

// Helpers calling into internal snarkjs parser functions
fn parse_snarkjs_proof_value(val: &JsonValue<'_>) -> Result<Proof, AcfError> {
    let proto = val.get_field("protocol")?.as_str()?;
    if proto != "groth16" {
        return Err(AcfError::Unsupported);
    }
    let curve = val.get_field("curve")?.as_str()?;
    if curve != "bn128" && curve != "bn254" {
        return Err(AcfError::Unsupported);
    }
    let a_val = val.get_field("pi_a")?;
    let b_val = val.get_field("pi_b")?;
    let c_val = val.get_field("pi_c")?;

    let a = parse_g1_helper(a_val)?;
    let b = parse_g2_helper(b_val)?;
    let c = parse_g1_helper(c_val)?;

    if a.is_infinity() || b.is_infinity() || c.is_infinity() {
        return Err(AcfError::InvalidProof);
    }

    Ok(Proof { a, b, c })
}

fn parse_snarkjs_vk_value(val: &JsonValue<'_>) -> Result<VerificationKey, AcfError> {
    let proto = val.get_field("protocol")?.as_str()?;
    if proto != "groth16" {
        return Err(AcfError::Unsupported);
    }
    let curve = val.get_field("curve")?.as_str()?;
    if curve != "bn128" && curve != "bn254" {
        return Err(AcfError::Unsupported);
    }
    let n_public = val.get_field("nPublic")?.as_u32()?;
    let alpha_val = val.get_field("vk_alpha_1")?;
    let beta_val = val.get_field("vk_beta_2")?;
    let gamma_val = val.get_field("vk_gamma_2")?;
    let delta_val = val.get_field("vk_delta_2")?;
    let ic_val = val.get_field("IC")?;

    let alpha = parse_g1_helper(alpha_val)?;
    let beta = parse_g2_helper(beta_val)?;
    let gamma = parse_g2_helper(gamma_val)?;
    let delta = parse_g2_helper(delta_val)?;

    let ic_items = ic_val.as_array()?;
    if ic_items.len() != (n_public as usize).saturating_add(1) {
        return Err(AcfError::PublicInputCount);
    }
    let mut ic = Vec::with_capacity(ic_items.len());
    for item in ic_items {
        ic.push(parse_g1_helper(item)?);
    }

    Ok(VerificationKey {
        alpha_g1: alpha,
        beta_g2: beta,
        gamma_g2: gamma,
        delta_g2: delta,
        ic,
    })
}

fn parse_g1_helper(val: &JsonValue<'_>) -> Result<crate::curve::G1, AcfError> {
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
    let x = crate::snarkjs::parse_num_fp(x_str)?;
    let y = crate::snarkjs::parse_num_fp(y_str)?;
    crate::curve::G1::from_coordinates(x, y)
}

fn parse_g2_helper(val: &JsonValue<'_>) -> Result<crate::curve::G2, AcfError> {
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
    let x0 =
        crate::snarkjs::parse_num_fp(x_arr.first().ok_or(AcfError::MalformedInput)?.as_str()?)?;
    let x1 = crate::snarkjs::parse_num_fp(x_arr.get(1).ok_or(AcfError::MalformedInput)?.as_str()?)?;

    let y_arr = items.get(1).ok_or(AcfError::MalformedInput)?.as_array()?;
    if y_arr.len() != 2 {
        return Err(AcfError::MalformedInput);
    }
    let y0 =
        crate::snarkjs::parse_num_fp(y_arr.first().ok_or(AcfError::MalformedInput)?.as_str()?)?;
    let y1 = crate::snarkjs::parse_num_fp(y_arr.get(1).ok_or(AcfError::MalformedInput)?.as_str()?)?;

    let x = crate::field::Fp2::new(x0, x1);
    let y = crate::field::Fp2::new(y0, y1);
    crate::curve::G2::from_coordinates(x, y)
}
