//! Implementation of `astrolabe export` command.

use crate::error::CliError;
use astrolabe_core::noir::{
    extract_noir_metadata, parse_noir_proof, parse_noir_public_inputs, parse_noir_vk,
};
use astrolabe_core::risc0::{parse_risc0_receipt_json, Risc0PublicInputsMode};
use astrolabe_core::snarkjs::{parse_snarkjs_proof, parse_snarkjs_public_inputs, parse_snarkjs_vk};
use astrolabe_core::{
    decode_envelope, decode_proof, decode_public_inputs, decode_vk, encode_envelope, encode_proof,
    encode_public_inputs, encode_vk, to_canonical_json, ArtifactKind, Envelope,
};
use clap::ValueEnum;
use std::fs;
use std::path::{Path, PathBuf};

/// Target output format for artifact export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// Raw ACF payload bytes in lowercase hex.
    AcfHex,
    /// Self-describing ACF binary envelope (.astr).
    Envelope,
    /// Canonical JSON representation per ACF Spec Section 6.
    CanonicalJson,
    /// Soroban-formatted arguments ready for `stellar contract invoke`.
    SorobanArgs,
}

/// Source proving toolchain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum ArtifactSource {
    /// Auto-detect format from file contents.
    #[default]
    Auto,
    /// Circom / snarkjs Groth16 JSON artifacts.
    Snarkjs,
    /// Noir Groth16 artifacts (individual files or unified bundle).
    Noir,
    /// RISC Zero Groth16 receipt/seal and journal artifacts.
    Risc0,
}

/// RISC Zero public input mapping mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum Risc0Mapping {
    /// 4-scalar 16-byte limb split (`[image_id_hi, image_id_lo, journal_hi, journal_lo]`).
    #[default]
    Limb16,
    /// 2-scalar direct representation (`[image_id, journal_digest]`).
    Direct,
}

impl From<Risc0Mapping> for Risc0PublicInputsMode {
    fn from(val: Risc0Mapping) -> Self {
        match val {
            Risc0Mapping::Limb16 => Self::Limb16,
            Risc0Mapping::Direct => Self::Direct,
        }
    }
}

/// Arguments for `astrolabe export`.
#[derive(Debug, clap::Args)]
pub struct ExportArgs {
    /// Source proving toolchain (auto, snarkjs, noir, risc0).
    #[arg(long, value_enum, default_value = "auto")]
    pub source: ArtifactSource,

    /// Path to unified bundle or receipt JSON (Noir bundle or RISC Zero receipt).
    #[arg(long)]
    pub bundle: Option<PathBuf>,

    /// Path to proof artifact (snarkjs proof.json or ACF binary/hex).
    #[arg(long)]
    pub proof: Option<PathBuf>,

    /// Path to verification key artifact (snarkjs verification_key.json or ACF binary/hex).
    #[arg(long)]
    pub vk: Option<PathBuf>,

    /// Path to public inputs artifact (snarkjs public.json or ACF binary/hex).
    #[arg(long)]
    pub public: Option<PathBuf>,

    /// Desired export format.
    #[arg(long, value_enum, default_value = "acf-hex")]
    pub format: ExportFormat,

    /// RISC Zero public input mapping mode (limb16 or direct).
    #[arg(long, value_enum, default_value = "limb16")]
    pub risc0_mapping: Risc0Mapping,

    /// Optional output directory to write exported artifacts.
    #[arg(long)]
    pub out_dir: Option<PathBuf>,

    /// Optional output file path (when exporting a single artifact).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub(crate) enum LoadedArtifact {
    Proof(Box<astrolabe_core::Proof>, Vec<u8>),
    Vk(Box<astrolabe_core::VerificationKey>, Vec<u8>),
    PublicInputs(astrolabe_core::PublicInputs, Vec<u8>),
}

pub(crate) fn load_artifact_from_path(
    path: &Path,
    expected_kind: Option<ArtifactKind>,
) -> Result<LoadedArtifact, CliError> {
    load_artifact_with_options(
        path,
        expected_kind,
        ArtifactSource::Auto,
        Risc0PublicInputsMode::Limb16,
    )
}

pub(crate) fn load_artifact_with_options(
    path: &Path,
    expected_kind: Option<ArtifactKind>,
    source: ArtifactSource,
    risc0_mode: Risc0PublicInputsMode,
) -> Result<LoadedArtifact, CliError> {
    let raw = fs::read(path).map_err(|e| CliError::Io(path.display().to_string(), e))?;

    // Explicit toolchain dispatch when --source is not auto
    if source != ArtifactSource::Auto {
        let text = std::str::from_utf8(&raw).map_err(|_| {
            CliError::Other(format!(
                "Expected UTF-8 JSON artifact for --source {:?} in '{}'",
                source,
                path.display()
            ))
        })?;
        let trimmed = text.trim();
        match source {
            ArtifactSource::Risc0 => {
                let receipt = parse_risc0_receipt_json(trimmed, risc0_mode)?;
                return match expected_kind {
                    Some(ArtifactKind::PublicInputs) => {
                        let bytes = encode_public_inputs(&receipt.public_inputs);
                        Ok(LoadedArtifact::PublicInputs(receipt.public_inputs, bytes))
                    }
                    Some(ArtifactKind::VerificationKey) => Err(CliError::Other(
                        "RISC Zero receipts do not contain a verification key".to_string(),
                    )),
                    _ => {
                        let bytes = encode_proof(&receipt.proof).to_vec();
                        Ok(LoadedArtifact::Proof(Box::new(receipt.proof), bytes))
                    }
                };
            }
            ArtifactSource::Snarkjs => {
                return match expected_kind {
                    Some(ArtifactKind::Proof) => {
                        let p = parse_snarkjs_proof(trimmed)?;
                        let bytes = encode_proof(&p).to_vec();
                        Ok(LoadedArtifact::Proof(Box::new(p), bytes))
                    }
                    Some(ArtifactKind::VerificationKey) => {
                        let vk = parse_snarkjs_vk(trimmed)?;
                        let bytes = encode_vk(&vk);
                        Ok(LoadedArtifact::Vk(Box::new(vk), bytes))
                    }
                    Some(ArtifactKind::PublicInputs) => {
                        let pi = parse_snarkjs_public_inputs(trimmed)?;
                        let bytes = encode_public_inputs(&pi);
                        Ok(LoadedArtifact::PublicInputs(pi, bytes))
                    }
                    None => {
                        if trimmed.contains("\"pi_a\"") {
                            let p = parse_snarkjs_proof(trimmed)?;
                            let bytes = encode_proof(&p).to_vec();
                            Ok(LoadedArtifact::Proof(Box::new(p), bytes))
                        } else if trimmed.contains("\"vk_alpha_1\"") {
                            let vk = parse_snarkjs_vk(trimmed)?;
                            let bytes = encode_vk(&vk);
                            Ok(LoadedArtifact::Vk(Box::new(vk), bytes))
                        } else {
                            let pi = parse_snarkjs_public_inputs(trimmed)?;
                            let bytes = encode_public_inputs(&pi);
                            Ok(LoadedArtifact::PublicInputs(pi, bytes))
                        }
                    }
                };
            }
            ArtifactSource::Noir => {
                return match expected_kind {
                    Some(ArtifactKind::Proof) => {
                        let p = parse_noir_proof(trimmed)?;
                        let bytes = encode_proof(&p).to_vec();
                        Ok(LoadedArtifact::Proof(Box::new(p), bytes))
                    }
                    Some(ArtifactKind::VerificationKey) => {
                        let vk = parse_noir_vk(trimmed)?;
                        let bytes = encode_vk(&vk);
                        Ok(LoadedArtifact::Vk(Box::new(vk), bytes))
                    }
                    Some(ArtifactKind::PublicInputs) => {
                        let pi = parse_noir_public_inputs(trimmed)?;
                        let bytes = encode_public_inputs(&pi);
                        Ok(LoadedArtifact::PublicInputs(pi, bytes))
                    }
                    None => {
                        if trimmed.contains("\"pi_a\"") {
                            let p = parse_noir_proof(trimmed)?;
                            let bytes = encode_proof(&p).to_vec();
                            Ok(LoadedArtifact::Proof(Box::new(p), bytes))
                        } else if trimmed.contains("\"vk_alpha_1\"") {
                            let vk = parse_noir_vk(trimmed)?;
                            let bytes = encode_vk(&vk);
                            Ok(LoadedArtifact::Vk(Box::new(vk), bytes))
                        } else {
                            let pi = parse_noir_public_inputs(trimmed)?;
                            let bytes = encode_public_inputs(&pi);
                            Ok(LoadedArtifact::PublicInputs(pi, bytes))
                        }
                    }
                };
            }
            ArtifactSource::Auto => unreachable!(),
        }
    }

    // 1. Try decoding as binary envelope first
    if raw.len() >= 8 && &raw[0..4] == b"ASTR" {
        let env = decode_envelope(&raw)?;
        let payload_bytes = env.payload.encode();
        return match env.payload {
            astrolabe_core::EnvelopePayload::Proof(p) => {
                Ok(LoadedArtifact::Proof(Box::new(p), payload_bytes))
            }
            astrolabe_core::EnvelopePayload::VerificationKey(vk) => {
                Ok(LoadedArtifact::Vk(Box::new(vk), payload_bytes))
            }
            astrolabe_core::EnvelopePayload::PublicInputs(pi) => {
                Ok(LoadedArtifact::PublicInputs(pi, payload_bytes))
            }
        };
    }

    // 2. Try UTF-8 text (snarkjs JSON or canonical JSON or hex)
    if let Ok(text) = std::str::from_utf8(&raw) {
        let trimmed = text.trim();

        // Hex string?
        if !trimmed.is_empty()
            && trimmed.len().is_multiple_of(2)
            && trimmed.chars().all(|c| c.is_ascii_hexdigit())
        {
            let bytes =
                hex::decode(trimmed).map_err(|e| CliError::Hex(path.display().to_string(), e))?;
            if let Some(kind) = expected_kind {
                return match kind {
                    ArtifactKind::Proof => {
                        let p = decode_proof(&bytes)?;
                        Ok(LoadedArtifact::Proof(Box::new(p), bytes))
                    }
                    ArtifactKind::VerificationKey => {
                        let vk = decode_vk(&bytes)?;
                        Ok(LoadedArtifact::Vk(Box::new(vk), bytes))
                    }
                    ArtifactKind::PublicInputs => {
                        let pi = decode_public_inputs(&bytes)?;
                        Ok(LoadedArtifact::PublicInputs(pi, bytes))
                    }
                };
            }
            // Auto-detect by length
            if bytes.len() == 256 {
                let p = decode_proof(&bytes)?;
                return Ok(LoadedArtifact::Proof(Box::new(p), bytes));
            } else if bytes.len() >= 452 && (bytes.len() - 452).is_multiple_of(64) {
                let vk = decode_vk(&bytes)?;
                return Ok(LoadedArtifact::Vk(Box::new(vk), bytes));
            } else if !bytes.is_empty() && bytes.len().is_multiple_of(32) {
                let pi = decode_public_inputs(&bytes)?;
                return Ok(LoadedArtifact::PublicInputs(pi, bytes));
            }
        }

        // Canonical JSON?
        if trimmed.starts_with('{') && trimmed.contains("\"acf\"") {
            if let Ok(canonical) = serde_json::from_str::<serde_json::Value>(trimmed) {
                if let Some(hex_str) = canonical.get("hex").and_then(|v| v.as_str()) {
                    let bytes = hex::decode(hex_str)
                        .map_err(|e| CliError::Hex(path.display().to_string(), e))?;
                    let kind_str = canonical
                        .get("kind")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    return match kind_str {
                        "proof" => {
                            let p = decode_proof(&bytes)?;
                            Ok(LoadedArtifact::Proof(Box::new(p), bytes))
                        }
                        "verification_key" => {
                            let vk = decode_vk(&bytes)?;
                            Ok(LoadedArtifact::Vk(Box::new(vk), bytes))
                        }
                        "public_inputs" => {
                            let pi = decode_public_inputs(&bytes)?;
                            Ok(LoadedArtifact::PublicInputs(pi, bytes))
                        }
                        _ => Err(CliError::Other(format!(
                            "Unknown canonical JSON kind: '{}'",
                            kind_str
                        ))),
                    };
                }
            }
        }

        // Auto-detect RISC Zero receipt JSON
        if trimmed.contains("\"seal\"")
            || (trimmed.contains("\"image_id\"") && trimmed.contains("\"journal\""))
        {
            if let Ok(receipt) = parse_risc0_receipt_json(trimmed, risc0_mode) {
                if expected_kind == Some(ArtifactKind::PublicInputs) {
                    let bytes = encode_public_inputs(&receipt.public_inputs);
                    return Ok(LoadedArtifact::PublicInputs(receipt.public_inputs, bytes));
                } else {
                    let bytes = encode_proof(&receipt.proof).to_vec();
                    return Ok(LoadedArtifact::Proof(Box::new(receipt.proof), bytes));
                }
            }
        }

        // Try Noir / snarkjs formats
        if let Some(kind) = expected_kind {
            match kind {
                ArtifactKind::Proof => {
                    let p = parse_noir_proof(trimmed)?;
                    let bytes = encode_proof(&p).to_vec();
                    return Ok(LoadedArtifact::Proof(Box::new(p), bytes));
                }
                ArtifactKind::VerificationKey => {
                    let vk = parse_noir_vk(trimmed)?;
                    let bytes = encode_vk(&vk);
                    return Ok(LoadedArtifact::Vk(Box::new(vk), bytes));
                }
                ArtifactKind::PublicInputs => {
                    let pi = parse_noir_public_inputs(trimmed)?;
                    let bytes = encode_public_inputs(&pi);
                    return Ok(LoadedArtifact::PublicInputs(pi, bytes));
                }
            }
        }

        if trimmed.contains("\"pi_a\"") {
            let p = parse_noir_proof(trimmed)?;
            let bytes = encode_proof(&p).to_vec();
            return Ok(LoadedArtifact::Proof(Box::new(p), bytes));
        } else if trimmed.contains("\"vk_alpha_1\"") {
            let vk = parse_noir_vk(trimmed)?;
            let bytes = encode_vk(&vk);
            return Ok(LoadedArtifact::Vk(Box::new(vk), bytes));
        } else if trimmed.starts_with('[') {
            let pi = parse_noir_public_inputs(trimmed)?;
            let bytes = encode_public_inputs(&pi);
            return Ok(LoadedArtifact::PublicInputs(pi, bytes));
        }
    }

    // Raw binary auto-detect by length
    if raw.len() == 256 {
        let p = decode_proof(&raw)?;
        Ok(LoadedArtifact::Proof(Box::new(p), raw))
    } else if raw.len() >= 452 && (raw.len() - 452).is_multiple_of(64) {
        let vk = decode_vk(&raw)?;
        Ok(LoadedArtifact::Vk(Box::new(vk), raw))
    } else if !raw.is_empty() && raw.len().is_multiple_of(32) {
        let pi = decode_public_inputs(&raw)?;
        Ok(LoadedArtifact::PublicInputs(pi, raw))
    } else {
        Err(CliError::Other(format!(
            "Could not detect artifact format for file '{}' (size {} bytes)",
            path.display(),
            raw.len()
        )))
    }
}

pub fn run_export(mut args: ExportArgs) -> Result<(), CliError> {
    // Expand --bundle into --proof, --vk, --public based on bundle contents if not explicitly set
    if let Some(ref bundle_path) = args.bundle {
        let text = fs::read_to_string(bundle_path)
            .map_err(|e| CliError::Io(bundle_path.display().to_string(), e))?;
        if args.proof.is_none()
            && (text.contains("\"proof\"")
                || text.contains("\"pi_a\"")
                || text.contains("\"seal\""))
        {
            args.proof = Some(bundle_path.clone());
        }
        if args.vk.is_none()
            && (text.contains("\"verification_key\"")
                || text.contains("\"vk\"")
                || text.contains("\"vk_alpha_1\""))
        {
            args.vk = Some(bundle_path.clone());
        }
        if args.public.is_none()
            && (text.contains("\"public_inputs\"")
                || text.contains("\"public\"")
                || text.contains("\"journal\"")
                || text.contains("\"journal_digest\"")
                || text.contains("\"journalDigest\""))
        {
            args.public = Some(bundle_path.clone());
        }
    }

    if args.proof.is_none() && args.vk.is_none() && args.public.is_none() {
        return Err(CliError::MissingArgument(
            "At least one of --bundle, --proof, --vk, or --public must be provided".to_string(),
        ));
    }

    let risc0_mode: Risc0PublicInputsMode = args.risc0_mapping.into();

    // Inspect Noir provenance metadata if present (Spec Section 10.2)
    for path in [&args.proof, &args.vk, &args.public]
        .iter()
        .filter_map(|p| p.as_ref())
    {
        if let Ok(text) = fs::read_to_string(path) {
            if let Ok(meta) = extract_noir_metadata(&text) {
                if meta.noir_version.is_some()
                    || meta.backend.is_some()
                    || meta.circuit_name.is_some()
                {
                    println!(
                        "Noir provenance metadata: version={:?}, backend={:?}, circuit={:?}",
                        meta.noir_version, meta.backend, meta.circuit_name
                    );
                    break;
                }
            }
        }
    }

    // Special case: --format soroban-args prints the combined invocation
    if args.format == ExportFormat::SorobanArgs {
        return export_soroban_args(&args, risc0_mode);
    }

    if let Some(ref path) = args.proof {
        let artifact =
            load_artifact_with_options(path, Some(ArtifactKind::Proof), args.source, risc0_mode)?;
        export_single(
            artifact,
            "proof",
            args.format,
            args.out.as_ref(),
            args.out_dir.as_ref(),
        )?;
    }

    if let Some(ref path) = args.vk {
        let artifact = load_artifact_with_options(
            path,
            Some(ArtifactKind::VerificationKey),
            args.source,
            risc0_mode,
        )?;
        export_single(
            artifact,
            "vk",
            args.format,
            args.out.as_ref(),
            args.out_dir.as_ref(),
        )?;
    }

    if let Some(ref path) = args.public {
        let artifact = load_artifact_with_options(
            path,
            Some(ArtifactKind::PublicInputs),
            args.source,
            risc0_mode,
        )?;
        export_single(
            artifact,
            "public",
            args.format,
            args.out.as_ref(),
            args.out_dir.as_ref(),
        )?;
    }

    Ok(())
}

fn export_single(
    artifact: LoadedArtifact,
    base_name: &str,
    format: ExportFormat,
    out_file: Option<&PathBuf>,
    out_dir: Option<&PathBuf>,
) -> Result<(), CliError> {
    let payload = match artifact {
        LoadedArtifact::Proof(p, _) => astrolabe_core::EnvelopePayload::Proof(*p),
        LoadedArtifact::Vk(vk, _) => astrolabe_core::EnvelopePayload::VerificationKey(*vk),
        LoadedArtifact::PublicInputs(pi, _) => astrolabe_core::EnvelopePayload::PublicInputs(pi),
    };
    let payload_bytes = payload.encode();
    let envelope = Envelope::new(payload);

    let (content_bytes, default_ext) = match format {
        ExportFormat::AcfHex => {
            let hex_str = hex::encode(&payload_bytes) + "\n";
            (hex_str.into_bytes(), "hex")
        }
        ExportFormat::Envelope => {
            let env_bytes = encode_envelope(&envelope);
            (env_bytes, "astr")
        }
        ExportFormat::CanonicalJson => {
            let json_str = to_canonical_json(&envelope);
            (json_str.into_bytes(), "json")
        }
        ExportFormat::SorobanArgs => {
            unreachable!("Handled separately");
        }
    };

    if let Some(file) = out_file {
        fs::write(file, &content_bytes).map_err(|e| CliError::Io(file.display().to_string(), e))?;
        println!("Exported {} to {}", base_name, file.display());
    } else if let Some(dir) = out_dir {
        fs::create_dir_all(dir).map_err(|e| CliError::Io(dir.display().to_string(), e))?;
        let target = dir.join(format!("{}.{}", base_name, default_ext));
        fs::write(&target, &content_bytes)
            .map_err(|e| CliError::Io(target.display().to_string(), e))?;
        println!("Exported {} to {}", base_name, target.display());
    } else {
        if format == ExportFormat::Envelope {
            // Write binary to stdout or hex representation
            print!("{}", hex::encode(&content_bytes));
            println!();
        } else {
            print!("{}", String::from_utf8_lossy(&content_bytes));
        }
    }

    Ok(())
}

fn export_soroban_args(
    args: &ExportArgs,
    risc0_mode: Risc0PublicInputsMode,
) -> Result<(), CliError> {
    let mut proof_hex = String::new();
    let mut pub_signals_hex = Vec::new();

    if let Some(ref path) = args.proof {
        let artifact =
            load_artifact_with_options(path, Some(ArtifactKind::Proof), args.source, risc0_mode)?;
        if let LoadedArtifact::Proof(_, bytes) = artifact {
            proof_hex = hex::encode(bytes);
        }
    }

    if let Some(ref path) = args.public {
        let artifact = load_artifact_with_options(
            path,
            Some(ArtifactKind::PublicInputs),
            args.source,
            risc0_mode,
        )?;
        if let LoadedArtifact::PublicInputs(_, bytes) = artifact {
            for chunk in bytes.chunks_exact(32) {
                pub_signals_hex.push(format!("\"{}\"", hex::encode(chunk)));
            }
        }
    }

    let pub_signals_json = format!("[{}]", pub_signals_hex.join(", "));

    println!("# Soroban CLI invocation arguments:");
    if !proof_hex.is_empty() {
        println!("--proof {}", proof_hex);
    }
    if !pub_signals_hex.is_empty() {
        println!("--public-inputs '{}'", pub_signals_json);
    }
    println!();
    println!("# Example Stellar CLI command:");
    println!("stellar contract invoke \\");
    println!("  --id <CONTRACT_ID> \\");
    println!("  --source <IDENTITY> \\");
    println!("  --network testnet \\");
    println!("  -- \\");
    println!("  verify \\");
    if !proof_hex.is_empty() {
        println!("  --proof {} \\", proof_hex);
    }
    if !pub_signals_hex.is_empty() {
        println!("  --public-inputs '{}'", pub_signals_json);
    }

    Ok(())
}
