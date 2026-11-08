//! Implementation of `astrolabe verify` command.

use crate::error::CliError;
use crate::export::{load_artifact_from_path, LoadedArtifact};
use astrolabe_core::ArtifactKind;
use astrolabe_verifier::verify_groth16_bytes;
use soroban_sdk::{Bytes, BytesN, Env, Vec};
use std::path::PathBuf;
use std::process::Command;

/// Arguments for `astrolabe verify`.
#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    /// Path to proof artifact (snarkjs proof.json or ACF binary/hex).
    #[arg(long)]
    pub proof: PathBuf,

    /// Path to public inputs artifact (snarkjs public.json or ACF binary/hex).
    #[arg(long)]
    pub public: PathBuf,

    /// Path to verification key (snarkjs verification_key.json or ACF binary/hex) for local verification.
    #[arg(long)]
    pub vk: Option<PathBuf>,

    /// Deployed contract ID for on-chain verification.
    #[arg(long)]
    pub contract_id: Option<String>,

    /// Network name for on-chain verification (e.g. testnet, futurenet, standalone).
    #[arg(long, default_value = "testnet")]
    pub network: String,

    /// Stellar identity or secret key used as the source account for on-chain invocation.
    #[arg(long)]
    pub source: Option<String>,

    /// Custom Stellar RPC URL.
    #[arg(long)]
    pub rpc_url: Option<String>,
}

pub fn run_verify(args: VerifyArgs) -> Result<(), CliError> {
    let proof_artifact = load_artifact_from_path(&args.proof, Some(ArtifactKind::Proof))?;
    let proof_bytes = match proof_artifact {
        LoadedArtifact::Proof(_, b) => b,
        _ => return Err(CliError::Other("Invalid proof artifact".to_string())),
    };
    if proof_bytes.len() != 256 {
        return Err(CliError::Other(format!(
            "Proof length must be exactly 256 bytes, got {}",
            proof_bytes.len()
        )));
    }

    let public_artifact = load_artifact_from_path(&args.public, Some(ArtifactKind::PublicInputs))?;
    let public_bytes = match public_artifact {
        LoadedArtifact::PublicInputs(_, b) => b,
        _ => {
            return Err(CliError::Other(
                "Invalid public inputs artifact".to_string(),
            ))
        }
    };
    if public_bytes.is_empty() || !public_bytes.len().is_multiple_of(32) {
        return Err(CliError::Other(format!(
            "Public inputs length must be a non-zero multiple of 32 bytes, got {}",
            public_bytes.len()
        )));
    }

    // Branch 1: On-chain verification
    if let Some(ref contract_id) = args.contract_id {
        return run_onchain_verify(
            contract_id,
            &args.network,
            args.source.as_deref(),
            args.rpc_url.as_deref(),
            &proof_bytes,
            &public_bytes,
        );
    }

    // Branch 2: Local verification via verification key
    if let Some(ref vk_path) = args.vk {
        let vk_artifact = load_artifact_from_path(vk_path, Some(ArtifactKind::VerificationKey))?;
        let vk_bytes = match vk_artifact {
            LoadedArtifact::Vk(_, b) => b,
            _ => {
                return Err(CliError::Other(
                    "Invalid verification key artifact".to_string(),
                ))
            }
        };
        return run_local_verify(&vk_bytes, &proof_bytes, &public_bytes);
    }

    Err(CliError::MissingArgument(
        "Either --vk (for local verification) or --contract-id (for on-chain verification) must be provided".to_string(),
    ))
}

fn run_local_verify(
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_bytes: &[u8],
) -> Result<(), CliError> {
    println!("=== Astrolabe Local Verifier (Soroban Host Simulation) ===");

    let env = Env::default();
    let vk = Bytes::from_slice(&env, vk_bytes);

    let mut proof_arr = [0u8; 256];
    proof_arr.copy_from_slice(proof_bytes);
    let proof = BytesN::from_array(&env, &proof_arr);

    let mut pub_vec = Vec::new(&env);
    let mut num_signals = 0;
    for chunk in public_bytes.chunks_exact(32) {
        let mut sig_arr = [0u8; 32];
        sig_arr.copy_from_slice(chunk);
        pub_vec.push_back(BytesN::from_array(&env, &sig_arr));
        num_signals += 1;
    }

    match verify_groth16_bytes(&env, &vk, &proof, &pub_vec) {
        Ok(true) => {
            println!("✓ Proof verification SUCCEEDED!");
            println!("  Public inputs count: {}", num_signals);
            println!("  Pairing check: VALID (product in GT is identity)");
            Ok(())
        }
        Ok(false) => {
            println!("✗ Proof verification FAILED!");
            println!("  Pairing check evaluated to false.");
            Err(CliError::Other("Proof pairing check failed".to_string()))
        }
        Err(err) => {
            println!("✗ Proof verification REJECTED with [{}]", err.code());
            println!("  Spec Section 11 code: {}", err.code());
            match err {
                astrolabe_verifier::VerifierError::BadLength => {
                    println!("  Reason: Payload size does not match expected length.");
                }
                astrolabe_verifier::VerifierError::NonCanonicalField => {
                    println!(
                        "  Reason: Point coordinate or public scalar is >= field modulus (p or r)."
                    );
                }
                astrolabe_verifier::VerifierError::PublicInputCount => {
                    println!("  Reason: Public inputs count does not match verification key (n_public + 1 != n_ic).");
                }
                astrolabe_verifier::VerifierError::InvalidProof => {
                    println!("  Reason: Proof contains degenerate (infinity) point or pairing equation failed.");
                }
                _ => {
                    println!("  Reason: Verification rejected by contract rule.");
                }
            }
            Err(CliError::Other(format!(
                "Verification failed with {}",
                err.code()
            )))
        }
    }
}

fn run_onchain_verify(
    contract_id: &str,
    network: &str,
    source: Option<&str>,
    rpc_url: Option<&str>,
    proof_bytes: &[u8],
    public_bytes: &[u8],
) -> Result<(), CliError> {
    println!("=== Astrolabe On-Chain Verifier ===");
    println!("Target contract: {}", contract_id);
    println!("Network: {}", network);

    let proof_hex = hex::encode(proof_bytes);
    let mut pub_signals_json_items = std::vec::Vec::new();
    for chunk in public_bytes.chunks_exact(32) {
        pub_signals_json_items.push(format!("\"{}\"", hex::encode(chunk)));
    }
    let pub_signals_arg = format!("[{}]", pub_signals_json_items.join(", "));

    let mut cmd = Command::new("stellar");
    cmd.arg("contract").arg("invoke");
    cmd.arg("--id").arg(contract_id);
    cmd.arg("--network").arg(network);

    if let Some(src) = source {
        cmd.arg("--source").arg(src);
    } else {
        // Read-only simulation mode
        cmd.arg("--send").arg("false");
    }

    if let Some(rpc) = rpc_url {
        cmd.arg("--rpc-url").arg(rpc);
    }

    cmd.arg("--");
    cmd.arg("verify");
    cmd.arg("--proof").arg(&proof_hex);
    cmd.arg("--public-inputs").arg(&pub_signals_arg);

    println!(
        "Executing: stellar contract invoke --id {} ...",
        contract_id
    );
    let output = cmd.output().map_err(|e| {
        CliError::CommandFailed("stellar contract invoke".to_string(), e.to_string())
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        eprintln!("{}", stderr);
        return Err(CliError::CommandFailed(
            "stellar contract invoke".to_string(),
            format!(
                "Exit code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr
            ),
        ));
    }

    println!("{}", stdout);
    if stdout.contains("true") {
        println!("✓ On-chain proof verification confirmed TRUE!");
    }

    Ok(())
}
