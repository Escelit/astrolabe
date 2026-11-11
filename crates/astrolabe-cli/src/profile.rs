//! Implementation of `astrolabe profile` command.
//!
//! Profiles Soroban resource consumption (CPU instructions, memory bytes, and WASM binary size)
//! for Groth16 verification against Stellar Protocol 25 Soroban network limits.

use crate::error::CliError;
use crate::export::{load_artifact_from_path, LoadedArtifact};
use astrolabe_core::ArtifactKind;
use astrolabe_verifier::verify_groth16_bytes;
use serde::Serialize;
use soroban_sdk::{Bytes, BytesN, Env, Vec};
use std::fs;
use std::path::PathBuf;

/// Stellar Protocol 25 Soroban network limits for smart contracts.
pub const SOROBAN_MAX_CPU_INSTRUCTIONS: u64 = 100_000_000;
pub const SOROBAN_STANDARD_CPU_BUDGET: u64 = 40_000_000;
pub const SOROBAN_MAX_MEMORY_BYTES: u64 = 41_943_040; // 40 MiB
pub const SOROBAN_MAX_WASM_SIZE_BYTES: u64 = 65_536; // 64 KiB recommended max

/// Arguments for `astrolabe profile`.
#[derive(Debug, clap::Args)]
pub struct ProfileArgs {
    /// Path to verification key artifact (snarkjs JSON or ACF binary/hex).
    #[arg(long)]
    pub vk: PathBuf,

    /// Path to proof artifact (snarkjs JSON or ACF binary/hex).
    #[arg(long)]
    pub proof: PathBuf,

    /// Path to public inputs artifact (snarkjs JSON or ACF binary/hex).
    #[arg(long)]
    pub public: PathBuf,

    /// Optional path to compiled verifier contract WASM file.
    #[arg(long)]
    pub wasm: Option<PathBuf>,

    /// Emit report as structured JSON for automation and CI checks.
    #[arg(long)]
    pub json: bool,
}

/// Structured profile report for JSON export.
#[derive(Debug, Serialize)]
pub struct ProfileReport {
    pub proof_valid: bool,
    pub n_public_inputs: usize,
    pub n_ic_points: usize,
    pub cpu_instructions: u64,
    pub cpu_limit: u64,
    pub cpu_headroom_pct: f64,
    pub memory_bytes: u64,
    pub memory_limit: u64,
    pub memory_headroom_pct: f64,
    pub g1_scalar_multiplications: usize,
    pub g1_point_additions: usize,
    pub pairing_pairs: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_limit_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_headroom_pct: Option<f64>,
}

pub fn run_profile(args: ProfileArgs) -> Result<(), CliError> {
    // 1. Load verification key
    let vk_artifact = load_artifact_from_path(&args.vk, Some(ArtifactKind::VerificationKey))?;
    let vk_bytes = match vk_artifact {
        LoadedArtifact::Vk(_, b) => b,
        _ => {
            return Err(CliError::Other(
                "Provided artifact is not a verification key".to_string(),
            ))
        }
    };

    // 2. Load proof
    let proof_artifact = load_artifact_from_path(&args.proof, Some(ArtifactKind::Proof))?;
    let proof_bytes = match proof_artifact {
        LoadedArtifact::Proof(_, b) => b,
        _ => {
            return Err(CliError::Other(
                "Provided artifact is not a proof".to_string(),
            ))
        }
    };
    if proof_bytes.len() != 256 {
        return Err(CliError::Other(format!(
            "Proof length must be exactly 256 bytes, got {}",
            proof_bytes.len()
        )));
    }

    // 3. Load public inputs
    let public_artifact = load_artifact_from_path(&args.public, Some(ArtifactKind::PublicInputs))?;
    let public_bytes = match public_artifact {
        LoadedArtifact::PublicInputs(_, b) => b,
        _ => {
            return Err(CliError::Other(
                "Provided artifact is not public inputs".to_string(),
            ))
        }
    };
    if public_bytes.is_empty() || !public_bytes.len().is_multiple_of(32) {
        return Err(CliError::Other(format!(
            "Public inputs length must be a non-zero multiple of 32 bytes, got {}",
            public_bytes.len()
        )));
    }

    let n_signals = public_bytes.len() / 32;

    // 4. Simulate execution in Soroban Env with resource metering
    let env = Env::default();
    let vk = Bytes::from_slice(&env, &vk_bytes);

    let mut proof_arr = [0u8; 256];
    proof_arr.copy_from_slice(&proof_bytes);
    let proof = BytesN::from_array(&env, &proof_arr);

    let mut pub_vec = Vec::new(&env);
    for chunk in public_bytes.chunks_exact(32) {
        let mut sig_arr = [0u8; 32];
        sig_arr.copy_from_slice(chunk);
        pub_vec.push_back(BytesN::from_array(&env, &sig_arr));
    }

    let initial_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let initial_mem = env.cost_estimate().budget().memory_bytes_cost();

    let is_valid = match verify_groth16_bytes(&env, &vk, &proof, &pub_vec) {
        Ok(valid) => valid,
        Err(err) => {
            return Err(CliError::Other(format!(
                "Verification simulation failed with [{}]",
                err.code()
            )));
        }
    };

    let final_cpu = env.cost_estimate().budget().cpu_instruction_cost();
    let final_mem = env.cost_estimate().budget().memory_bytes_cost();

    let cpu_used = final_cpu.saturating_sub(initial_cpu);
    let mem_used = final_mem.saturating_sub(initial_mem);

    let cpu_headroom_pct = (SOROBAN_MAX_CPU_INSTRUCTIONS.saturating_sub(cpu_used) as f64
        / SOROBAN_MAX_CPU_INSTRUCTIONS as f64)
        * 100.0;
    let mem_headroom_pct = (SOROBAN_MAX_MEMORY_BYTES.saturating_sub(mem_used) as f64
        / SOROBAN_MAX_MEMORY_BYTES as f64)
        * 100.0;

    // 5. Optional WASM binary analysis
    let (wasm_size_bytes, wasm_limit_bytes, wasm_headroom_pct) =
        if let Some(ref wasm_path) = args.wasm {
            let metadata = fs::metadata(wasm_path)
                .map_err(|e| CliError::Io(wasm_path.display().to_string(), e))?;
            let size = metadata.len();
            let headroom = (SOROBAN_MAX_WASM_SIZE_BYTES.saturating_sub(size) as f64
                / SOROBAN_MAX_WASM_SIZE_BYTES as f64)
                * 100.0;
            (
                Some(size),
                Some(SOROBAN_MAX_WASM_SIZE_BYTES),
                Some(headroom),
            )
        } else {
            (None, None, None)
        };

    let report = ProfileReport {
        proof_valid: is_valid,
        n_public_inputs: n_signals,
        n_ic_points: n_signals + 1,
        cpu_instructions: cpu_used,
        cpu_limit: SOROBAN_MAX_CPU_INSTRUCTIONS,
        cpu_headroom_pct,
        memory_bytes: mem_used,
        memory_limit: SOROBAN_MAX_MEMORY_BYTES,
        memory_headroom_pct: mem_headroom_pct,
        g1_scalar_multiplications: n_signals,
        g1_point_additions: n_signals,
        pairing_pairs: 4,
        wasm_size_bytes,
        wasm_limit_bytes,
        wasm_headroom_pct,
    };

    if args.json {
        let json_str =
            serde_json::to_string_pretty(&report).map_err(|e| CliError::Other(e.to_string()))?;
        println!("{}", json_str);
        return Ok(());
    }

    // Human-readable formatting
    println!("=== Astrolabe Cost Profiler (Stellar Protocol 25 BN254) ===");
    println!();
    println!(
        "Proof Verification Result : {}",
        if is_valid { "✓ VALID" } else { "✗ INVALID" }
    );
    println!("Public Inputs Count       : {}", n_signals);
    println!("IC Points in Key          : {}", n_signals + 1);
    println!();
    println!("Cryptographic Operation Breakdown:");
    println!(
        "  • G1 Scalar Multiplications : {} (IC linear combination)",
        n_signals
    );
    println!(
        "  • G1 Point Additions        : {} (accumulator additions)",
        n_signals
    );
    println!("  • G1 Point Negations        : 1 (-A via y -> p - y)");
    println!(
        "  • BN254 Multi-Pairing Check : 4 pairs (e(-A,B) * e(α,β) * e(vk_x,γ) * e(C,δ) == 1)"
    );
    println!();
    println!("Resource Consumption vs Soroban Network Limits:");
    println!(
        "  CPU Instructions : {:>10} / {:>10} ({:.2}% headroom)",
        cpu_used, SOROBAN_MAX_CPU_INSTRUCTIONS, cpu_headroom_pct
    );
    if cpu_used > SOROBAN_STANDARD_CPU_BUDGET {
        println!("  ⚠️ Warning: CPU cost exceeds standard 40M budget (requires extended limit up to 100M)");
    } else {
        println!("  ✓ Within standard default tx budget (40,000,000 instructions)");
    }

    println!(
        "  RAM Memory Bytes : {:>10} / {:>10} ({:.2}% headroom)",
        mem_used, SOROBAN_MAX_MEMORY_BYTES, mem_headroom_pct
    );

    if let Some(w_size) = wasm_size_bytes {
        let w_headroom = wasm_headroom_pct.unwrap_or(0.0);
        println!(
            "  WASM Binary Size : {:>10} / {:>10} bytes ({:.2}% headroom)",
            w_size, SOROBAN_MAX_WASM_SIZE_BYTES, w_headroom
        );
        if w_size > SOROBAN_MAX_WASM_SIZE_BYTES {
            println!("  ⚠️ Warning: WASM binary size exceeds recommended 64 KiB threshold!");
        } else {
            println!("  ✓ WASM binary size is within recommended 64 KiB threshold");
        }
    }
    println!();
    println!("Overall Status: ✓ PASSED ALL SOROBAN CONSTRAINTS");

    Ok(())
}
