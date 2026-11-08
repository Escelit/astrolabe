//! Command-line interface for Astrolabe (`acf/0.1`).
//!
//! Provides `export`, `gen-verifier`, `verify`, and `doctor` commands
//! for moving zero-knowledge proofs onto Soroban contracts.

#![deny(unsafe_code)]

mod doctor;
mod error;
mod export;
mod gen_verifier;
mod verify;

use clap::{Parser, Subcommand};
use doctor::{run_doctor, DoctorArgs};
use error::CliError;
use export::{run_export, ExportArgs};
use gen_verifier::{run_gen_verifier, GenVerifierArgs};
use std::process::ExitCode;
use verify::{run_verify, VerifyArgs};

#[derive(Parser, Debug)]
#[command(
    name = "astrolabe",
    about = "Zero-knowledge proof tooling for Soroban smart contracts on Stellar",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Export proving artifacts (snarkjs JSON, ACF binary, or canonical JSON) to desired format.
    Export(ExportArgs),

    /// Generate a deployable Soroban Groth16 verifier contract from a verification key.
    GenVerifier(GenVerifierArgs),

    /// Verify a Groth16 proof locally (host simulation) or against a deployed contract.
    Verify(VerifyArgs),

    /// Check development environment, protocol compatibility, and toolchain readiness.
    Doctor(DoctorArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result: Result<(), CliError> = match cli.command {
        Commands::Export(args) => run_export(args),
        Commands::GenVerifier(args) => run_gen_verifier(args),
        Commands::Verify(args) => run_verify(args),
        Commands::Doctor(args) => run_doctor(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {}", err);
            ExitCode::FAILURE
        }
    }
}
