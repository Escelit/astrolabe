//! Implementation of `astrolabe doctor` diagnostic command.

use crate::error::CliError;
use std::process::Command;

/// Arguments for `astrolabe doctor`.
#[derive(Debug, clap::Args)]
pub struct DoctorArgs {
    /// Skip testing remote RPC network connectivity.
    #[arg(long)]
    pub offline: bool,

    /// Custom Stellar RPC URL to probe (defaults to Stellar Testnet).
    #[arg(long, default_value = "https://soroban-testnet.stellar.org")]
    pub rpc_url: String,
}

#[derive(Debug)]
struct CheckResult {
    name: &'static str,
    passed: bool,
    details: String,
    remedy: Option<&'static str>,
}

pub fn run_doctor(args: DoctorArgs) -> Result<(), CliError> {
    println!("=== Astrolabe Environment Diagnostics (doctor) ===\n");

    let mut checks = vec![
        // 1. rustc
        check_command(
            "rustc",
            &["--version"],
            "Install Rust via https://rustup.rs",
        ),
        // 2. wasm32v1-none target
        check_rustup_target("wasm32v1-none"),
        // 3. cargo
        check_command(
            "cargo",
            &["--version"],
            "Install Cargo via https://rustup.rs",
        ),
        // 4. stellar CLI
        check_command(
            "stellar",
            &["--version"],
            "Install Stellar CLI via `cargo install --locked stellar-cli`",
        ),
        // 5. circom
        check_command(
            "circom",
            &["--version"],
            "Install Circom via https://docs.circom.io/getting-started/installation/",
        ),
        // 6. snarkjs
        check_command(
            "snarkjs",
            &[],
            "Install snarkjs via `npm install -g snarkjs`",
        ),
        // 7. Node.js & pnpm
        check_command(
            "node",
            &["--version"],
            "Install Node.js (v18+) via https://nodejs.org",
        ),
        check_command(
            "pnpm",
            &["--version"],
            "Install pnpm via `npm install -g pnpm`",
        ),
    ];

    // 8. Stellar Testnet RPC connectivity
    if !args.offline {
        checks.push(check_rpc_health(&args.rpc_url));
    }

    let mut all_critical_passed = true;
    for check in &checks {
        let symbol = if check.passed { "✓" } else { "✗" };
        println!("[{}] {}: {}", symbol, check.name, check.details);
        if !check.passed {
            if let Some(remedy) = check.remedy {
                println!("    Fix: {}", remedy);
            }
            if check.name == "rustc"
                || check.name == "wasm32v1-none target"
                || check.name == "cargo"
            {
                all_critical_passed = false;
            }
        }
    }

    println!();
    if all_critical_passed {
        println!("All core requirements for Soroban BN254 verification are SATISFIED.");
        Ok(())
    } else {
        println!(
            "Some required components are missing or outdated. Please review the fixes above."
        );
        Err(CliError::Other(
            "Doctor diagnostic checks failed".to_string(),
        ))
    }
}

fn check_command(name: &'static str, args: &[&str], remedy: &'static str) -> CheckResult {
    match Command::new(name).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first_line = stdout
                .lines()
                .chain(stderr.lines())
                .find(|l| !l.trim().is_empty())
                .unwrap_or("Available")
                .trim();
            CheckResult {
                name,
                passed: true,
                details: first_line.to_string(),
                remedy: None,
            }
        }
        Err(e) => CheckResult {
            name,
            passed: false,
            details: format!("Not found or failed to execute: {}", e),
            remedy: Some(remedy),
        },
    }
}

fn check_rustup_target(target: &'static str) -> CheckResult {
    match Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.lines().any(|l| l.trim() == target) {
                CheckResult {
                    name: "wasm32v1-none target",
                    passed: true,
                    details: format!("Target '{}' is installed", target),
                    remedy: None,
                }
            } else {
                CheckResult {
                    name: "wasm32v1-none target",
                    passed: false,
                    details: format!("Target '{}' is not installed", target),
                    remedy: Some("Run `rustup target add wasm32v1-none`"),
                }
            }
        }
        Err(e) => CheckResult {
            name: "wasm32v1-none target",
            passed: false,
            details: format!("Failed to query rustup: {}", e),
            remedy: Some("Install rustup and run `rustup target add wasm32v1-none`"),
        },
    }
}

fn check_rpc_health(rpc_url: &str) -> CheckResult {
    let payload = r#"{"jsonrpc":"2.0","id":1,"method":"getHealth"}"#;
    match Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
            "--max-time",
            "5",
            rpc_url,
        ])
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("\"healthy\"") {
                CheckResult {
                    name: "Stellar RPC Health",
                    passed: true,
                    details: format!("{} is healthy", rpc_url),
                    remedy: None,
                }
            } else if output.status.success() && !stdout.trim().is_empty() {
                CheckResult {
                    name: "Stellar RPC Health",
                    passed: true,
                    details: format!("{} responded ({})", rpc_url, stdout.trim()),
                    remedy: None,
                }
            } else {
                CheckResult {
                    name: "Stellar RPC Health",
                    passed: false,
                    details: format!("RPC did not return healthy status: {}", stdout.trim()),
                    remedy: Some("Check internet connection or supply --offline"),
                }
            }
        }
        Err(e) => CheckResult {
            name: "Stellar RPC Health",
            passed: false,
            details: format!("Failed to curl RPC: {}", e),
            remedy: Some("Check internet connection or supply --offline"),
        },
    }
}
