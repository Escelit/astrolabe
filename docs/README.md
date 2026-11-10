# Astrolabe Documentation

Welcome to the documentation for **Astrolabe (`acf/1.0`)**, the open-source toolkit and canonical format for verifying zero-knowledge proofs from Circom/`snarkjs` (and `snarkjs`-compatible Noir Groth16 backends) in Soroban smart contracts on Stellar.

---

## Documentation Map

| Guide | What You Will Learn |
| ----- | ------------------- |
| [**Quickstart**](quickstart.md) | Go from a fresh clone to a verified Groth16 proof locally and on Stellar Testnet in under 15 minutes. |
| [**Core Concepts & Security**](concepts.md) | How Soroban Protocol 25+ BN254 host functions work, why `Fp2` ordering and scalar aliasing matter, and baked vs. stored verification keys. |
| [**CLI Reference**](cli-reference.md) | Complete command, flag, and format documentation for `astrolabe export`, `gen-verifier`, `verify`, and `doctor`. |
| [**Format Reference (`acf/1.0`)**](format-reference.md) | Byte-level layouts for `Fp`, `Fr`, `G1`, `G2`, `Proof`, `VerificationKey`, `PublicInputs`, `Envelope`, and Canonical JSON. |
| [**Troubleshooting Guide**](troubleshooting.md) | Common encoding mistakes, Soroban host traps, ACF error codes (`ERR_*`), symptoms, and how to fix them. |
| [**Phase 1 Ground-Truth Findings**](phase1-findings.md) | Empirical verification of Soroban BN254 host behavior with SDK/host source citations and Stellar Testnet transaction hashes. |
| [**Security Audit & Verification Report**](security-review.md) | Line-by-line review of all cryptographic hotspots, fuzzing coverage results, and formal security invariants. |
| [**Project Roadmap**](roadmap.md) | Completed milestones (Phases 0–7) and planned work (Noir, RISC Zero, cost profiler). |
| [**End-to-End Example (`circom-multiplier`)**](../examples/circom-multiplier/README.md) | Self-contained Circom 2.0 `Multiplier2` circuit, public `snarkjs` artifacts, generated Soroban contract, and Testnet walkthrough. |

> **Normative Specification:** The authoritative byte-level specification is [`spec/spec.md`](spec.md), backed by 101 cross-language conformance vectors in [`spec/vectors/`](../spec/vectors/).

---

## Compatibility Table

Astrolabe (`acf/0.1`) is tested in CI and against live Stellar Testnet RPC with the following tool and protocol versions:

| Component | Supported / Tested Version | Notes |
| --------- | -------------------------- | ----- |
| **Stellar Protocol** | **Protocol 25+** (tested on **Protocol 29**) | Requires CAP-0074 BN254 host functions (`bn254_g1_add`, `bn254_g1_mul`, `bn254_multi_pairing_check`) |
| **`soroban-sdk`** | `=29.0.1` | Uses `soroban_sdk::crypto::bn254::{Bn254, Bn254Fp, Bn254Fr, Bn254G1Affine, Bn254G2Affine}` |
| **`soroban-env-host`** | `=29.0.1` | Used for local host simulation (`astrolabe verify`) and contract integration tests |
| **`stellar-cli`** | `28.0.0+` | Used for `stellar contract build`, `deploy`, and `invoke` |
| **Rust (`rustc` / `cargo`)** | `1.85+` (pinned `1.97.1` in `rust-toolchain.toml`) | Requires `wasm32v1-none` target (`rustup target add wasm32v1-none`) |
| **Circom** | `2.2.3` (`2.0.0+` compatible) | Compiles `.circom` circuits with `--prime bn128` (default) |
| **`snarkjs`** | `0.7.6` | Groth16 proving and verification over `"curve": "bn128"` |
| **Node.js** | `24.x` (`18+` compatible) | Required for `astrolabe-ts` and differential tests |
| **`pnpm`** | `10.x` (`9+` compatible) | Workspace package manager for `packages/astrolabe-ts` |
