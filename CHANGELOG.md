# Changelog

All notable changes to the Astrolabe project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-10

### Overview
Astrolabe v1.0.0 is the first production release of the toolchain and specification for zero-knowledge proof verification on Stellar Soroban contracts using the Protocol 25 BN254 host functions.

### Added
- **ACF Specification 1.0 (`acf/1.0`):** Promoted specification to Final 1.0 with all empirical `[VERIFY]` items resolved against CAP-0074, `soroban-sdk 29.0.1`, and live Stellar Testnet verification transactions.
- **Continuous Fuzzing Suite (`fuzz/`):** 8 coverage-guided fuzz targets using `cargo-fuzz` / LLVM `libFuzzer` (`fuzz_decode_g1`, `fuzz_decode_g2`, `fuzz_decode_proof`, `fuzz_decode_vk`, `fuzz_decode_envelope`, `fuzz_snarkjs_proof`, `fuzz_snarkjs_vk`, `fuzz_snarkjs_public`).
- **In-Tree Regression Property Tests:** Deterministic property fuzzing suites in Rust (`fuzz_regression.rs`) and TypeScript (`fuzz.test.ts`) executed on every test run.
- **Security Audit Report (`docs/security-review.md`):** Comprehensive line-by-line security review covering all six security hotspots, Soroban host boundaries, and formal security invariants.
- **Release Documentation (`docs/release.md`):** Step-by-step checklist and procedures for verifying, building, tagging, and publishing releases.
- **`make fuzz` Target:** Automated Makefile target to run Rust and TypeScript property fuzzing.
- **Parser Hardening:** Enforced `MAX_JSON_DEPTH = 64` in `#![no_std]` JSON parser to guard against stack exhaustion on malicious nested JSON.
- **Verifier Hardening:** Explicitly rejected `n_ic == 0` in contract `parse_vk` and `verify_groth16_bytes` with `VerifierError::PublicInputCount`.

### Changed
- Promoted all Cargo workspace crates (`astrolabe-core`, `astrolabe-verifier`, `astrolabe-cli`, `multiplier-verifier`) and TypeScript package (`astrolabe-ts`) to version `1.0.0`.
- Updated documentation links and format references across the repository to `acf/1.0`.

---

## [0.1.0] - 2026-10-31

### Added
- **Phase 0:** Workspace scaffold for Rust (`astrolabe-core`, `astrolabe-verifier`, `astrolabe-cli`) and TypeScript (`astrolabe-ts`), with 1:1 error code parity and vector schema.
- **Phase 1:** Soroban BN254 ground-truth empirical findings on Stellar Testnet Protocol 29 (`docs/phase1-findings.md`).
- **Phase 2:** Strict $F_p$, $F_r$, $F_{p^2}$, $G_1$, and $G_2$ codecs and validators with complete Jacobian twist-curve arithmetic and $[r]P = \mathcal{O}$ subgroup check.
- **Phase 3:** Groth16 `Proof`, `VerificationKey`, `PublicInputs`, canonical JSON, and 12-byte binary envelope with 101 conformance vectors.
- **Phase 4:** Zero-dependency `snarkjs` adapter in Rust (`#![no_std]`) and TypeScript, differential testing harness (`make differential`).
- **Phase 5:** Soroban verifier contract template and `astrolabe` CLI (`export`, `gen-verifier`, `verify`, `doctor`).
- **Phase 6:** End-to-end `circom-multiplier` example on Stellar Testnet and full documentation suite (`quickstart`, `concepts`, `cli-reference`, `format-reference`, `troubleshooting`).
