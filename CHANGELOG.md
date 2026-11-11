# Changelog

All notable changes to the Astrolabe project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-11-11

### Overview
Astrolabe v1.1.0 delivers Phase 8 expansion, adding official adapter support for Noir and RISC Zero proving toolchains, a Soroban cost profiler (`astrolabe profile`), production-ready application contract templates (Merkle membership, private vote, nullifier claim), and automated continuous verification CI actions.

### Added
- **Noir Groth16 Adapter:** Rust (`astrolabe-core::noir`) and TypeScript (`@astrolabe/ts/noir`) adapters for parsing snarkjs-compatible Noir Groth16 proofs, keys, and unified artifact bundles, recording toolchain/backend provenance metadata per ACF Spec Section 10.2.
- **RISC Zero Groth16 Adapter:** Rust (`astrolabe-core::risc0`) and TypeScript (`@astrolabe/ts/risc0`) adapters for converting 256-byte Groth16 seals, image IDs, and journal digests into canonical ACF objects, with both 4-limb (`Limb16`, matching Bonsai recursion circuit) and 2-limb (`Direct`) mapping modes.
- **Pure `#![no_std]` SHA-256:** Zero-dependency, portable NIST SHA-256 implementations in Rust and TypeScript for hashing raw guest journals.
- **Soroban Cost Profiler (`astrolabe profile`):** CLI tool for simulating Groth16 proof verification inside Soroban `Env`, profiling exact CPU instruction budgets, RAM consumption, and WASM binary sizes against Stellar Protocol 25 network limits.
- **Soroban ZK Application Contract Templates:**
  - `MerkleMembershipContract`: private leaf inclusion verification against authorized Merkle roots in contract instance storage.
  - `PrivateVoteContract`: anonymous voting with Groth16 eligibility proofs, persistent nullifier registry for replay protection, and option tallying.
  - `NullifierClaimContract`: private airdrop and reward redemption with nullifier double-claim prevention.
  - Generator support via `astrolabe gen-verifier --template <merkle-membership|private-vote|nullifier-claim>`.
- **Continuous Artifact Verification GitHub Action:** Composite action `.github/actions/verify-artifacts/action.yml` for automated export, simulation, and cost profiling in CI workflows.

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
