# Project Roadmap

Astrolabe is developed in small, verifiable phases. Every phase is gated by conformance vectors, differential cross-checks, and on-chain or host-level verification.

---

## Completed Phases (v1.0 – v1.1)

| Phase | Milestone | Status | Key Deliverables |
| ----- | --------- | ------ | ---------------- |
| **Phase 0** | Workspace & Conformance Scaffold | **Complete** | Rust (`#![no_std]` `astrolabe-core`, `astrolabe-verifier`, `astrolabe-cli`) and TypeScript (`astrolabe-ts`) workspaces, `AcfError` 1:1 parity, JSON Schema for vectors, CI workflow. |
| **Phase 1** | Soroban BN254 Ground Truth | **Complete** | Empirical verification of all five `[VERIFY]` items against CAP-0074, `soroban-sdk 29.0.1`, `soroban-env-host 29.0.1`, and live Stellar Testnet Protocol 29 transactions ([`docs/phase1-findings.md`](phase1-findings.md)). |
| **Phase 2** | BN254 Primitives & Validators | **Complete** | Strict `Fp`, `Fr`, `Fp2` (`FP2_COMPONENT_ORDER`), `G1`, and `G2` codecs and validators (including complete Jacobian twist-curve arithmetic and `[r]P = O` subgroup checks) in Rust and TypeScript. |
| **Phase 3** | Groth16 Objects, Envelope & Canonical JSON | **Complete** | `Proof` (256B), `VerificationKey` (`452 + 64*n_ic` B), `PublicInputs` (`32*n` B), 12-byte `ASTR` binary envelope, and canonical JSON codecs with 101 conformance vectors passing in both languages. |
| **Phase 4** | `snarkjs` Adapter & Differential Oracle | **Complete** | Zero-dependency `snarkjs` converters in Rust (`no_std`) and TypeScript, fixtures across multiple Circom circuits (`multiplier2`, `square`, `linear3`), and 3-way differential testing (`Rust == TypeScript == snarkjs == ark-groth16`). |
| **Phase 5** | Soroban Verifier Contract & CLI | **Complete** | `astrolabe-verifier` crate (`verify_groth16_bytes`, `verify_groth16_slice`, `StoredVkVerifierContract`) and `astrolabe` CLI (`export`, `gen-verifier`, `verify`, `doctor`). |
| **Phase 6** | End-to-End Example & Documentation | **Complete** | [`examples/circom-multiplier`](../examples/circom-multiplier/README.md), user-facing documentation suite (`quickstart`, `concepts`, `cli-reference`, `format-reference`, `troubleshooting`), and compatibility matrix. |
| **Phase 7** | Hardening & v1.0.0 Release | **Complete** | Full security review of all hotspots ([`docs/security-review.md`](security-review.md)), continuous fuzzing suite (`cargo-fuzz` & property tests), parser recursion limits, spec promoted to `1.0`, and `v1.0.0` release. |
| **Phase 8** | Multi-Toolchain Adapters, Profiler & Templates (`v1.1.0`) | **Complete** | Noir Groth16 adapter (`astrolabe_core::noir` & `astrolabe-ts`), RISC Zero Groth16 adapter (`astrolabe_core::risc0` & `astrolabe-ts` with `#![no_std]` SHA-256), `astrolabe profile` cost profiler, ZK application contract templates (`MerkleMembershipContract`, `PrivateVoteContract`, `NullifierClaimContract`), and GitHub CI Action (`.github/actions/verify-artifacts`). |

---

## Future Explorations (Reserved in Spec)

1. **Additional Curves:** BLS12-381 (`CurveId` `0x02` reserved in `spec/spec.md` Section 5).
2. **Additional Proof Systems:** PLONK (`0x02`) and UltraHonk (`0x03`) verifiers as Soroban host support evolves.
3. **Multi-Scalar Multiplication (`bn254_g1_msm`) Threshold Tuning:** Automatic dispatch between iterative `g1_mul` + `g1_add` and `bn254_g1_msm` for circuits with high public-input counts.
