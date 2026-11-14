# Astrolabe

**The canonical format, verification toolkit, and smart contract library for zero-knowledge proofs on Stellar Soroban.**

Astrolabe is an open-source, toolchain-neutral pipeline for moving Groth16 zero-knowledge proofs over **BN254** from proving toolchains (**Circom / `snarkjs`**, **Noir**, and **RISC Zero**) into **Soroban smart contracts** on Stellar using the Protocol 25+ BN254 host functions ([CAP-0074](https://github.com/stellar/stellar-protocol/blob/master/core/cap-0074.md)).

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Why Astrolabe?](#why-astrolabe)
- [Quickstart (Verify a Proof in 2 Minutes)](#quickstart-verify-a-proof-in-2-minutes)
- [SDK Usage (Rust & TypeScript)](#sdk-usage-rust--typescript)
- [ACF Byte Layout at a Glance (`acf/1.0`)](#acf-byte-layout-at-a-glance-acf10)
- [Documentation](#documentation)
- [Compatibility Table](#compatibility-table)
- [Repository Layout](#repository-layout)
- [Development & Verification Commands](#development--verification-commands)
- [Security Considerations](#security-considerations)
- [Related Work](#related-work)
- [Contributing & License](#contributing--license)

---

## Architecture Overview

```text
  Off-Chain Proving Toolchains            Astrolabe Canonical Format (acf/1.0)             Stellar Soroban (Protocol 25+)
┌──────────────────────────────┐        ┌──────────────────────────────────────┐        ┌──────────────────────────────────┐
│ • Circom / snarkjs           │        │  astrolabe-core (Rust #![no_std])    │        │  astrolabe-verifier              │
│   (proof.json, vk.json, ...) │        │  astrolabe-ts   (TypeScript bigint)  │        │  • verify_groth16_slice / _bytes │
│                              │        │  astrolabe-cli  (CLI & Profiler)     │        │  • StoredVkVerifierContract      │
│ • Noir (Groth16 BN254)       │───────▶│                                      │───────▶│  • MerkleMembershipContract      │
│   (bundle / snarkjs JSON)    │        │  • Fp2 swap: [c0,c1] -> c1 || c0     │        │  • PrivateVoteContract           │
│                              │        │  • Canonical range (< p, < r)        │        │  • NullifierClaimContract        │
│ • RISC Zero (Groth16 Seal)   │        │  • G1 & G2 curve + subgroup [r]P = O │        │                                  │
│   (seal, image_id, journal)  │        │  • Proof (256B), VK, PublicInputs    │        │  CAP-0074 BN254 Host Functions   │
└──────────────────────────────┘        └──────────────────────────────────────┘        └──────────────────────────────────┘
```

---

## Why Astrolabe?

Stellar Protocol 25 introduced native BN254 host functions (`bn254_g1_add`, `bn254_g1_mul`, `bn254_g1_msm`, `bn254_multi_pairing_check`), making on-chain Groth16 verification fast and inexpensive. However, wiring off-chain provers directly into Soroban contracts by hand exposes subtle, high-severity cryptographic pitfalls:

| Pitfall | Ground-Truth Behavior on Soroban | How Astrolabe Protects You |
| ------- | -------------------------------- | -------------------------- |
| **1. $G_2$ $\mathbb{F}_{p^2}$ coordinate order** | `snarkjs` emits `[c0, c1]` (`real, imaginary`), whereas CAP-0074 / EIP-197 requires `be32(c1) \|\| be32(c0)` (`imaginary, real`). | Converts and validates `Fp2` ordering via a single audited constant (`FP2_COMPONENT_ORDER`). |
| **2. Silent scalar reduction ($\ge r$)** | Both `soroban-sdk`'s `Bn254Fr` and the host's `bn254_g1_mul` silently reduce scalars $\ge r$ modulo $r$. An unguarded verifier accepts aliased inputs ($s + r$), breaking nullifier uniqueness. | Rejects any public input $\ge r$ with `ERR_NON_CANONICAL_FIELD` **before** converting to `Bn254Fr`. |
| **3. Degenerate infinity points** | `bn254_multi_pairing_check` accepts all-zero infinity points (`[0u8; 64]` in $G_1$, `[0u8; 128]` in $G_2$) without trapping, allowing trivial forged proofs if unchecked. | Explicitly rejects infinity proof elements $A$, $B$, or $C$ (`ERR_INVALID_PROOF`) both off-chain and on-chain. |
| **4. Unchecked $G_2$ twist & subgroup** | Off-chain tooling that skips $G_2$ twist-curve or prime-order-$r$ subgroup checks fails late with opaque host traps (`Error(Crypto, InvalidInput)`). | Performs complete Jacobian twist-curve validation (`ERR_NOT_ON_CURVE`) and $[r]P = \mathcal{O}$ subgroup checks (`ERR_NOT_IN_SUBGROUP`) off-chain. |

### Key Components

- **Astrolabe Canonical Format ([`spec/spec.md`](spec/spec.md), `acf/1.0`):** Unambiguous big-endian byte layouts for `Fp` (32B), `Fr` (32B), `G1` (64B), `G2` (128B), `Proof` (256B), `VerificationKey` (`452 + 64 * n_ic` B), `PublicInputs` (`32 * n` B), and 12-byte `ASTR` envelopes.
- **`astrolabe-core` (Rust `#![no_std]`):** Zero-dependency, `#![forbid(unsafe_code)]`, panic-free codecs, validators, and adapters for **`snarkjs` / Circom**, **Noir**, and **RISC Zero**.
- **`astrolabe-verifier` (Soroban Contract Crate):** On-chain Groth16 verifier helpers (`verify_groth16_slice`, `verify_groth16_bytes`), admin-managed `StoredVkVerifierContract`, and ready-to-deploy ZK application templates (`MerkleMembershipContract`, `PrivateVoteContract`, `NullifierClaimContract`).
- **`astrolabe-ts` (TypeScript SDK):** Browser- and Node.js-compatible zero-dependency SDK using pure `bigint` arithmetic, tested byte-for-byte against Rust and `snarkjs`.
- **`astrolabe-cli` (`astrolabe`):** Unified command-line interface providing `export`, `gen-verifier`, `verify`, `profile`, and `doctor`.

---

## Quickstart (Verify a Proof in 2 Minutes)

### 1. Check your environment

```bash
git clone https://github.com/Escelit/astrolabe.git
cd astrolabe
cargo run -p astrolabe-cli -- doctor
```

### 2. Verify a `snarkjs` Groth16 proof locally (Soroban host simulation)

Using the included `Multiplier2` (`c <== a * b`) artifacts in [`examples/circom-multiplier/`](examples/circom-multiplier/README.md):

```bash
cargo run -p astrolabe-cli -- verify \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --public examples/circom-multiplier/artifacts/public.json
```

```text
=== Astrolabe Local Verifier (Soroban Host Simulation) ===
✓ Proof verification SUCCEEDED!
  Public inputs count: 2
  Pairing check: VALID (product in GT is identity)
```

### 3. Profile Soroban CPU & memory budget (`astrolabe profile`)

Measure exact Soroban host CPU instructions, RAM bytes, and WASM size headroom against Stellar Protocol 25+ network limits:

```bash
cargo run -p astrolabe-cli -- profile \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json
```

### 4. Export `snarkjs` artifacts to Astrolabe Canonical Format (`acf/1.0`)

```bash
# Export raw ACF hex files (proof.hex, vk.hex, public.hex):
cargo run -p astrolabe-cli -- export \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --public examples/circom-multiplier/artifacts/public.json \
  --format acf-hex \
  --out-dir examples/circom-multiplier/artifacts

# Or print ready-to-invoke flags for `stellar contract invoke`:
cargo run -p astrolabe-cli -- export \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json \
  --format soroban-args
```

### 5. Generate, build, and test a Soroban verifier contract

```bash
# Generate a Soroban contract with the verification key baked into WASM:
cargo run -p astrolabe-cli -- gen-verifier \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --mode baked \
  --name MultiplierVerifier \
  --out examples/circom-multiplier/contract/src/lib.rs \
  --force

# (Optional) Or generate a complete ZK application contract template:
#   --template <standard | merkle-membership | private-vote | nullifier-claim>

# Run contract tests and build optimized WASM (~6.6 KB):
cargo test -p multiplier-verifier
stellar contract build --manifest-path examples/circom-multiplier/contract/Cargo.toml
```

### 6. Verify on Stellar Testnet

Verify against our deployed reference contract (`CBWJBCNFY2ZKBSQIS3BFJ4LGRQO2QTKQ7VOWEUNETTOGKUP4OXZ54TF4`, recorded in Testnet TX [`3d5683f2...`](spec/vectors/onchain/testnet-circom-multiplier.json)), or deploy your own:

```bash
cargo run -p astrolabe-cli -- verify \
  --contract-id CBWJBCNFY2ZKBSQIS3BFJ4LGRQO2QTKQ7VOWEUNETTOGKUP4OXZ54TF4 \
  --network testnet \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json
```

For the full end-to-end walkthrough—including compiling a Circom circuit from scratch and deploying to Stellar Testnet—see the [**Quickstart Guide**](docs/quickstart.md) and [`examples/circom-multiplier/README.md`](examples/circom-multiplier/README.md).

---

## SDK Usage (Rust & TypeScript)

### Rust Off-Chain (`astrolabe-core`, `#![no_std]`)

```rust
use astrolabe_core::{
    encode_proof, encode_public_inputs, encode_vk,
    snarkjs::{parse_snarkjs_proof, parse_snarkjs_public_inputs, parse_snarkjs_vk},
};

let proof = parse_snarkjs_proof(proof_json)?;
let vk = parse_snarkjs_vk(vk_json)?;
let public_inputs = parse_snarkjs_public_inputs(public_json)?;

// Validate public input count against VK (n_public + 1 == n_ic)
vk.validate_public_inputs(&public_inputs)?;

let proof_bytes: [u8; 256] = encode_proof(&proof);
let vk_bytes: Vec<u8> = encode_vk(&vk);
let public_bytes: Vec<u8> = encode_public_inputs(&public_inputs);
```

> **Noir & RISC Zero:** `astrolabe_core::noir` (`parse_noir_bundle`, `parse_noir_proof`, `parse_noir_vk`) and `astrolabe_core::risc0` (`parse_risc0_receipt_json`, `map_risc0_seal`, `map_risc0_journal_and_image_id`) provide the same strict validation for Noir and RISC Zero Groth16 artifacts.

### Rust On-Chain (`astrolabe-verifier`, Soroban Smart Contract)

```rust
#![no_std]
use astrolabe_verifier::{verify_groth16_slice, VerifierError};
use soroban_sdk::{contract, contractimpl, BytesN, Env, Vec};

const VK_BYTES: [u8; 644] = [/* ACF verification key bytes */];

#[contract]
pub struct MyZkContract;

#[contractimpl]
impl MyZkContract {
    pub fn verify(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, VerifierError> {
        verify_groth16_slice(&env, &VK_BYTES, &proof, &public_inputs)
    }
}
```

### TypeScript (`astrolabe-ts`, Browser & Node.js)

```typescript
import {
  parseSnarkjsProof,
  parseSnarkjsVk,
  parseSnarkjsPublicInputs,
  encodeProof,
  encodeVk,
  encodePublicInputs,
  validatePublicInputsWithVk,
  bytesToHex,
} from "astrolabe-ts";

const proof = parseSnarkjsProof(proofJsonString);
const vk = parseSnarkjsVk(vkJsonString);
const publicInputs = parseSnarkjsPublicInputs(publicJsonString);

validatePublicInputsWithVk(publicInputs, vk);

const proofHex = bytesToHex(encodeProof(proof));             // 256 bytes (512 hex chars)
const vkHex = bytesToHex(encodeVk(vk));                      // 452 + 64 * n_ic bytes
const pubHex = bytesToHex(encodePublicInputs(publicInputs)); // 32 * n_public bytes
```

---

## ACF Byte Layout at a Glance (`acf/1.0`)

All numbers are big-endian unsigned integers (`be32`). See [`spec/spec.md`](spec/spec.md) and [`docs/format-reference.md`](docs/format-reference.md) for complete offset tables.

| Object | Byte Size | Wire Layout | Soroban Type |
| ------ | --------- | ----------- | ------------ |
| `Fp` | `32` | `be32(x)` where `x < p` | `BytesN<32>` / `Bn254Fp` |
| `Fr` | `32` | `be32(x)` where `x < r` | `BytesN<32>` (checked `< r` before `Bn254Fr`) |
| `G1` | `64` | `be32(x) \|\| be32(y)` (`[0u8; 64]` = $\mathcal{O}$) | `BytesN<64>` / `Bn254G1Affine` |
| `G2` | `128` | `be32(x.c1) \|\| be32(x.c0) \|\| be32(y.c1) \|\| be32(y.c0)` (`[0u8; 128]` = $\mathcal{O}$) | `BytesN<128>` / `Bn254G2Affine` |
| `Proof` | `256` | `A (64B) \|\| B (128B) \|\| C (64B)` (un-negated `A`, non-infinity) | `BytesN<256>` / `Groth16Proof` |
| `VerificationKey` | `452 + 64 * n_ic` | `alpha_g1 (64B) \|\| beta_g2 (128B) \|\| gamma_g2 (128B) \|\| delta_g2 (128B) \|\| be32_u32(n_ic) (4B) \|\| IC[0..n_ic]` | `Bytes` / `Groth16Vk` |
| `PublicInputs` | `32 * n` | `be32(s_0) \|\| ... \|\| be32(s_{n-1})` where `n == n_ic - 1` | `Vec<BytesN<32>>` |
| `Envelope` | `12 + payload_len` | `"ASTR" (4B) \|\| ver (1B) \|\| kind (1B) \|\| curve (1B) \|\| sys (1B) \|\| len (4B) \|\| payload` | Off-chain container |

### Canonical Error Codes (Spec Section 11)

Every implementation (`astrolabe-core`, `astrolabe-verifier`, `astrolabe-ts`) maps validation failures 1:1 to these stable codes:

| Error Code | Contract Code | Condition |
| ---------- | ------------- | --------- |
| `ERR_BAD_LENGTH` | `1` | Byte length does not match expected size |
| `ERR_NON_CANONICAL_FIELD` | `2` | Field element $\ge p$ or scalar input $\ge r$ |
| `ERR_NOT_ON_CURVE` | `3` | Non-infinity $G_1$ or $G_2$ point fails curve equation |
| `ERR_NOT_IN_SUBGROUP` | `4` | Non-infinity $G_2$ point is outside the prime-order-$r$ subgroup |
| `ERR_PUBLIC_INPUT_COUNT` | `5` | `n_public + 1 != n_ic` or `n_ic == 0` |
| `ERR_INVALID_PROOF` | `6` | Infinity proof point ($A, B, C$) or failed pairing check |
| `ERR_UNSUPPORTED` | `7` | Unknown envelope header, curve, proof system, or protocol |
| `ERR_TRAILING_BYTES` | `8` | Extra bytes after declared envelope payload length |
| `ERR_MALFORMED_INPUT` | `9` | Unparseable JSON, invalid hex/decimal string, or excessive nesting |

---

## Documentation

| Document | Description |
| -------- | ----------- |
| [**Specification (`spec/spec.md`)**](spec/spec.md) | Normative Astrolabe Canonical Format (`acf/1.0`) specification. |
| [**Quickstart Guide**](docs/quickstart.md) | Install prerequisites, verify locally and on Testnet, and use the Rust & TypeScript SDKs. |
| [**Core Concepts & Security**](docs/concepts.md) | BN254 host functions, Groth16 pairing equation, `Fp2` ordering, scalar aliasing defense, and baked vs. stored VKs. |
| [**CLI Reference**](docs/cli-reference.md) | All flags, input auto-detection rules, and output formats for `export`, `gen-verifier`, `verify`, `profile`, and `doctor`. |
| [**Format Reference (`acf/1.0`)**](docs/format-reference.md) | Byte-offset diagrams and tables for every ACF primitive, Groth16 object, envelope, and Soroban type. |
| [**Troubleshooting Guide**](docs/troubleshooting.md) | Diagnosis and fixes for `ERR_*` codes, Soroban `Error(Crypto, InvalidInput)` traps, and common encoding mistakes. |
| [**Circom Multiplier Example**](examples/circom-multiplier/README.md) | Self-contained Circom 2.0 project, public `snarkjs` artifacts, generated Soroban contract, and Testnet evidence. |
| [**BN254 Host Behavior Reference**](docs/phase1-findings.md) | Empirical verification of Soroban BN254 host functions, SDK types, and Stellar Testnet transactions. |
| [**Security Review**](docs/security-review.md) | Review of cryptographic invariants, edge cases, and fuzzing coverage. |
| [**Project Roadmap**](docs/roadmap.md) | Project milestones and planned expansions. |
| [**Changelog**](CHANGELOG.md) | Release history ([`CHANGELOG.md`](CHANGELOG.md)) and release procedures ([`docs/release.md`](docs/release.md)). |

---

## Compatibility Table

| Component | Supported / Tested Version | Notes |
| --------- | -------------------------- | ----- |
| **Stellar Protocol** | **Protocol 25+** (tested on **Protocol 29**) | CAP-0074 BN254 host functions |
| **`soroban-sdk`** | `=29.0.1` | `soroban_sdk::crypto::bn254` (`Bn254Fp`, `Bn254Fr`, `Bn254G1Affine`, `Bn254G2Affine`) |
| **`soroban-env-host`** | `=29.0.1` | Local host simulation, cost profiler, and contract test runner |
| **`stellar-cli`** | `28.0.0+` | Contract WASM builds, deployment, and invocation |
| **Rust (`rustc` / `cargo`)** | `1.85+` (pinned `1.97.1`) | Requires `wasm32v1-none` target (`rustup target add wasm32v1-none`) |
| **Circom** | `2.2.3` (`2.0.0+` compatible) | BN254 (`--prime bn128`) |
| **`snarkjs`** | `0.7.6` | Groth16 over `"curve": "bn128"` |
| **Noir / RISC Zero** | Groth16 BN254 backends | Supported via `astrolabe_core::{noir, risc0}` and `astrolabe-ts` |
| **Node.js / `pnpm`** | Node `24.x` (`18+`), `pnpm` `10.x` (`9+`) | TypeScript SDK and differential cross-check suite |

---

## Repository Layout

```text
.
├── AGENTS.md                   # Engineering, security, and testing rules
├── CHANGELOG.md                # Release history
├── spec/
│   ├── spec.md                 # Authoritative ACF 1.0 specification
│   ├── fixtures/snarkjs/       # Multi-circuit snarkjs fixtures (multiplier2, square, linear3)
│   └── vectors/                # Cross-language conformance test vectors (JSON)
├── crates/
│   ├── astrolabe-core/         # Rust #![no_std] codecs, validators, and snarkjs/Noir/RISC0 adapters
│   ├── astrolabe-verifier/     # Soroban Groth16 verifier helpers, stored-VK & app contract templates
│   └── astrolabe-cli/          # `astrolabe` CLI (export, gen-verifier, verify, profile, doctor)
├── packages/
│   └── astrolabe-ts/           # TypeScript SDK (browser + Node.js, zero dependencies)
├── examples/
│   └── circom-multiplier/      # End-to-end Circom -> Soroban -> Stellar Testnet example
├── fuzz/                       # Coverage-guided libFuzzer targets for decoders and parsers
├── docs/                       # User guides, CLI/format references, security review, roadmap
├── scripts/                    # Differential cross-checks and ground-truth probes
└── .github/
    ├── actions/verify-artifacts/ # Reusable GitHub Action for continuous proof verification
    └── workflows/              # CI pipelines
```

---

## Development & Verification Commands

```bash
# Format and lint (Rust + TypeScript)
make fmt-check
make lint

# Run all unit, integration, and contract tests across Rust and TypeScript
make test

# Verify #![no_std] WASM compilation for astrolabe-core
make build-wasm

# Run the conformance test vector suite in both Rust and TypeScript
make vectors-check

# Run 3-way differential tests (Rust == TypeScript == snarkjs == ark-groth16)
make differential

# Run deterministic property and regression fuzzing suites (Rust + TypeScript)
make fuzz
```

---

## Security Considerations

- **Malleability and replay protection:** Groth16 proofs are malleable and can be replayed unless constrained. Applications **must** bind context (recipient address, nullifier/nonce, contract ID, network ID) into the circuit's public inputs—or use the built-in `PrivateVoteContract` / `NullifierClaimContract` templates.
- **Trusted setup provenance:** Groth16 security depends on the Phase 1 (Powers-of-Tau) and Phase 2 (`.zkey`) ceremonies. Never use a single-party development ceremony in production.
- **BN254 security margin:** The BN254 curve provides ~100 bits of classical security (below 128 bits). Document this assumption when designing high-value protocols.
- **Public data only:** Astrolabe libraries process public proofs, verification keys, and public inputs. They never handle private witnesses, secret keys, or ceremony toxic waste.

See [`docs/security-review.md`](docs/security-review.md) for details on Astrolabe's cryptographic invariants and validation rules. If you discover a security vulnerability, please do not open a public issue; contact the maintainers privately.

---

## Related Work

Astrolabe complements existing Stellar zero-knowledge projects:

- [Soroban-ZK-Std](https://github.com/georgegoldman/Soroban-ZK-Std): on-chain field arithmetic and cryptographic primitives
- The Groth16 verifier example in [`stellar/soroban-examples`](https://github.com/stellar/soroban-examples)
- Community walkthroughs and scripts for Circom and Noir on Stellar
- Nethermind's RISC Zero Groth16 verifier for Soroban

---

## Contributing & License

Contributions are welcome! Please read [`AGENTS.md`](AGENTS.md) for our engineering and testing standards (vector-first development, zero `unwrap`/`panic!` in library code, and differential verification).

Code is dual-licensed under **MIT OR Apache-2.0** (see [`LICENSE`](LICENSE)). Specification text is licensed under **CC-BY-4.0**.
