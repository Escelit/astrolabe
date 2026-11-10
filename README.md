# Astrolabe

**The navigation toolkit and canonical format for verifying zero-knowledge proofs on Stellar Soroban.**

> **Status: `v1.0.0` (`acf/1.0`) — Production-ready, fully hardened, and verified on Stellar Testnet (Protocol 29).**  
> Core libraries, `snarkjs` adapters, Soroban verifier contracts, and CLI are complete, audited ([`docs/security-review.md`](docs/security-review.md)), and tested against 101 conformance vectors, continuous fuzzing suites, and live Stellar Testnet transactions.

Astrolabe is an open-source, toolchain-neutral pipeline for moving Groth16 zero-knowledge proofs over **BN254** from proving toolchains (**Circom / `snarkjs`**, and `snarkjs`-compatible **Noir** Groth16 backends) into **Soroban smart contracts** using the Stellar Protocol 25+ BN254 host functions (CAP-0074).

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

### 3. Export `snarkjs` artifacts to Astrolabe Canonical Format (`acf/0.1`)

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

### 4. Generate, build, and test a Soroban verifier contract

```bash
# Generate a Soroban contract with the verification key baked into WASM:
cargo run -p astrolabe-cli -- gen-verifier \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --mode baked \
  --name MultiplierVerifier \
  --out examples/circom-multiplier/contract/src/lib.rs \
  --force

# Run contract tests and build optimized WASM (~6.6 KB):
cargo test -p multiplier-verifier
stellar contract build --manifest-path examples/circom-multiplier/contract/Cargo.toml
```

### 5. Verify on Stellar Testnet

Verify against our deployed reference contract (`CBWJBCNFY2ZKBSQIS3BFJ4LGRQO2QTKQ7VOWEUNETTOGKUP4OXZ54TF4`, verified in Testnet TX [`3d5683f2...`](spec/vectors/onchain/testnet-circom-multiplier.json)), or deploy your own:

```bash
cargo run -p astrolabe-cli -- verify \
  --contract-id CBWJBCNFY2ZKBSQIS3BFJ4LGRQO2QTKQ7VOWEUNETTOGKUP4OXZ54TF4 \
  --network testnet \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json
```

For the full walkthrough—including compiling a Circom circuit from scratch and deploying to Stellar Testnet—see the [**Quickstart Guide**](docs/quickstart.md) and [`examples/circom-multiplier/README.md`](examples/circom-multiplier/README.md).

---

## Why Astrolabe?

Stellar Protocol 25 added native BN254 host functions (`bn254_g1_add`, `bn254_g1_mul`, `bn254_g1_msm`, `bn254_multi_pairing_check`), making on-chain Groth16 verification fast and inexpensive. However, bridging off-chain provers to Soroban manually is error-prone and security-critical:

1. **$G_2$ $\mathbb{F}_{p^2}$ coordinate order:** `snarkjs` outputs `[c0, c1]` (`real, imaginary`), whereas CAP-0074 requires `be32(c1) || be32(c0)` (`imaginary, real`).
2. **Silent scalar reduction ($\ge r$):** Both `soroban-sdk`'s `Bn254Fr` and the Soroban host silently reduce scalars $\ge r$ modulo $r$. An unguarded contract accepts aliased public inputs ($s + r$), breaking nullifier uniqueness.
3. **Degenerate infinity points:** The Soroban host accepts all-zero infinity points (`[0u8; 64]` and `[0u8; 128]`) in `multi_pairing_check` without trapping. Verifiers must explicitly reject infinity proof points $A, B, C$.
4. **Public signal ordering:** Circom emits public outputs before public inputs in `public.json`.

Astrolabe solves these once in a single, strictly validated format and toolchain:

- **Astrolabe Canonical Format (`acf/0.1`):** Unambiguous big-endian byte layouts for `Fp`, `Fr`, `G1`, `G2`, `Proof` (256B), `VerificationKey` (`452 + 64 * n_ic` B), `PublicInputs` (`32 * n` B), and self-describing `ASTR` envelopes, backed by 101 conformance vectors.
- **`astrolabe-core` (Rust `#![no_std]`):** Zero-dependency, panic-free encoders, decoders, `G2` twist-curve and prime-order-$r$ subgroup validators, and `snarkjs` adapters.
- **`astrolabe-verifier` (Soroban Contract Crate):** On-chain Groth16 verifier helpers (`verify_groth16_slice`, `verify_groth16_bytes`) and admin-managed `StoredVkVerifierContract` that enforce all Spec Section 8 & 9 security rules.
- **`astrolabe-ts` (TypeScript SDK):** Zero-dependency browser and Node.js SDK using pure `bigint` arithmetic, tested byte-for-byte against Rust and `snarkjs`.
- **`astrolabe-cli` (`astrolabe`):** `export`, `gen-verifier`, `verify`, and `doctor` commands.

---

## Documentation

| Document | Description |
| -------- | ----------- |
| [**Quickstart Guide**](docs/quickstart.md) | Install prerequisites, verify locally and on Testnet, and use the Rust & TypeScript SDKs. |
| [**Core Concepts & Security**](docs/concepts.md) | BN254 host functions, Groth16 pairing equation, `Fp2` ordering, scalar aliasing defense, and baked vs. stored VKs. |
| [**CLI Reference**](docs/cli-reference.md) | All flags, input auto-detection rules, and output formats for `export`, `gen-verifier`, `verify`, and `doctor`. |
| [**Format Reference (`acf/0.1`)**](docs/format-reference.md) | Byte-offset diagrams and tables for every ACF primitive, Groth16 object, envelope, and Soroban type. |
| [**Troubleshooting Guide**](docs/troubleshooting.md) | Diagnosis and fixes for `ERR_*` codes, Soroban `Error(Crypto, InvalidInput)` traps, and common encoding mistakes. |
| [**Circom Multiplier Example**](examples/circom-multiplier/README.md) | Self-contained Circom 2.0 project, public `snarkjs` artifacts, generated Soroban contract, and Testnet evidence. |
| [**Phase 1 Ground-Truth Findings**](docs/phase1-findings.md) | SDK/host source inspection and Stellar Testnet experiments resolving every spec assumption. |
| [**Security Audit & Review**](docs/security-review.md) | Comprehensive security review of all cryptographic hotspots, fuzzing results, and hardened invariants. |
| [**Project Roadmap**](docs/roadmap.md) | Completed milestones (Phases 0–7) and planned expansions (Noir, RISC Zero, cost profiler). |

---

## Compatibility Table

| Component | Supported / Tested Version | Notes |
| --------- | -------------------------- | ----- |
| **Stellar Protocol** | **Protocol 25+** (tested on **Protocol 29**) | CAP-0074 BN254 host functions |
| **`soroban-sdk`** | `=29.0.1` | `soroban_sdk::crypto::bn254` (`Bn254Fp`, `Bn254Fr`, `Bn254G1Affine`, `Bn254G2Affine`) |
| **`soroban-env-host`** | `=29.0.1` | Local host simulation and contract test runner |
| **`stellar-cli`** | `28.0.0+` | Contract WASM builds, deployment, and invocation |
| **Rust (`rustc` / `cargo`)** | `1.85+` (pinned `1.97.1`) | Requires `wasm32v1-none` target |
| **Circom** | `2.2.3` (`2.0.0+` compatible) | BN254 (`--prime bn128`) |
| **`snarkjs`** | `0.7.6` | Groth16 over `"curve": "bn128"` |
| **Node.js / `pnpm`** | Node `24.x` (`18+`), `pnpm` `10.x` (`9+`) | TypeScript SDK and differential cross-check suite |

---

## Repository Layout

```text
.
├── spec/
│   ├── fixtures/snarkjs/       # Multi-circuit snarkjs fixtures (multiplier2, square, linear3)
│   └── vectors/                # 101 cross-language conformance test vectors (JSON)
├── crates/
│   ├── astrolabe-core/         # Rust #![no_std] encoders, validators, and snarkjs adapter
│   ├── astrolabe-verifier/     # Soroban Groth16 verifier helpers and stored-VK contract
│   └── astrolabe-cli/          # `astrolabe` CLI (export, gen-verifier, verify, doctor)
├── packages/
│   └── astrolabe-ts/           # TypeScript SDK (browser + Node.js, zero dependencies)
├── examples/
│   └── circom-multiplier/      # End-to-end Circom -> Soroban -> Testnet example
├── docs/                       # User guides, CLI/format references, troubleshooting, roadmap
└── scripts/                    # Differential cross-checks and ground-truth probes
```

---

## Development & Verification Commands

```bash
# Format and lint (Rust + TypeScript)
make fmt-check
make lint

# Run all unit and integration tests across Rust and TypeScript
make test

# Verify #![no_std] WASM compilation for astrolabe-core
make build-wasm

# Run the 101 conformance test vectors in both Rust and TypeScript
make vectors-check

# Run 3-way differential tests (Rust == TypeScript == snarkjs == ark-groth16)
make differential
```

---

## Security Considerations

- **Malleability and replay protection:** Groth16 proofs can be re-randomized. Applications **must** bind context (recipient address, nullifier/nonce, contract ID, chain/network ID) into the circuit's public inputs.
- **Trusted setup provenance:** Groth16 security depends on the Phase 1 (Powers-of-Tau) and Phase 2 (`.zkey`) ceremonies. Never use a single-party development ceremony in production.
- **BN254 security margin:** The BN254 curve is estimated to provide ~100 bits of classical security (below 128 bits). Document this assumption when designing high-value protocols.
- **Public data only:** Astrolabe libraries process public proofs, verification keys, and public inputs. They never handle private witnesses, secret keys, or ceremony toxic waste.

If you discover a security vulnerability, please do not open a public issue. Follow our disclosure process in `SECURITY.md` (or contact the maintainers privately).

---

## Related Work

Astrolabe complements existing Stellar zero-knowledge projects:

- [Soroban-ZK-Std](https://github.com/georgegoldman/Soroban-ZK-Std): on-chain field arithmetic and cryptographic primitives
- The Groth16 verifier example in `stellar/soroban-examples`
- Community walkthroughs and scripts for Circom and Noir on Stellar
- Nethermind's RISC Zero Groth16 verifier for Soroban

---

## Contributing

Contributions are welcome! Please read `AGENTS.md` for our engineering and testing standards (vector-first development, zero `unwrap`/`panic!` in library code, and differential verification).

## License

Code is dual-licensed under **MIT OR Apache-2.0** (see [`LICENSE`](LICENSE)). Specification text is licensed under **CC-BY-4.0**.
