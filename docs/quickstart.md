# Quickstart Guide

This guide takes you from a fresh clone of Astrolabe to a verified Groth16 proof in a Soroban smart contract—both locally in the Soroban host simulator and on **Stellar Testnet**—in under 15 minutes.

---

## 1. Prerequisites

Ensure you have the following installed:

- **Rust** (`1.85+`) with the `wasm32v1-none` compilation target:
  ```bash
  rustup target add wasm32v1-none
  ```
- **Stellar CLI** (`28.0.0+`):
  ```bash
  cargo install --locked stellar-cli
  ```
- **Node.js** (`18+`) and **pnpm** (`9+`) *(optional, for the TypeScript SDK)*
- **Circom** (`2.2+`) and **snarkjs** (`0.7+`) *(optional, only needed if compiling new circuits)*

Clone the repository and run `astrolabe doctor` to verify your setup:

```bash
git clone https://github.com/Escelit/astrolabe.git
cd astrolabe
cargo run -p astrolabe-cli -- doctor
```

Expected output:

```text
=== Astrolabe Environment Diagnostics (doctor) ===

[✓] rustc: rustc 1.97.1 ...
[✓] wasm32v1-none target: Target 'wasm32v1-none' is installed
[✓] cargo: cargo 1.97.1 ...
[✓] stellar: stellar 28.0.0 ...
[✓] circom: circom compiler 2.2.3
[✓] snarkjs: snarkjs@0.7.6
[✓] node: v24.13.0
[✓] pnpm: 10.28.2
[✓] Stellar RPC Health: https://soroban-testnet.stellar.org is healthy

All core requirements for Soroban BN254 verification are SATISFIED.
```

---

## 2. Verify a `snarkjs` Proof Locally in 60 Seconds

Astrolabe includes public `snarkjs` artifacts for the `Multiplier2` circuit (`c <== a * b`, proving `3 * 11 = 33` with public output `33` and public input `3`) in [`examples/circom-multiplier/artifacts/`](../examples/circom-multiplier/artifacts/).

Run `astrolabe verify` to convert the `snarkjs` JSON files into the Astrolabe Canonical Format (`acf/0.1`), validate all field ranges, curve equations, and `G2` subgroup membership, and execute the Groth16 pairing check inside a local Soroban host simulation:

```bash
cargo run -p astrolabe-cli -- verify \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --public examples/circom-multiplier/artifacts/public.json
```

Output:

```text
=== Astrolabe Local Verifier (Soroban Host Simulation) ===
✓ Proof verification SUCCEEDED!
  Public inputs count: 2
  Pairing check: VALID (product in GT is identity)
```

---

## 3. Export Artifacts to ACF Bytes or Soroban CLI Arguments

Use `astrolabe export` to convert `snarkjs` JSON files into raw ACF hex (`acf-hex`), binary envelopes (`envelope`), canonical JSON (`canonical-json`), or ready-to-paste `stellar contract invoke` flags (`soroban-args`):

```bash
# Print ready-to-use arguments for `stellar contract invoke`:
cargo run -p astrolabe-cli -- export \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json \
  --format soroban-args
```

To write `.hex` files (`proof.hex`, `vk.hex`, `public.hex`) to a directory:

```bash
cargo run -p astrolabe-cli -- export \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --public examples/circom-multiplier/artifacts/public.json \
  --format acf-hex \
  --out-dir /tmp/acf-out
```

---

## 4. Generate and Build a Soroban Verifier Contract

Generate a standalone Soroban verifier contract with your verification key baked into contract bytecode (`--mode baked`):

```bash
cargo run -p astrolabe-cli -- gen-verifier \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --mode baked \
  --name MultiplierVerifier \
  --out examples/circom-multiplier/contract/src/lib.rs \
  --force
```

Run the contract's unit and negative-control test suite, then compile to optimized `wasm32v1-none` bytecode:

```bash
cargo test -p multiplier-verifier
stellar contract build --manifest-path examples/circom-multiplier/contract/Cargo.toml
```

This produces a ~6.6 KB optimized WASM binary at `target/wasm32v1-none/release/multiplier_verifier.wasm`.

---

## 5. Deploy and Verify on Stellar Testnet

1. **Create and fund a Testnet account:**
   ```bash
   stellar keys generate --global alice --network testnet --fund
   ```

2. **Deploy the verifier WASM:**
   ```bash
   CONTRACT_ID=$(stellar contract deploy \
     --wasm target/wasm32v1-none/release/multiplier_verifier.wasm \
     --source alice \
     --network testnet)
   echo "Contract ID: $CONTRACT_ID"
   ```

3. **Verify the proof against the deployed contract:**
   ```bash
   cargo run -p astrolabe-cli -- verify \
     --contract-id "$CONTRACT_ID" \
     --network testnet \
     --source alice \
     --proof examples/circom-multiplier/artifacts/proof.json \
     --public examples/circom-multiplier/artifacts/public.json
   ```
   *(Omit `--source alice` if you want a free read-only RPC simulation without submitting a transaction.)*

---

## 6. Using the SDKs in Code

### Rust (`astrolabe-core` & `astrolabe-verifier`)

Convert `snarkjs` JSON off-chain with `astrolabe-core` (`#![no_std]`):

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

Verify inside a Soroban smart contract with `astrolabe-verifier`:

```rust
use astrolabe_verifier::{verify_groth16_slice, VerifierError};
use soroban_sdk::{BytesN, Env, Vec};

pub fn verify_my_proof(
    env: Env,
    proof: BytesN<256>,
    public_inputs: Vec<BytesN<32>>,
) -> Result<bool, VerifierError> {
    verify_groth16_slice(&env, &VK_BYTES, &proof, &public_inputs)
}
```

### TypeScript (`astrolabe-ts`)

Convert and validate `snarkjs` artifacts in Node.js or the browser (zero runtime dependencies, pure `bigint` math):

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

const proofHex = bytesToHex(encodeProof(proof));       // 512 hex chars (256 bytes)
const vkHex = bytesToHex(encodeVk(vk));                // 452 + 64 * n_ic bytes
const pubHex = bytesToHex(encodePublicInputs(publicInputs)); // 32 * n_public bytes
```

---

## Next Steps

- Walk through the full [**Circom Multiplier Example**](../examples/circom-multiplier/README.md).
- Read [**Core Concepts & Security**](concepts.md) to understand how Soroban BN254 verification works under the hood.
- Keep the [**Troubleshooting Guide**](troubleshooting.md) handy when debugging failed proofs or host traps.
