# CLI Reference (`astrolabe`)

The `astrolabe` command-line tool converts proving artifacts (`snarkjs` JSON, ACF binary envelopes, canonical JSON, or raw hex), generates Soroban Groth16 verifier contracts, verifies proofs locally or on-chain, and checks your development environment.

Run via Cargo from the workspace root:

```bash
cargo run -p astrolabe-cli -- <COMMAND> [OPTIONS]
```

Or install the `astrolabe` binary globally:

```bash
cargo install --path crates/astrolabe-cli
astrolabe --help
```

---

## Input Auto-Detection

All CLI commands that accept `--proof`, `--vk`, or `--public` automatically detect and validate the input file format:

1. **ACF Binary Envelope (`.astr`)**: Files starting with the 4-byte ASCII magic `ASTR` (`0x41 0x53 0x54 0x52`).
2. **Hex String (`.hex`)**: UTF-8 text containing even-length hexadecimal characters (`256` bytes for `Proof`, `452 + 64 * n_ic` bytes for `VerificationKey`, `32 * n` bytes for `PublicInputs`).
3. **Canonical JSON (`.json`)**: JSON objects containing `"acf": "0.1"`, `"kind"`, `"curve"`, `"system"`, and `"hex"`.
4. **`snarkjs` JSON (`proof.json`, `verification_key.json`, `public.json`)**: Standard `snarkjs` decimal-string JSON files (`"protocol": "groth16"`, `"curve": "bn128"`).
5. **Raw ACF Payload Bytes**: Raw binary files matching the exact byte size of the artifact.

Every loaded artifact is strictly validated against ACF Specification Section 9 before any output is produced.

---

## 1. `astrolabe export`

Converts proving artifacts into ACF hex, binary envelopes, canonical JSON, or Soroban CLI invocation arguments.

### Usage

```bash
astrolabe export [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| `--proof <PATH>` | `PathBuf` | — | Path to proof file (`proof.json`, `.astr`, `.hex`, or canonical JSON) |
| `--vk <PATH>` | `PathBuf` | — | Path to verification key file (`verification_key.json`, `.astr`, `.hex`, or canonical JSON) |
| `--public <PATH>` | `PathBuf` | — | Path to public inputs file (`public.json`, `.astr`, `.hex`, or canonical JSON) |
| `--format <FORMAT>` | `ExportFormat` | `acf-hex` | Output format: `acf-hex`, `envelope`, `canonical-json`, or `soroban-args` |
| `--out <FILE>` | `PathBuf` | stdout | Write output to a single file (when exporting one artifact) |
| `--out-dir <DIR>` | `PathBuf` | — | Write exported files (`proof.<ext>`, `vk.<ext>`, `public.<ext>`) into `<DIR>` |

*(At least one of `--proof`, `--vk`, or `--public` is required.)*

### Output Formats (`--format`)

| Format | Default Extension | Description |
| ------ | ----------------- | ----------- |
| `acf-hex` | `.hex` | Lowercase hexadecimal string of raw ACF payload bytes (no `0x` prefix), followed by LF (`\n`) |
| `envelope` | `.astr` | 12-byte `ASTR` header (`magic \|\| spec_ver \|\| kind \|\| curve \|\| system \|\| payload_len`) + raw payload |
| `canonical-json` | `.json` | Canonical JSON object per `spec/spec.md` Section 6 |
| `soroban-args` | stdout | Ready-to-run `--proof <HEX> --public-inputs '["<HEX>", ...]'` flags and `stellar contract invoke` command |

### Examples

```bash
# Export all three snarkjs artifacts as ACF hex files into ./artifacts:
astrolabe export \
  --proof proof.json \
  --vk verification_key.json \
  --public public.json \
  --format acf-hex \
  --out-dir ./artifacts

# Export a proof as a self-describing binary envelope (.astr):
astrolabe export --proof proof.json --format envelope --out proof.astr

# Print ready-to-copy arguments for `stellar contract invoke`:
astrolabe export --proof proof.json --public public.json --format soroban-args
```

---

## 2. `astrolabe gen-verifier`

Generates a Soroban Groth16 verifier smart contract (either a complete Cargo project directory or a single `.rs` source file) from a verification key.

### Usage

```bash
astrolabe gen-verifier --vk <PATH> --out <PATH> [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| `--vk <PATH>` | `PathBuf` | *(required)* | Path to verification key (`verification_key.json`, `.astr`, `.hex`, or canonical JSON) |
| `--out <PATH>`, `-o` | `PathBuf` | *(required)* | Output path: if it ends with `.rs`, writes a single Rust file; otherwise scaffolds a Cargo package directory (`Cargo.toml`, `src/lib.rs`, `README.md`) |
| `--mode <MODE>` | `VerifierMode` | `baked` | `baked` (embeds `VK_BYTES` constant in WASM) or `stored` (stores VK in Soroban instance storage with admin control) |
| `--name <NAME>` | `String` | `Groth16Verifier` | Rust struct name for the generated `#[contract]` |
| `--force`, `-f` | `bool` | `false` | Overwrite output file or non-empty directory if it already exists |

### Examples

```bash
# Generate a complete Soroban contract package with a baked-in verification key:
astrolabe gen-verifier \
  --vk verification_key.json \
  --mode baked \
  --name MultiplierVerifier \
  --out ./my-verifier

# Regenerate only src/lib.rs in an existing contract crate:
astrolabe gen-verifier \
  --vk verification_key.json \
  --mode baked \
  --name MultiplierVerifier \
  --out ./my-verifier/src/lib.rs \
  --force
```

---

## 3. `astrolabe verify`

Verifies a Groth16 proof either **locally** (using the Soroban `29.0.1` host simulator and BN254 host functions) or **on-chain** (against a deployed Soroban contract via `stellar contract invoke`).

### Usage

```bash
# Local verification (requires --vk):
astrolabe verify --proof <PATH> --public <PATH> --vk <PATH>

# On-chain verification (requires --contract-id):
astrolabe verify --proof <PATH> --public <PATH> --contract-id <CONTRACT_ID> [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| `--proof <PATH>` | `PathBuf` | *(required)* | Path to proof (`proof.json`, `.astr`, `.hex`, or canonical JSON) |
| `--public <PATH>` | `PathBuf` | *(required)* | Path to public inputs (`public.json`, `.astr`, `.hex`, or canonical JSON) |
| `--vk <PATH>` | `PathBuf` | — | Path to verification key for local host simulation |
| `--contract-id <ID>` | `String` | — | Deployed Soroban contract address (`C...`) for on-chain verification |
| `--network <NET>` | `String` | `testnet` | Stellar network name (`testnet`, `futurenet`, `standalone`, `mainnet`) |
| `--source <ACCOUNT>` | `String` | — | Stellar identity or secret key; if omitted during on-chain verification, runs in read-only simulation mode (`--send false`) |
| `--rpc-url <URL>` | `String` | — | Custom Stellar RPC endpoint URL |

### Examples

```bash
# 1. Local Soroban host simulation (fast, offline, zero fees):
astrolabe verify \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --vk examples/circom-multiplier/artifacts/verification_key.json \
  --public examples/circom-multiplier/artifacts/public.json

# 2. On-chain read-only simulation against Stellar Testnet contract:
astrolabe verify \
  --contract-id CBWJBCNFY2ZKBSQIS3BFJ4LGRQO2QTKQ7VOWEUNETTOGKUP4OXZ54TF4 \
  --network testnet \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json

# 3. Submit a live signed verification transaction on Stellar Testnet:
astrolabe verify \
  --contract-id "$CONTRACT_ID" \
  --network testnet \
  --source alice \
  --proof examples/circom-multiplier/artifacts/proof.json \
  --public examples/circom-multiplier/artifacts/public.json
```

---

## 4. `astrolabe doctor`

Inspects your local machine for required and optional tools (`rustc`, `wasm32v1-none` target, `cargo`, `stellar` CLI, `circom`, `snarkjs`, `node`, `pnpm`) and probes Stellar RPC health.

### Usage

```bash
astrolabe doctor [OPTIONS]
```

### Options

| Flag | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| `--offline` | `bool` | `false` | Skip probing the remote Stellar RPC endpoint |
| `--rpc-url <URL>` | `String` | `https://soroban-testnet.stellar.org` | Stellar RPC endpoint to query with `getHealth` |

### Exit Codes

- `0`: All critical Rust/WASM requirements (`rustc`, `cargo`, `wasm32v1-none` target) are satisfied.
- `1`: A critical requirement is missing or an invalid argument/artifact was supplied.
