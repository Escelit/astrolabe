# Troubleshooting Guide

This guide lists the most common encoding, circuit, and contract errors when verifying Groth16 proofs on Soroban, along with their exact symptoms and fixes.

---

## 1. ACF & Contract Error Code Reference (`spec/spec.md` Section 11)

Both the off-chain libraries (`astrolabe-core`, `astrolabe-ts`, `astrolabe-cli`) and the on-chain Soroban contract (`astrolabe-verifier::VerifierError`) use the same nine error codes:

| Contract `#` | Stable Code | Common Cause | How to Fix |
| ------------ | ----------- | ------------ | ---------- |
| `Error(Contract, #1)` | `ERR_BAD_LENGTH` | Proof is not 256 bytes, `G1` is not 64 bytes, `G2` is not 128 bytes, `PublicInputs` is not a multiple of 32 bytes, or `VK` length $\neq 452 + 64 \cdot n_{ic}$. | Re-export the artifact with `astrolabe export` instead of slicing hex strings manually. |
| `Error(Contract, #2)` | `ERR_NON_CANONICAL_FIELD` | A point coordinate is $\ge p$, a public input scalar is $\ge r$, or arkworks compression/infinity flags (`0x80 \| 0x40` in byte `0`) are set. | Ensure field elements are big-endian (not little-endian!) and that public signals are reduced in your circuit before proving. |
| `Error(Contract, #3)` | `ERR_NOT_ON_CURVE` | A $G_1$ or $G_2$ point does not satisfy the curve equation ($y^2 = x^3 + 3$ or $y^2 = x^3 + 3/(9+u)$). Almost always caused by **wrong $G_2$ $\mathbb{F}_{p^2}$ component order (`c0 \|\| c1` instead of `c1 \|\| c0`)** or little-endian bytes. | Use `parse_snarkjs_proof` / `parse_snarkjs_vk` or `astrolabe export`, which convert `snarkjs` `[c0, c1]` into CAP-0074 `be32(c1) \|\| be32(c0)`. |
| `Error(Contract, #4)` | `ERR_NOT_IN_SUBGROUP` | A $G_2$ point lies on the twist curve $E'(\mathbb{F}_{p^2})$ but is not in the prime-order-$r$ subgroup ($[r]P \neq \mathcal{O}$). | Reject the untrusted proof or verification key; genuine `snarkjs` Groth16 outputs always lie in $G_2$. |
| `Error(Contract, #5)` | `ERR_PUBLIC_INPUT_COUNT` | The number of public inputs $n$ does not match the verification key ($n + 1 \neq n_{ic}$), or `verification_key.json` has `nPublic != IC.length - 1`. | Verify that you are passing all public outputs and public inputs from `public.json` against the matching circuit's `verification_key.json`. |
| `Error(Contract, #6)` | `ERR_INVALID_PROOF` | Either the pairing check evaluated to `false` ($\prod e(P_i, Q_i) \neq 1$), or one of the proof points $A, B, C$ is the point at infinity (all zeros). | Check that `proof.json` and `public.json` come from the same proving run, `public.json` signals are in `snarkjs` order (outputs first, then public inputs), and $A$ was **not** already negated off-chain. |
| `Error(Contract, #7)` | `ERR_UNSUPPORTED` | Envelope magic is not `"ASTR"`, `spec_ver != 0x01`, or `snarkjs` JSON has `"protocol"` $\neq$ `"groth16"` or `"curve"` $\neq$ `"bn128"` (e.g., `"bls12381"` or `"plonk"`). | Compile and prove your circuit with Groth16 over BN254 (`circom --prime bn128` and `snarkjs groth16`). For stored-VK contracts, ensure `initialize` was called before `verify`. |
| `Error(Contract, #8)` | `ERR_TRAILING_BYTES` | Extra bytes exist after an envelope's declared `payload_len`, or a `snarkjs` projective point array has a trailing projective coordinate $\neq 1$. | Strip any trailing garbage bytes or re-export using `astrolabe export`. |
| `Error(Contract, #9)` | `ERR_MALFORMED_INPUT` | Malformed JSON syntax, missing required fields (`pi_a`, `vk_alpha_1`), negative decimal string, leading zeros (`"01"`), or non-digit characters. | Inspect the JSON file for syntax errors or truncated output from the prover. |

---

## 2. Common Mistakes and Their Symptoms

### Mistake 1: Passing `snarkjs` $G_2$ coordinates in `[c0, c1]` order
- **Symptom on-chain:**
  ```text
  HostError: Error(Crypto, InvalidInput)
  Diagnostic Event: "bn254 G2: point not on curve"
  ```
- **Symptom off-chain (`astrolabe-core` / `astrolabe-ts`):** Returns `ERR_NOT_ON_CURVE`.
- **Why it happens:** `snarkjs` writes $\mathbb{F}_{p^2}$ pairs as `[c0, c1]` (real first, imaginary second), whereas CAP-0074 and EIP-197 require `be32(c1) || be32(c0)` (imaginary first, real second).
- **Fix:** Always convert `snarkjs` JSON using `astrolabe export` or `parse_snarkjs_proof` / `parse_snarkjs_vk`.

### Mistake 2: Negating Proof Point $A$ Both Off-Chain and On-Chain
- **Symptom:** Point validation succeeds (`A` and `-A` are both valid points on $G_1$), no host trap occurs, but `verify` returns `ERR_INVALID_PROOF` (`Error(Contract, #6)`).
- **Why it happens:** Some Ethereum/Solidity scripts negate `pi_a` off-chain before sending the transaction. Because `astrolabe-verifier` negates `A` on-chain (`spec/spec.md` Section 8 Step 3), negating `A` off-chain results in `--A = +A`, so the pairing check computes $e(A, B) \cdot e(A, B)$ instead of $e(-A, B) \cdot e(A, B) = 1$.
- **Fix:** Do **not** negate `A` off-chain. Pass the unmodified `proof.json` to `astrolabe`.

### Mistake 3: Reversing Public Outputs and Public Inputs
- **Symptom:** `snarkjs groth16 verify` passes, all points are on-curve, and public input count matches, but on-chain verification fails with `ERR_INVALID_PROOF` (`Error(Contract, #6)`).
- **Why it happens:** When constructing `public_inputs: Vec<BytesN<32>>` manually in an application, developers often put circuit `input` signals before `output` signals. Circom and `snarkjs` always assign **public outputs first** ($IC_1 \dots IC_{n_{\text{out}}}$), followed by **public inputs** ($IC_{n_{\text{out}}+1} \dots IC_n$).
- **Fix:** Match the exact element order in `public.json`.

### Mistake 4: Little-Endian Field Elements (Arkworks Default Serialization)
- **Symptom:** Fails immediately with `ERR_NON_CANONICAL_FIELD` (`Error(Contract, #2)`) or `ERR_NOT_ON_CURVE` (`Error(Contract, #3)`), or traps on-chain with `HostError: Error(Crypto, InvalidInput)`.
- **Why it happens:** Rust's `ark-serialize` uses little-endian byte order and embeds sign/infinity flags in the most significant bits of the last byte. CAP-0074 and ACF (`spec/spec.md` Section 2 & 3) use **uncompressed big-endian** encoding (`be32`) with the top two flag bits of byte `0` unset (`0`).
- **Fix:** Encode integers with 32-byte big-endian (`encode_fp`, `encode_fr`) and represent infinity as all-zero bytes (`[0u8; 64]` for $G_1$, `[0u8; 128]` for $G_2$).

### Mistake 5: Using `Vec<Bn254Fr>` in Custom Contract Entrypoints
- **Symptom:** A custom contract accepts both a valid public input $s$ and an aliased input $s + r < 2^{256}$ for the same proof!
- **Why it happens:** `soroban_sdk::crypto::bn254::Bn254Fr` reduces values $\ge r$ modulo $r$ inside `TryFromVal` during argument deserialization before contract code executes.
- **Fix:** Always use `Vec<BytesN<32>>` in contract entrypoints and call `astrolabe_verifier::verify_groth16_slice` or `verify_groth16_bytes`, which rejects any scalar $\ge r$ with `VerifierError::NonCanonicalField` before constructing `Bn254Fr`.

### Mistake 6: Duplicate Symbol `get_vk` or `verify` When Building WASM
- **Symptom:** `warning: Linking globals named 'get_vk': symbol multiply defined!` during `stellar contract build`.
- **Why it happens:** Defining multiple `#[contractimpl]` blocks that export the same function names in the same WASM dependency graph.
- **Fix:** Depend on `astrolabe-verifier` with default features (`default-features = true`) when writing a custom or baked-VK contract (`verify_groth16_slice` / `verify_groth16_bytes`), and only enable `features = ["stored-contract"]` when re-exporting `StoredVkVerifierContract` directly.
