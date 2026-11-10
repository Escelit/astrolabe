# Astrolabe Canonical Format (ACF) Specification

**Status:** Final 1.0 (Audited and Hardened)
**Version string:** `acf/1.0`
**License:** CC-BY-4.0 (text), MIT OR Apache-2.0 (reference code)

> Authoritative specification for the Astrolabe Canonical Format (ACF). Ground-truth
> behaviors confirmed against Stellar Protocol 25/29 BN254 host functions (CAP-0074),
> `soroban-sdk 29.0.1`, and live Stellar Testnet verification transactions. See
> `docs/phase1-findings.md` and `docs/security-review.md`.

---

## 1. Purpose and Scope

Astrolabe defines a single, versioned, toolchain-neutral encoding for moving
zero-knowledge proof artifacts from proof-generation toolchains into Soroban
smart contracts that use Stellar Protocol 25 BN254 host functions.

**In scope (v0.1):**

- Proof system: Groth16
- Curve: BN254 (a.k.a. alt_bn128, bn128)
- Artifacts: proof, verification key, public inputs
- Source toolchains: snarkjs (Circom), Noir via a Groth16 backend that emits
  snarkjs-compatible artifacts
- Target: Soroban contracts calling the BN254 host functions

**Out of scope (v0.1), reserved for later versions:**

- PLONK, UltraHonk, Halo2, STARK/FRI verifiers
- BLS12-381 (a different curve ID is reserved, see Section 5)
- RISC Zero seals and journals (an adapter section is reserved, see Section 10.3)
- Proof generation, trusted-setup management, circuit compilation

**Goals:**

1. One unambiguous byte-level format, with exact test vectors.
2. Deterministic: the same logical artifact always yields the same bytes.
3. Strict validation: reject malformed input early, with stable error codes.
4. Cheap to consume on-chain: no parsing beyond fixed-offset slicing.

## 2. Conventions

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" are to be
interpreted as described in RFC 2119.

| Symbol | Meaning |
| ------ | ------- |
| `p` | BN254 base field modulus: `21888242871839275222246405745257275088696311157297823662689037894645226208583` |
| `r` | BN254 scalar field modulus (group order): `21888242871839275222246405745257275088548364400416034343698204186575808495617` |
| `Fp` | Base field, integers in `[0, p)` |
| `Fr` | Scalar field, integers in `[0, r)` |
| `Fp2` | Quadratic extension `Fp[u]/(u^2 + 1)`, elements written `c0 + c1·u` |
| `G1` | Group of points on `y^2 = x^3 + 3` over `Fp` |
| `G2` | Order-`r` subgroup of the twist curve over `Fp2` |
| `‖` | Byte concatenation |
| `be32(n)` | 32-byte big-endian unsigned encoding of integer `n` |

All multi-byte integers in this spec are **big-endian** unless stated otherwise.

## 3. Primitive Encodings

### 3.1 Field elements

- An `Fp` element is encoded as `be32(x)` where `x < p`.
- An `Fr` element is encoded as `be32(x)` where `x < r`.
- Encoders MUST emit exactly 32 bytes. Decoders MUST reject values `>= p`
  (or `>= r`) as non-canonical (`ERR_NON_CANONICAL_FIELD`).

### 3.2 G1 points (64 bytes)

```
G1 = be32(x) ‖ be32(y)
```

- Affine, uncompressed.
- The point at infinity is encoded as 64 zero bytes (`x = 0, y = 0`).
  Since `(0, 0)` is not on the curve `y^2 = x^3 + 3`, this is unambiguous.
- Non-infinity points MUST satisfy the curve equation
  (`ERR_NOT_ON_CURVE`). G1 has cofactor 1, so no separate subgroup check is
  needed.

### 3.3 G2 points (128 bytes)

```
G2 = be32(x.c1) ‖ be32(x.c0) ‖ be32(y.c1) ‖ be32(y.c0)
```

Confirmed against CAP-0074, `soroban-sdk 29.0.1`, and Stellar Testnet TX
`3d5683f26ac43c01964b89f8d7d1bdaf2f7a24a23589e437ba7a19f39f87a804`: CAP-0074
adopts Ethereum EIP-197 ordering (imaginary component first, real component
second), and the top two flag bits (`0x80 | 0x40` of byte 0) MUST be unset.
Implementations MUST keep the component order in a single named constant
(`FP2_COMPONENT_ORDER`).

- Affine, uncompressed.
- Infinity is 128 zero bytes.
- Non-infinity points MUST satisfy the twist curve equation
  (`ERR_NOT_ON_CURVE`) AND MUST lie in the order-`r` subgroup
  (`ERR_NOT_IN_SUBGROUP`). The twist has a large cofactor, so the subgroup
  check is mandatory in off-chain validators. Confirmed in `soroban-env-host 29.0.1`
  and on Stellar Testnet: `bn254_multi_pairing_check` validates both twist-curve
  membership and order-`r` subgroup membership, trapping with
  `Error(Crypto, InvalidInput)`. Off-chain Astrolabe validators MUST still perform
  both checks independently to report `ERR_NOT_ON_CURVE` vs `ERR_NOT_IN_SUBGROUP`.

### 3.4 Scalars used as public inputs

Encoded as `be32(x)` with `x < r`. Values `>= r` MUST be rejected, never
silently reduced (`ERR_NON_CANONICAL_FIELD`). Reduction would let two distinct
inputs map to one scalar, which can break nullifier or uniqueness logic in
applications.

## 4. Groth16 Objects

### 4.1 Proof (256 bytes)

```
Proof = A ‖ B ‖ C
        G1   G2   G1
        64  128   64   = 256 bytes
```

The encoder MUST NOT negate `A`. Negation is performed by the verifier
(Section 8). This keeps the proof bytes identical to what the prover emitted.

### 4.2 Verification key

```
VK = alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ be32_u32(n_ic) ‖ IC[0] ‖ ... ‖ IC[n_ic-1]
     G1         G2        G2         G2          4 bytes          G1 each
```

- `n_ic = n_public + 1`.
- Total size: `64 + 3·128 + 4 + 64·n_ic` bytes. Note the length prefix is a
  4-byte big-endian unsigned integer, not an Fp element.
- The precomputed pairing `vk_alphabeta_12` that snarkjs emits is NOT included.
  The on-chain verifier computes the pairing check through the multi-pairing
  host function, so it is unnecessary.

### 4.3 Public inputs

```
PublicInputs = be32(s_0) ‖ be32(s_1) ‖ ... ‖ be32(s_{n-1})
```

- Order is the order snarkjs emits in `public.json` (outputs first, then
  public inputs, in circuit declaration order).
- `n` MUST equal `VK.n_ic - 1` (`ERR_PUBLIC_INPUT_COUNT`).

## 5. Artifact Envelope

Artifacts MAY be wrapped in a self-describing envelope for storage and tooling.
On-chain contracts typically consume the raw payloads from Section 4 directly
and do not need the envelope.

```
Envelope = magic ‖ spec_ver ‖ kind ‖ curve ‖ system ‖ payload_len ‖ payload
           4       1          1      1       1        4             payload_len
```

| Field | Size | Value |
| ----- | ---- | ----- |
| `magic` | 4 | ASCII `ASTR` (`0x41 0x53 0x54 0x52`) |
| `spec_ver` | 1 | `0x01` for ACF 0.x |
| `kind` | 1 | `0x01` proof, `0x02` verification key, `0x03` public inputs |
| `curve` | 1 | `0x01` BN254. Reserved: `0x02` BLS12-381 |
| `system` | 1 | `0x01` Groth16. Reserved: `0x02` PLONK, `0x03` UltraHonk |
| `payload_len` | 4 | Big-endian length of the payload |

Decoders MUST reject unknown `spec_ver`, `kind`, `curve`, or `system` values
(`ERR_UNSUPPORTED`) and any trailing bytes after `payload_len`
(`ERR_TRAILING_BYTES`).

## 6. Textual (JSON) Form

For human review and fixtures, each artifact has a canonical JSON form:

```json
{
  "acf": "0.1",
  "kind": "proof",
  "curve": "bn254",
  "system": "groth16",
  "hex": "<lowercase hex of the payload, no 0x prefix>"
}
```

- Hex MUST be lowercase, without a `0x` prefix, with even length.
- Keys appear in the order shown. Output is UTF-8, no BOM, LF newlines, and a
  single trailing newline.

## 7. Soroban Mapping

| ACF object | Soroban type |
| ---------- | ------------ |
| `Fp` / `Fr` element | `BytesN<32>` (or `U256` where the SDK requires) |
| `G1` | `BytesN<64>` |
| `G2` | `BytesN<128>` |
| `Proof` | struct `{ a: BytesN<64>, b: BytesN<128>, c: BytesN<64> }` |
| `VerificationKey` | struct `{ alpha: BytesN<64>, beta: BytesN<128>, gamma: BytesN<128>, delta: BytesN<128>, ic: Vec<BytesN<64>> }` |
| `PublicInputs` | `Vec<BytesN<32>>` (or `Vec<U256>`) |

Confirmed host-side types in `soroban-sdk 29.0.1`:
`Bn254Fp(BytesN<32>)`, `Bn254Fr(U256)`, `Bn254G1Affine(BytesN<64>)`,
`Bn254G2Affine(BytesN<128>)`, and `Bn254::pairing_check(Vec<Bn254G1Affine>, Vec<Bn254G2Affine>)`.

**Normative Security Requirement:** Soroban contract entrypoints accepting
public inputs MUST take `Vec<BytesN<32>>` (or `Vec<U256>`) and explicitly reject
values `>= r` (`ERR_NON_CANONICAL_FIELD`) before converting to `Bn254Fr`,
because both `Bn254Fr` (`TryFromVal` / `from_bytes` / `from_u256`) and the host
`bn254_g1_mul` function silently reduce values `>= r` modulo `r` without error.

## 8. Reference Verification Algorithm

Given `Proof(A, B, C)`, `VK`, and public inputs `s_1..s_n`:

1. Validate all inputs per Section 9.
2. Compute `vk_x = IC[0] + Σ_{i=1..n} s_i · IC[i]` using `bn254_g1_mul` and
   `bn254_g1_add` (or `bn254_g1_msm` + `bn254_g1_add`).
3. Negate `A`: `-A = (A.x, p - A.y)`; if `A.y = 0` the point is its own
   negation. If `A`, `B`, or `C` is infinity, reject (`ERR_INVALID_PROOF`).
   On-chain contracts MUST explicitly verify `A`, `B`, and `C` are non-zero,
   because host functions accept all-zero infinity points in pairings without
   trapping.
4. Call `bn254_multi_pairing_check` over the pairs:

```
( -A,      B       )
( alpha,   beta    )
( vk_x,    gamma   )
( C,       delta   )
```

5. The proof is valid if and only if the product of the pairings equals the
   identity in the target group, i.e. the host call returns `true`.

Contracts MUST bind any application-level context (recipient, nonce, chain ID,
contract ID) into the public inputs. Groth16 proofs are malleable and can be
replayed unless the circuit constrains them.

## 9. Validation Rules

A conforming validator MUST check, in this order:

1. **Length.** Payload sizes match Sections 3 and 4 exactly (`ERR_BAD_LENGTH`).
2. **Canonical fields.** Every Fp / Fr value is below its modulus
   (`ERR_NON_CANONICAL_FIELD`).
3. **On-curve.** Every non-infinity G1 / G2 point satisfies its curve equation
   (`ERR_NOT_ON_CURVE`).
4. **Subgroup (G2).** Every non-infinity G2 point is in the order-`r` subgroup
   (`ERR_NOT_IN_SUBGROUP`).
5. **Counts.** `n_public + 1 == n_ic` (`ERR_PUBLIC_INPUT_COUNT`).
6. **Degenerate points.** `A`, `B`, `C` MUST NOT be infinity for a proof to be
   accepted (`ERR_INVALID_PROOF`). VK points are allowed to be infinity only
   where the circuit genuinely produces them (e.g. an `IC[i]` for an
   unconstrained input); validators SHOULD warn.

Error codes are stable strings and are part of the public API.

## 10. Toolchain Mappings

### 10.1 snarkjs / Circom (`curve: "bn128"`)

snarkjs emits decimal strings. Mapping to ACF:

**proof.json**

| snarkjs field | ACF |
| ------------- | --- |
| `pi_a = [x, y, "1"]` | `A = be32(x) ‖ be32(y)`; the trailing `"1"` is dropped |
| `pi_b = [[x0, x1], [y0, y1], ["1","0"]]` | `B = be32(x1) ‖ be32(x0) ‖ be32(y1) ‖ be32(y0)`; the trailing `["1","0"]` is dropped |
| `pi_c = [x, y, "1"]` | `C`, as for `A` |
| `protocol`, `curve` | MUST equal `"groth16"` and `"bn128"`, else `ERR_UNSUPPORTED` |

snarkjs lists each `Fp2` as `[c0, c1]` (real, imaginary), which is why the
imaginary component is moved first when producing ACF `G2` bytes.

**verification_key.json**

| snarkjs field | ACF |
| ------------- | --- |
| `vk_alpha_1` | `alpha_g1` (G1) |
| `vk_beta_2` | `beta_g2` (G2) |
| `vk_gamma_2` | `gamma_g2` (G2) |
| `vk_delta_2` | `delta_g2` (G2) |
| `IC` | `IC[0..n_ic-1]` (G1 each) |
| `nPublic` | MUST equal `len(IC) - 1`, else `ERR_PUBLIC_INPUT_COUNT` |
| `vk_alphabeta_12` | ignored |

**public.json:** an array of decimal strings, each converted with `be32` and
range-checked against `r`.

### 10.2 Noir

Astrolabe v0.1 supports Noir only through a Groth16 backend that emits
snarkjs-compatible `proof.json`, `verification_key.json`, and `public.json`.
Section 10.1 then applies unchanged. Noir's native proof systems (e.g.
UltraHonk) are out of scope.

Implementations SHOULD record the Noir toolchain and backend versions in
artifact metadata (not in the canonical bytes).

### 10.3 RISC Zero (reserved)

A future revision will define how a RISC Zero Groth16 seal, image ID, and
journal digest map onto `Proof` and `PublicInputs`. Not specified in v0.1.

## 11. Error Codes

| Code | Meaning |
| ---- | ------- |
| `ERR_BAD_LENGTH` | Byte length does not match the expected size |
| `ERR_NON_CANONICAL_FIELD` | Value is not below the field modulus |
| `ERR_NOT_ON_CURVE` | Point does not satisfy the curve equation |
| `ERR_NOT_IN_SUBGROUP` | G2 point is not in the order-`r` subgroup |
| `ERR_PUBLIC_INPUT_COUNT` | Public-input count does not match the VK |
| `ERR_INVALID_PROOF` | Degenerate proof element or failed pairing check |
| `ERR_UNSUPPORTED` | Unknown version, kind, curve, system, or protocol |
| `ERR_TRAILING_BYTES` | Extra bytes after the declared payload |
| `ERR_MALFORMED_INPUT` | Source file is not parseable (bad JSON, bad decimal) |

## 12. Test Vectors

Test vectors are the primary conformance mechanism. They live in
`vectors/` as JSON files, one file per category:

```json
{
  "id": "g1-generator-valid",
  "description": "BN254 G1 generator (1, 2)",
  "operation": "decode_g1",
  "input_hex": "<64 bytes>",
  "expected": { "ok": true },
  "tags": ["g1", "valid"]
}
```

Required categories:

| Category | Purpose |
| -------- | ------- |
| `valid/` | Known-good proofs, VKs, and public inputs, at least one per supported toolchain |
| `invalid-length/` | Truncated and over-long payloads |
| `invalid-field/` | Values equal to or above `p` / `r` |
| `invalid-curve/` | Points not on the curve |
| `invalid-subgroup/` | G2 points on the twist but outside the subgroup |
| `infinity/` | Infinity handling for G1, G2, and degenerate proofs |
| `public-input-count/` | Mismatches between `n_public` and `n_ic` |
| `onchain/` | Proofs verified via testnet transactions, with transaction hashes recorded |

Anchor vector (G1 generator `(1, 2)`):

```
x = 0000000000000000000000000000000000000000000000000000000000000001
y = 0000000000000000000000000000000000000000000000000000000000000002
```

G2 generator and Circom/snarkjs fixtures MUST be generated by the reference
tooling and cross-checked against two independent libraries (e.g. arkworks and
snarkjs) before being committed.

## 13. Versioning and Conformance

- This spec follows semantic versioning: `MAJOR.MINOR`.
- A **breaking** change to byte layouts bumps `MAJOR` and the envelope
  `spec_ver`.
- Additions (new curves, systems, toolchain mappings) bump `MINOR` and MUST NOT
  change existing byte layouts.
- An implementation is **conformant** if it passes every vector for the
  features it claims. Implementations MUST state the spec version and feature
  set they support (e.g. `acf/0.1: groth16, bn254, snarkjs`).
- An implementation SHOULD publish its test-vector results in CI.

## 14. Security Considerations

- **Malleability and replay.** Groth16 proofs can be re-randomized. Bind
  application context into public inputs (Section 8).
- **Non-canonical inputs.** Never reduce silently. Accepting two encodings of
  one scalar can break nullifier logic.
- **Subgroup checks.** Off-chain validators MUST check G2 subgroup membership.
  Skipping this has caused practical attacks on pairing-based systems.
- **Trusted setup.** Groth16 security depends on the ceremony that produced the
  proving and verification keys. Astrolabe does not validate setup provenance;
  tooling SHOULD surface it.
- **BN254 security level.** BN254 is generally considered to offer a lower
  security margin than 128 bits against known attacks. Applications handling
  high-value assets SHOULD document this assumption.
- **Resource limits.** Verification cost grows with the number of public
  inputs (one scalar multiplication each). Contracts SHOULD bound `n_public`
  and measure instruction cost against current Soroban limits.
- **Side channels.** Reference encoders and validators operate on public data
  and do not need constant-time guarantees, but any code handling witnesses or
  secret keys is out of scope and MUST NOT be added to these libraries.

## 15. Open Questions

1. **Resolved in Phase 1 & 7:** Exact G2 `Fp2` component order in CAP-0074 (Section 3.3).
   Confirmed as `be32(c1) ‖ be32(c0)` matching EIP-197. See `docs/phase1-findings.md`.
2. **Resolved in Phase 1 & 7:** Host function on-curve and subgroup validation.
   Confirmed: host enforces both on-curve and order-`r` subgroup checks, trapping
   with `Error(Crypto, InvalidInput)`. Off-chain validators enforce both.
3. **Resolved in Phase 1 & 7:** Infinity encoding accepted by host functions.
   Confirmed: 64 zero bytes for G1, 128 zero bytes for G2. Contracts explicitly
   reject zero points for proof elements $A$, $B$, and $C$.
4. **Resolved in Phase 1 & 7:** Scalar reduction behavior in `bn254_g1_mul`.
   Confirmed: host and SDK silently reduce modulo `r`. Contracts explicitly
   reject scalars $\ge r$.
5. Should `PublicInputs` carry an explicit count prefix, or rely on the VK?
6. Which RISC Zero seal and journal mapping should the first adapter target?
7. Should the envelope support optional metadata (toolchain versions, circuit
   hash) in a separate, non-canonical section?

## 16. Reference Implementations

| Component | Language | Role |
| --------- | -------- | ---- |
| `astrolabe-spec` | Markdown + JSON | This document and `vectors/` |
| `astrolabe-ts` | TypeScript | Browser and Node encoder/validator |
| `astrolabe-core` | Rust (`no_std`) | Core codecs, validators, and snarkjs adapter |
| `astrolabe-verifier` | Rust / Soroban | On-chain Groth16 verifier helpers and contract template |
| `astrolabe-cli` | Rust | `export`, `gen-verifier`, `verify`, `doctor` CLI |

The TypeScript and Rust implementations MUST agree byte-for-byte on every
vector, and MUST agree with snarkjs's own off-chain verification result on
every `valid/` vector.

## 17. Changelog

- **1.0.0 (final):** Promoted to final 1.0 specification. Resolved all
  `[VERIFY]` items with testnet transaction hashes and host evidence.
  Documented confirmed Soroban SDK 29.0.1 types, silent reduction defense,
  and infinity rejection rules. Passed independent security review and fuzzing.
- **0.1 (draft):** Initial draft. Groth16 on BN254, snarkjs/Circom mapping,
  Noir via Groth16 backend, envelope, validation rules, error codes.
