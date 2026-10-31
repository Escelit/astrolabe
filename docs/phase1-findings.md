# Phase 1 Findings: Soroban BN254 Ground Truth

**Date:** 2026-10-31  
**Status:** Complete (all five `[VERIFY]` questions resolved with SDK/host source inspection, local tests, negative controls, and live Stellar Testnet transactions)  
**Spec version targeted:** `acf/0.1`

---

## 1. Executive Summary

| # | Spec `[VERIFY]` Question | Verified Answer | Primary Evidence |
| - | ------------------------ | --------------- | ---------------- |
| 1 | **G2 `Fp2` component order** (Spec §3.3, §15.1) | **`be32(c1) ‖ be32(c0)`** (imaginary component first, real component second — identical to Ethereum EIP-197). | `soroban-sdk 29.0.1` (`src/crypto/bn254.rs:58-62`), `soroban-env-host 29.0.1` (`src/crypto/bn254.rs:99-129`), live Testnet TX `3d5683f2...` (`c1 ‖ c0` -> `true`) vs `c0 ‖ c1` (`Error(Crypto, InvalidInput): "bn254 G2: point not on curve"`). |
| 2 | **Host on-curve & G2 subgroup validation** (Spec §3.3, §15.2) | **Yes, the host validates both on-curve and G2 subgroup membership**, plus exact byte length, unset top two flag bits (`0x80 \| 0x40` of byte 0), and canonical `Fp < p`. Violations trap with `Error(Crypto, InvalidInput)`. *(Exception: `bn254_g1_is_on_curve` returns `false` without trapping when `(x, y)` with `x, y < p` is off-curve.)* | `soroban-env-host 29.0.1` (`src/crypto/bn254.rs:53-89, 202-305`) and live Testnet RPC probe on twist point `x = 0 + u` (`Error(Crypto, InvalidInput): "bn254 G2: point not in the correct subgroup"`). |
| 3 | **Infinity encoding & host behavior** (Spec §3.2, §3.3, §15.3) | **G1 infinity = 64 zero bytes (`[0u8; 64]`); G2 infinity = 128 zero bytes (`[0u8; 128]`).** Accepted without trapping in all positions by `g1_add`, `g1_mul`, `g1_msm`, `g1_is_on_curve` (`true`), and `multi_pairing_check` (contributes `1` in `GT`). Setting arkworks flag bit `0x40` traps. **On-chain Groth16 verifiers MUST explicitly reject zero `A`, `B`, `C`.** | `soroban-env-host 29.0.1` (`src/crypto/bn254.rs:84-88, 212-216, 260-264`), local `exp3_infinity_handling_across_host_functions`, and live Testnet RPC probes. |
| 4 | **`bn254_g1_mul` scalar input type & `>= r` behavior** (Spec §3.4, §7, §15.4) | Host takes **`U256Val`** (`Bn254Fr(U256)` in `soroban-sdk`). **Both `soroban-sdk` and `soroban-env-host` silently reduce values `>= r` modulo `r` (never trap).** An unguarded verifier accepts aliased public input `s + r` (`TX 7e789d10...` -> `true`). **On-chain verifiers MUST explicitly reject scalars `>= r` before `Bn254Fr` conversion.** | `soroban-sdk 29.0.1` (`src/crypto/bn254.rs:322-335`), `soroban-env-host 29.0.1` (`src/crypto/metered_scalar.rs:108-119`), live Testnet TX `7e789d10...` (`verify_raw` -> `true`) vs `verify_acf` (`Error(Contract, #2)`). |
| 5 | **Exact `soroban-sdk` BN254 types & conversions** (Spec §7) | Module `soroban_sdk::crypto::bn254`: `Bn254`, `Bn254Fp(BytesN<32>)`, `Bn254Fr(U256)` (`Fr` alias is `#[deprecated]`), `Bn254G1Affine(BytesN<64>)`, `Bn254G2Affine(BytesN<128>)`. Operations: `g1_add`, `g1_mul`, `g1_msm`, `g1_is_on_curve`, `pairing_check(Vec<Bn254G1Affine>, Vec<Bn254G2Affine>)`, `fr_{add,sub,mul,pow,inv}`. | `soroban-sdk 29.0.1` (`src/crypto/bn254.rs:15-494`) and compiled contract `scripts/phase1-probe` (`7,407` bytes optimized WASM). |

---

## 2. Environment and Pinned Tool Versions

All experiments were run on Linux (`x86_64-unknown-linux-gnu`) with the following exact versions:

| Tool / Component | Version |
| ---------------- | ------- |
| `rustc` | `1.97.1 (8bab26f4f 2026-07-14)` |
| `cargo` | `1.97.1 (c980f4866 2026-06-30)` |
| `stellar` CLI | `28.0.0 (300aaf69ab100536678bdb641428b06f06b318ea)` |
| `stellar-xdr` | `28.0.0 (d0f1330e43c3a2c0c616da30698b24140d4eea72)` |
| `soroban-sdk` | `29.0.1` |
| `soroban-env-host` | `29.0.1` |
| `ark-bn254` / `ark-ec` / `ark-ff` | `0.5.0` (matches `soroban-env-host` dependency) |
| `circom` | `2.2.3` |
| `snarkjs` | `0.7.6` |
| `node` | `v24.13.0` |
| `pnpm` | `10.28.2` |
| Stellar Testnet RPC | `stellar-core 30.0.0 (0e49751aa9ddf892302cca02cea7f3f5d97df9f1)`, **Protocol Version 29** |
| Testnet Network Passphrase | `Test SDF Network ; September 2015` |

### Probe Dependency Justification (`scripts/phase1-probe` only)

- Root workspace crates (`astrolabe-core`, `astrolabe-verifier`, `astrolabe-cli`) and `packages/astrolabe-ts` remain at **zero runtime dependencies**.
- `scripts/phase1-probe` is a standalone excluded Cargo package (`[workspace]`) pinning `soroban-sdk = "=29.0.1"` (`no_std` compatible; produces a **`7,407`-byte** optimized `wasm32v1-none` binary, `8,621` bytes unstripped) and `[dev-dependencies]` `soroban-env-host = "=29.0.1"` + `ark-bn254 / ark-ec / ark-ff / ark-serialize = "0.5.0"` for host-level and reference-curve cross-checks.

---

## 3. Circuit & Public Artifact Provenance

A minimal Circom 2.0 circuit (`Multiplier2`: `c <== a * b` with `public [a]`) was compiled with `circom 2.2.3` and set up using an ephemeral development Powers-of-Tau and Phase 2 `.zkey` (`snarkjs 0.7.6`) outside the repository:

- **Security note:** The development ceremony is strictly for public test-vector generation and is **not** safe for production use. All toxic waste, `.ptau`, `.zkey`, private input JSON, and `.wtns` files were deleted immediately after `snarkjs groth16 verify` succeeded (`[INFO] snarkJS: OK!`). Only public verification artifacts were retained.
- **Public statement:** `a = 3` (public input), `c = 33` (public output; private witness was `b = 11`).
- **Signal ordering confirmed (Spec §4.3):** `snarkjs` emitted `public.json` as `["33", "3"]` — public outputs first (`c = 33`), then public inputs (`a = 3`), with `VK.n_ic = 3`.
- **Reproducible commands:**
  ```bash
  cargo test --manifest-path scripts/phase1-probe/Cargo.toml -- --nocapture
  stellar contract build --manifest-path scripts/phase1-probe/Cargo.toml
  ```

---

## 4. Recorded Stellar Testnet Deployment & Transactions

| Action | Identifier / Hash | Outcome |
| ------ | ----------------- | ------- |
| Optimized Probe WASM SHA-256 | `b782ef50e908a50c1f74e5edd047fc188bad4b82f54120c3acae0690f3a20462` | `7,407` bytes (`wasm32v1-none`) |
| Upload WASM TX | `395a04b89dcae2ec576f0bc1ec34650e74ceb827f8cb140cb0a882c710d83e75` | Success |
| Deploy Contract TX | `ee9d5673b32307899858fc26c9b4e113dcfda33f0d920bc17de5056d0497107a` | Contract `CBWJBCNFY2ZKBSQIS3BFJ4LGRQO2QTKQ7VOWEUNETTOGKUP4OXZ54TF4` |
| **Valid Groth16 Verification TX (`verify_acf`)** | **`3d5683f26ac43c01964b89f8d7d1bdaf2f7a24a23589e437ba7a19f39f87a804`** | **`true`** (`c1 ‖ c0` proof + VK, public signals `[33, 3]`) |
| Negative Control TX: Wrong Signal (`verify_raw`) | `591358bbe9c3e62dcbe23d7043c70484d7affb0784dfa1c3fe5d9b79adf1559d` | **`false`** (public signals `[34, 3]`; no trap, pairing product != 1) |
| Security Control TX: Aliased Scalar `33 + r` (`verify_raw`) | `7e789d10a2903283dcd48a2dd42377ad17d1981f14eb311043928c746a1edae8` | **`true`** on unguarded `verify_raw`; rejected with `Error(Contract, #2)` by guarded `verify_acf` |

---

## 5. Detailed Experiment Results

### Experiment 1: G2 `Fp2` Component Order (`c1 ‖ c0` vs `c0 ‖ c1`)

- **SDK & Host Source:**
  - `soroban-sdk-29.0.1/src/crypto/bn254.rs:58-62`: *"Format: `be_bytes(X) || be_bytes(Y)` where each coordinate is an Fp2 element (64 bytes) - Fp2 element encoding: `be_bytes(c1) || be_bytes(c0)` where `c0` is the real component ... `c1` is the imaginary component"*.
  - `soroban-env-host-29.0.1/src/crypto/bn254.rs:99-129`: Arkworks serializes `Fp2` as `le32(c0) ‖ le32(c1)`, so `bn254_field_element_deserialize` reverses the entire 64-byte slice in place, mapping `be32(c1) ‖ be32(c0)` to `le32(c0) ‖ le32(c1)`.
- **Positive Run:** Converting `snarkjs` `[c0, c1]` pairs into `be32(x.c1) ‖ be32(x.c0) ‖ be32(y.c1) ‖ be32(y.c0)` verified `true` both locally and on Stellar Testnet (`TX 3d5683f26ac43c01964b89f8d7d1bdaf2f7a24a23589e437ba7a19f39f87a804`).
- **Negative Control A (`c0 ‖ c1`):** Encoding both `VK` and `Proof` G2 points as `be32(c0) ‖ be32(c1)` trapped on live Testnet RPC:
  ```text
  HostError: Error(Crypto, InvalidInput)
  Diagnostic Event: "bn254 G2: point not on curve"
  ```
- **Negative Control B (Wrong Public Signal):** Keeping valid `c1 ‖ c0` curve points but changing `s_0` from `33` to `34` did not trap and returned `false` (`TX 591358bbe9c3e62dcbe23d7043c70484d7affb0784dfa1c3fe5d9b79adf1559d`), while `verify_acf` returned `Err(ProbeError::InvalidProof)`.
- **Conclusion:** ACF Spec §3.3's `be32(x.c1) ‖ be32(x.c0) ‖ be32(y.c1) ‖ be32(y.c0)` layout is **confirmed**.

### Experiment 2: Host On-Curve, Subgroup, Range, and Flag Checks

- **Host Source (`soroban-env-host-29.0.1/src/crypto/bn254.rs`):**
  1. `bn254_validate_flags_and_check_infinity` (`lines 53-89`): Rejects wrong byte lengths and rejects any point where `bytes[0] & 0b1100_0000 != 0` (the two arkworks sign/infinity flag bits MUST be `0`).
  2. `bn254_field_element_deserialize` (`lines 107-146`): Rejects any `Fp` coordinate `>= p`.
  3. `bn254_g1_affine_deserialize` (`lines 202-251`): Checks `y^2 = x^3 + 3` for `bn254_g1_add`, `bn254_g1_mul`, `bn254_g1_msm`, and `bn254_multi_pairing_check` (cofactor is 1, so on-curve implies subgroup membership). `bn254_g1_is_on_curve` (`host.rs:3372-3380`) uses `PointValidationMode::NoCheck` after flag/range deserialization and returns `bool`.
  4. `bn254_g2_affine_deserialize` (`lines 255-305`): Checks twist curve equation `y^2 = x^3 + 3/(9 + u)` (`ContractCostType::Bn254G2CheckPointOnCurve`) **and** checks order-`r` subgroup membership (`ContractCostType::Bn254G2CheckPointInSubgroup`, `pt.is_in_correct_subgroup_assuming_on_curve()`).
- **Testnet Subgroup Probe:** Using `ark-bn254 0.5.0`, `x = 0 + 1·u` yields a point on the twist curve `y^2 = x^3 + 3/(9+u)` that is outside the prime-order-`r` subgroup:
  ```text
  0000000000000000000000000000000000000000000000000000000000000001
  0000000000000000000000000000000000000000000000000000000000000000
  28a7a81c6bf2a75dc9f0125bb581747e9e6b33fc3b2710a2309cef97a3163c65
  23712136978ed49faf2120ca4f7f71cfd4e7b46ffa0ea89edbc94ddc59238e9f
  ```
  Passing `(G1_gen, P_twist)` to `probe_pairing` on live Stellar Testnet RPC trapped with:
  ```text
  HostError: Error(Crypto, InvalidInput)
  Diagnostic Event: "bn254 G2: point not in the correct subgroup"
  ```
  Whereas `( -G1_gen, G2_gen ), ( G1_gen, G2_gen )` returned `true`.
- **Conclusion:** All host functions trap with `ScErrorType::Crypto` / `ScErrorCode::InvalidInput` on malformed, non-canonical, flagged, off-curve, or non-subgroup points (except `bn254_g1_is_on_curve`, which returns `false` on off-curve canonical points). Off-chain Astrolabe validators MUST still perform all checks in Spec §9 to surface distinct ACF error codes before incurring on-chain traps.

### Experiment 3: Infinity Encoding and Per-Host-Function Behavior

- **Encoding Confirmed:** G1 infinity is 64 zero bytes (`[0u8; 64]`); G2 infinity is 128 zero bytes (`[0u8; 128]`). Setting arkworks' compressed/uncompressed infinity flag (`byte[0] = 0x40`) traps in the host.
- **Per-Function Behavior (Verified Locally & on Testnet RPC):**
  - `bn254_g1_add`: `0 + G1 == G1`, `G1 + 0 == G1`, `0 + 0 == 0`, and `G1 + (-G1) == [0u8; 64]`.
  - `bn254_g1_mul`: `0 * 5 == [0u8; 64]` and `G1 * 0 == [0u8; 64]`.
  - `bn254_g1_is_on_curve`: returns `true` for `[0u8; 64]`.
  - `bn254_multi_pairing_check`: accepts `[0u8; 64]` in `vp1` and `[0u8; 128]` in `vp2` without trapping; any pair with an infinity point evaluates to `1` in `GT` (`probe_pairing([0_G1], [G2_gen]) == true`, `probe_pairing([G1_gen], [0_G2]) == true`).
  - Guest `-Bn254G1Affine`: negating `[0u8; 64]` yields `[0u8; 64]` without panicking.
- **Security Requirement for Phase 5 (`astrolabe-verifier`):** Because neither guest negation nor `bn254_multi_pairing_check` rejects infinity, **on-chain verifier contracts MUST explicitly reject all-zero `A`, `B`, or `C`** to satisfy Spec §8 Step 3 and §9 Rule 6 (`ERR_INVALID_PROOF`).

### Experiment 4: `bn254_g1_mul` Scalar Input Type and Reduction Behavior

- **Host & SDK Source:**
  - Host signature (`soroban-env-host-29.0.1/src/host.rs:3292`): `fn bn254_g1_mul(&self, ..., p0: BytesObject, scalar: U256Val) -> Result<BytesObject, HostError>`.
  - Host conversion (`src/crypto/metered_scalar.rs:108-119`): calls `ark_bn254::Fr::from_le_bytes_mod_order(&u.to_le_bytes())` — **reduces modulo `r` without error**.
  - SDK conversion (`soroban-sdk-29.0.1/src/crypto/bn254.rs:322-335`): `impl From<U256> for Bn254Fr` computes `value.rem_euclid(&modulus)` whenever `value >= r` — **also reduces modulo `r` without error** (including `Bn254Fr::from_bytes`, `Bn254Fr::from_u256`, and `TryFromVal`).
- **Experimental Results (Local + Testnet):**
  - `probe_g1_mul(G1_gen, r)` -> `[0u8; 64]` (reduced `r -> 0`).
  - `probe_g1_mul(G1_gen, r + 1)` -> `G1_gen` (reduced `r + 1 -> 1`), including when calling `RawHostEnv::bn254_g1_mul` directly with an unreduced `U256Val` bypassing `Bn254Fr`.
  - **Public-Input Aliasing Exploit Demonstration:** For `s_0 = 33`, `s_0 + r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000022 < 2^256`. Submitting `[33 + r, 3]` to unguarded `verify_raw` on Stellar Testnet **succeeded and returned `true`** (`TX 7e789d10a2903283dcd48a2dd42377ad17d1981f14eb311043928c746a1edae8`), whereas guarded `verify_acf` rejected it with `Error(Contract, #2)` (`ProbeError::NonCanonicalField`).
- **Security Requirement for Phase 5 (`astrolabe-verifier`):** Contracts accepting `BytesN<32>` or `U256` public inputs (or `Bn254Fr` via XDR `ScVal::U256`, which reduces on `TryFromVal`!) MUST accept `BytesN<32>` / `U256` and explicitly reject values `>= r` **before** constructing `Bn254Fr`. Never use `Bn254Fr` directly in a public contract entrypoint parameter list if canonical uniqueness is required, because `TryFromVal<Env, Val> for Bn254Fr` silently reduces uncanonical `U256` caller inputs!

### Experiment 5: Exact `soroban-sdk` (`29.0.1`) Types, Methods, and Gotchas

- **Types (`soroban_sdk::crypto::bn254`):**
  - `Bn254G1Affine(BytesN<64>)` — `from_bytes(BytesN<64>)`, `from_array(&Env, &[u8; 64])`, `to_bytes() -> BytesN<64>`, `to_array() -> [u8; 64]`, `Add`, `Mul<Bn254Fr>`, `Neg`. Does not validate on construction.
  - `Bn254G2Affine(BytesN<128>)` — `from_bytes(BytesN<128>)`, `from_array(&Env, &[u8; 128])`, `to_bytes() -> BytesN<128>`, `to_array() -> [u8; 128]`. Does not validate on construction.
  - `Bn254Fp(BytesN<32>)` — `from_bytes(BytesN<32>)`, `from_array(&Env, &[u8; 32])`, `Neg`. **Validates `< p` in guest WASM on construction and panics with `"Bn254: Invalid Fp"` if `>= p`.**
  - `Bn254Fr(U256)` — `from_bytes(BytesN<32>)`, `from_u256(U256)`, `to_bytes() -> BytesN<32>`, `to_u256() -> U256`, `Add`, `Sub`, `Mul`, `pow(u64)`, `inv()`. Note: `soroban_sdk::crypto::bn254::Fr` is `#[deprecated]` in `29.0.1` in favor of `Bn254Fr`.
- **Methods on `env.crypto().bn254()` (`Bn254`):**
  - `g1_add(&Bn254G1Affine, &Bn254G1Affine) -> Bn254G1Affine`
  - `g1_mul(&Bn254G1Affine, &Bn254Fr) -> Bn254G1Affine`
  - `g1_msm(Vec<Bn254G1Affine>, Vec<Bn254Fr>) -> Bn254G1Affine` *(Confirmed working; Phase 5 `astrolabe-verifier` can use `g1_msm` + one `g1_add` to compute `IC[0] + Σ s_i · IC[i]` in fewer host calls when `n_public > 0`!)*
  - `g1_is_on_curve(&Bn254G1Affine) -> bool`
  - `pairing_check(Vec<Bn254G1Affine>, Vec<Bn254G2Affine>) -> bool` *(Takes two parallel `Vec`s rather than a single `Vec` of pairs.)*
  - `fr_add`, `fr_sub`, `fr_mul`, `fr_pow`, `fr_inv`
- **Implementation Gotchas Recorded for Phase 5:**
  1. **Contract crate `unsafe_code` lint:** `#[contractimpl]` expands with `#[allow(unsafe_code)]`, which fails to compile under `#![forbid(unsafe_code)]`. Use `#![deny(unsafe_code)]` in Soroban contract crates (`#![forbid(unsafe_code)]` remains fine in pure library crates like `astrolabe-core`).
  2. **Guest panic in `-Bn254G1Affine`:** Because `Neg for &Bn254G1Affine` slices `A.y` into `Bn254Fp`, an uncanonical `A.y >= p` panics in guest WASM before reaching the host. Validate `A.x < p` and `A.y < p` explicitly first if returning a typed contract error.
  3. **Entrypoint type for public inputs:** Contract entrypoints MUST take `Vec<BytesN<32>>` (or `Vec<U256>`) rather than `Vec<Bn254Fr>`, because `TryFromVal` for `Bn254Fr` reduces `>= r` during argument deserialization before contract code runs.

---

## 6. Proposed Manual Updates to `spec/spec.md` (Plan Step 6)

Per `AGENTS.md` Section 3 Rule 1 and `Plan.md` Section 8 Step 6, `spec.md` was **not** modified by the agent. Below are the exact updates recommended for human review:

1. **Section 3.3 (G2 points):**
   - Remove `**[VERIFY]**` on the `Fp2` component order paragraph and state: *"Confirmed against CAP-0074, `soroban-sdk 29.0.1`, and Stellar Testnet TX `3d5683f26ac43c01964b89f8d7d1bdaf2f7a24a23589e437ba7a19f39f87a804`: CAP-0074 uses Ethereum EIP-197 ordering (`be32(c1) ‖ be32(c0)`), and the top two flag bits (`0x80 | 0x40` of byte 0) MUST be unset."*
   - Remove `**[VERIFY]**` on host subgroup validation and state: *"Confirmed in `soroban-env-host 29.0.1` and on Stellar Testnet: `bn254_multi_pairing_check` validates both twist-curve membership and order-`r` subgroup membership, trapping with `Error(Crypto, InvalidInput)`. Off-chain Astrolabe validators MUST still perform both checks independently to report `ERR_NOT_ON_CURVE` vs `ERR_NOT_IN_SUBGROUP`."*
2. **Section 7 (Soroban Mapping):**
   - Remove `**[VERIFY]**` and document the confirmed `soroban-sdk 29.0.1` types (`Bn254Fp`, `Bn254Fr`, `Bn254G1Affine`, `Bn254G2Affine`, and `Bn254::pairing_check(Vec<Bn254G1Affine>, Vec<Bn254G2Affine>)`).
   - Add a normative security warning that Soroban contract entrypoints MUST accept `Vec<BytesN<32>>` (or `Vec<U256>`) and explicitly reject values `>= r` before converting to `Bn254Fr`, because both `Bn254Fr` (`TryFromVal` / `from_bytes` / `from_u256`) and host `bn254_g1_mul` silently reduce modulo `r`.
3. **Section 8 (Reference Verification Algorithm):**
   - Note in Step 2 that `bn254_g1_msm` (plus one `bn254_g1_add` with `IC[0]`) is also available in `soroban-sdk 29.0.1` and equivalent to repeated `g1_mul` + `g1_add`.
   - Emphasize in Step 3 that on-chain contracts MUST explicitly check `A`, `B`, and `C` are non-zero (not infinity), because the host accepts all-zero infinity points in `g1_add`, `g1_mul`, and `multi_pairing_check` without trapping.
4. **Section 15 (Open Questions):**
   - Mark items 1–4 as **Resolved in Phase 1** with a link to `docs/phase1-findings.md` (leaving open design questions 5–7 for their scheduled phases).
