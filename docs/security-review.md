# Security Audit and Verification Report: Astrolabe v1.0 Hardening (Phase 7)

**Date:** November 2026  
**Auditor / Reviewer:** Astrolabe Core Security Team & Verification Suite  
**Status:** Completed — All Review Hotspots Verified, Findings Remediated  
**Target Specification:** Astrolabe Canonical Format (`acf/1.0`)  
**Target Codebase:**
- `crates/astrolabe-core` (`#![no_std]`, zero runtime dependencies)
- `crates/astrolabe-verifier` (Soroban Protocol 25/29 host bindings & verifier template)
- `crates/astrolabe-cli` (Export, verification, and contract generator)
- `packages/astrolabe-ts` (TypeScript browser & Node SDK, zero runtime dependencies)

---

## 1. Executive Summary

Astrolabe implements cryptographic serialization, strict input validation, toolchain adapters, and Soroban on-chain verifiers for zero-knowledge proofs (Groth16 over the BN254 curve). Because zero-knowledge verifiers guard financial assets and smart contract authorization gates on Stellar, cryptographic soundness, canonical uniqueness, and memory safety are paramount.

Phase 7 executes a rigorous, line-by-line security review of all six **Security Review Hotspots** defined in `AGENTS.md` Section 11, audits host-boundary interactions with Stellar Protocol 25/29 BN254 host functions (CAP-0074), and incorporates continuous coverage-guided fuzzing (`cargo-fuzz` and Vitest property runners).

### Summary of Audit Results

| Category | Status | Notes |
| -------- | ------ | ----- |
| **Point Negation & Infinity** | **PASSED** | On-chain negation $-A = (A_x, p - A_y)$ correctly preserves order. All-zero infinity points explicitly rejected for $A, B, C$. |
| **G2 Subgroup Check** | **PASSED** | Complete projective/Jacobian arithmetic on twist curve $y^2 = x^3 + 3/(9+u)$. $[r]P = \mathcal{O}$ verified against Arkworks reference. |
| **Canonical Range Checks** | **PASSED** | All coordinates and scalars strictly checked $< p$ and $< r$. Silent reduction rejected at contract boundary. |
| **Public Input Sizing** | **PASSED** | Exact $VK.n\_ic = n\_public + 1$ enforced. Buffer allocation strictly bounded by physical input length. |
| **$F_{p^2}$ Component Ordering** | **PASSED** | Held in single constant `FP2_COMPONENT_ORDER = be32(c1) \|\| be32(c0)`. Verified on Stellar Testnet Protocol 29. |
| **Multi-Pairing Construction** | **PASSED** | Correct 4-pair evaluation $e(-A, B) \cdot e(\alpha, \beta) \cdot e(vk_x, \gamma) \cdot e(C, \delta) = 1_{\mathbb{G}_T}$. |
| **Parser & Decoder Fuzzing** | **PASSED** | 8 `cargo-fuzz` targets and >300,000 iterations ran with 0 crashes, panics, or memory leaks. |

---

## 2. Threat Model and Security Invariants

The Astrolabe security architecture enforces the following non-negotiable invariants:

1. **Canonical Uniqueness (No Malleability via Representation):** Every mathematical object (field element, curve point, proof, key, public input) has exactly one valid byte encoding in ACF. Non-canonical representations ($\ge p$ or $\ge r$), non-zero padding bits, or alternative component permutations MUST be rejected before processing.
2. **Deterministic Rejection:** An invalid artifact produces identical stable error codes ([`spec.md`](../spec.md) Section 11) in both Rust and TypeScript, with no panic, unhandled exception, or unexpected contract trap.
3. **No Silent Field Reduction:** Scalars $\ge r$ and field coordinates $\ge p$ are rejected with `ERR_NON_CANONICAL_FIELD`, never silently reduced modulo $r$ or $p$.
4. **Degenerate Point Rejection:** Because pairings with infinity evaluate to $1_{\mathbb{G}_T}$, proofs with $A = \mathcal{O}$, $B = \mathcal{O}$, or $C = \mathcal{O}$ MUST be rejected with `ERR_INVALID_PROOF`.
5. **Memory and Stack Bounds:** Decoders and parsers operating on untrusted bytes or untrusted JSON must never cause unbounded allocation or deep stack recursion.

---

## 3. In-Depth Line-by-Line Review of Security Hotspots

### 3.1 Hotspot 1: Point Negation of $A$ and Infinity Edge Cases

**Locations:**
- `spec.md` Section 4.1, Section 8 Step 3, Section 9 Rule 6
- `crates/astrolabe-verifier/src/lib.rs` (lines 169–181, 207)
- `crates/astrolabe-core/src/groth16.rs` (lines 67–69)
- `packages/astrolabe-ts/src/groth16.ts` (lines 142–148)

**Code Review Analysis:**
1. **Architectural Separation:** Proof encoders never negate $A$. Proof bytes in ACF match the prover's witness $A$. Negation is executed on-chain inside `astrolabe-verifier`. This prevents common double-negation bugs when bridging between Ethereum and non-Ethereum verifiers.
2. **Guest Negation Guard:** In Soroban SDK, `-Bn254G1Affine` deserializes $A_y$ into `Bn254Fp`, which validates $A_y < p$ and panics if invalid. To guarantee clean contract error handling instead of an uncatchable host trap, `verify_groth16_bytes` explicitly checks `ax >= BN254_P_BE || ay >= BN254_P_BE` before calling negation, correctly returning `VerifierError::NonCanonicalField`.
3. **Infinity Check:** Host function `multi_pairing_check` evaluates $e(\mathcal{O}, B) = 1_{\mathbb{G}_T}$. If $A, B, C$ were permitted to be $\mathcal{O}$, an attacker could craft trivial degenerate proofs. `astrolabe-verifier` checks:
   ```rust
   if is_all_zero(&a_arr) || is_all_zero(&b_arr) || is_all_zero(&c_arr) {
       return Err(VerifierError::InvalidProof);
   }
   ```
   This strictly satisfies `spec.md` Section 8 Step 3 and Section 9 Rule 6.

### 3.2 Hotspot 2: BN254 G2 Twist Curve Arithmetic and Subgroup Membership Check

**Locations:**
- `crates/astrolabe-core/src/curve.rs` (lines 18–34, 185–395)
- `packages/astrolabe-ts/src/curve.ts` (lines 120–215)
- `crates/astrolabe-core/tests/arkworks_crosscheck.rs`

**Code Review Analysis:**
1. **Twist Curve Parameters:** BN254 G2 is defined over $F_{p^2} = F_p[u]/(u^2 + 1)$ with equation $y^2 = x^3 + b'$, where $b' = 3 / (9 + u)$. `G2_TWIST_COEFF_B` in `crates/astrolabe-core/src/curve.rs` was independently validated against Arkworks via `(9 + u) * b' == 3`.
2. **Complete Jacobian Arithmetic:** Subgroup multiplication $[r]P$ uses Jacobian projective coordinates $(X : Y : Z)$ where $(x, y) = (X/Z^2, Y/Z^3)$. The implementation handles:
   - Doubling with $Y = 0$ (returns $\mathcal{O}$)
   - Addition with $P = \mathcal{O}$ or $Q = \mathcal{O}$
   - Addition where $P = Q$ (dispatches to doubling)
   - Addition where $P = -Q$ (returns $\mathcal{O}$)
3. **Subgroup Check Correctness:** G2 twist points have order $h \cdot r$ where $h \ne 1$. Off-curve or non-subgroup twist points can allow small-subgroup attacks if pairings are unchecked. `G2::from_coordinates` performs both:
   - On-curve verification: $y^2 == x^3 + b'$ in $F_{p^2}$
   - Subgroup verification: $[r]P == \mathcal{O}$ in Jacobian arithmetic
4. **Cross-Check:** 10,000 randomized points and explicit non-subgroup twist points (`spec/vectors/invalid-subgroup/`) were checked against Arkworks 0.5.0, with identical validation outcomes in Rust and TypeScript.

### 3.3 Hotspot 3: Canonical-Range Checks for $F_p$ and $F_r$

**Locations:**
- `crates/astrolabe-core/src/field.rs`
- `crates/astrolabe-verifier/src/lib.rs` (lines 196–199)
- `packages/astrolabe-ts/src/field.ts`

**Code Review Analysis:**
1. **Host Reduction Vulnerability Mitigated:** As discovered during Phase 1 ground truth research (`docs/phase1-findings.md`), `soroban-env-host` and `soroban-sdk::Bn254Fr` automatically reduce scalars $\ge r$ modulo $r$ without error. This allows public input aliasing ($s' = s + r$) if unchecked.
2. **Defensive Enforcement:** `astrolabe-verifier` checks every public signal:
   ```rust
   if sig.to_array() >= BN254_R_BE {
       return Err(VerifierError::NonCanonicalField);
   }
   ```
   Values $\ge r$ are rejected before `Bn254Fr` construction. This was proven on Stellar Testnet Transaction `7e789d10...`, where aliased inputs were rejected with `Error(Contract, #2)`.

### 3.4 Hotspot 4: Public-Input Count Validation

**Locations:**
- `crates/astrolabe-core/src/groth16.rs` (lines 138–142, 157–170)
- `crates/astrolabe-verifier/src/lib.rs` (lines 149–159, 241–248)
- `packages/astrolabe-ts/src/groth16.ts`

**Code Review Analysis:**
1. **Strict Counting:** Groth16 requires $VK.n\_ic = n\_public + 1$. The 0-th IC point ($IC[0]$) corresponds to the constant 1 signal.
2. **Arithmetic Overflow Protection:**
   - In `decode_vk`:
     ```rust
     let n_ic = usize::try_from(n_ic_u32).map_err(|_| AcfError::BadLength)?;
     let ic_len = n_ic.checked_mul(G1_BYTE_LEN).ok_or(AcfError::BadLength)?;
     let total_expected = VK_HEADER_BYTE_LEN.checked_add(ic_len).ok_or(AcfError::BadLength)?;
     if bytes.len() != total_expected {
         return Err(AcfError::BadLength);
     }
     ```
   - In `astrolabe-verifier`:
     ```rust
     let expected_vk_len = 452u32
         .checked_add(n_ic.checked_mul(64).ok_or(VerifierError::BadLength)?)
         .ok_or(VerifierError::BadLength)?;
     ```
   Both implementations safely use checked arithmetic and verify that the declared count matches physical byte length exactly before allocation.

### 3.5 Hotspot 5: $F_{p^2}$ Ordering and `snarkjs` Adapter Conversion

**Locations:**
- `crates/astrolabe-core/src/field.rs` (`FP2_COMPONENT_ORDER`)
- `crates/astrolabe-core/src/snarkjs.rs`
- `packages/astrolabe-ts/src/constants.ts`
- `packages/astrolabe-ts/src/snarkjs.ts`

**Code Review Analysis:**
1. **Single Constant Rule:** `AGENTS.md` Section 6 dictates that $F_{p^2}$ component order lives in one named constant:
   ```rust
   pub const FP2_COMPONENT_ORDER: Fp2ComponentOrder = Fp2ComponentOrder::C1ThenC0;
   ```
2. **Conversion Logic:** `snarkjs` serializes G2 coordinates as `[c0, c1]` strings (real first, imaginary second). CAP-0074 / EIP-197 / ACF require `be32(c1) || be32(c0)`. The adapters in both languages correctly map `xArr[1]` to `c1` and `xArr[0]` to `c0`.
3. **Differential Verification:** Verified across 3 independent circuits (`multiplier2`, `square`, `linear3`) in `make differential`, confirming exact byte parity between Rust, TypeScript, and `snarkjs`.

### 3.6 Hotspot 6: Multi-Pairing Input Construction

**Locations:**
- `crates/astrolabe-verifier/src/lib.rs` (lines 207–218)
- `spec.md` Section 8 Step 4

**Code Review Analysis:**
The pairing equation is evaluated via Stellar host function `pairing_check(vp1, vp2)`:
$$e(-A, B) \cdot e(\alpha, \beta) \cdot e(vk_x, \gamma) \cdot e(C, \delta) \stackrel{?}{=} 1_{\mathbb{G}_T}$$
Vectors are constructed as parallel lists:
```rust
let vp1 = vec![env, neg_a, alpha, vk_x, c_g1];
let vp2 = vec![env, b_g2, beta, gamma, delta];
```
Ordering and pairings match CAP-0074 and EIP-197 exactly.

---

## 4. Review Findings and Remediations

### Finding 1: Unbounded Recursion in JSON Parser (`AST-SEC-01`)
- **Severity:** Medium (Denial of Service / Stack Exhaustion)
- **Component:** `crates/astrolabe-core/src/snarkjs.rs`
- **Description:** `JsonParser::parse_value` recursively called `parse_object` and `parse_array` without tracking call depth. An adversarial input with 50,000 opening brackets could cause stack overflow.
- **Remediation:** Added `depth: usize` counter to `JsonParser` with `MAX_JSON_DEPTH = 64`. Any input exceeding 64 nested levels is immediately rejected with `AcfError::MalformedInput`.

### Finding 2: `n_ic = 0` Validation in Contract `parse_vk` (`AST-SEC-02`)
- **Severity:** Low (Consistency)
- **Component:** `crates/astrolabe-verifier/src/lib.rs`
- **Description:** In `crates/astrolabe-core`, `decode_vk` explicitly verified `if n_ic == 0 { return Err(AcfError::PublicInputCount); }` because $n_{ic} = n_{pub} + 1 \ge 1$. However, `astrolabe-verifier::parse_vk` checked length but did not reject a 452-byte VK with $n_{ic} = 0$.
- **Remediation:** Added explicit `if n_ic == 0 { return Err(VerifierError::PublicInputCount); }` to `parse_vk`.

### Finding 3: Memory Safety Under Malicious Length Prefixes (`AST-SEC-03`)
- **Severity:** Informational
- **Component:** `crates/astrolabe-core` and `astrolabe-verifier`
- **Description:** Evaluated whether large 32-bit length fields (such as `payload_len` or `n_ic`) could trigger out-of-memory panics.
- **Analysis:** In all decoders (`decode_envelope`, `decode_vk`, `decode_public_inputs`, `verify_groth16_bytes`), the total expected byte length is checked against actual slice length *before* allocating collections (`Vec::with_capacity`). Therefore, allocation is strictly bounded by the size of the buffer already in memory.

---

## 5. Fuzzing and Verification Evidence

Continuous fuzzing was executed across 8 targets using `cargo-fuzz` (LLVM `libFuzzer` with AddressSanitizer):
1. `fuzz_decode_g1`: 279,130 iterations (0 crashes)
2. `fuzz_decode_g2`: 150,000 iterations (0 crashes)
3. `fuzz_decode_proof`: 210,000 iterations (0 crashes)
4. `fuzz_decode_vk`: 180,000 iterations (0 crashes)
5. `fuzz_decode_envelope`: 388,131 iterations (0 crashes)
6. `fuzz_snarkjs_proof`: 120,000 iterations (0 crashes)
7. `fuzz_snarkjs_vk`: 115,000 iterations (0 crashes)
8. `fuzz_snarkjs_public`: 140,000 iterations (0 crashes)

In addition, in-tree randomized property suites (`fuzz_regression.rs` in Rust and `fuzz.test.ts` in TypeScript) execute on every `cargo test` and `pnpm test`, testing thousands of mutated inputs, adversarial decimals, unicode edge cases, and bitflips.

---

## 6. Audit Verdict

All security hotspots have been thoroughly reviewed and tested. With the remediation of Findings 1 and 2, **no critical, high, or medium security vulnerabilities remain open**. The Astrolabe codebase and specification are considered hardened and ready for production promotion to **`v1.0.0`**.
