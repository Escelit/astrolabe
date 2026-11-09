# Core Concepts & Security Architecture

This guide explains how Groth16 verification over BN254 works on Stellar Soroban (Protocol 25+), why naive conversions from `snarkjs` fail or introduce subtle vulnerabilities, and how Astrolabe enforces strict end-to-end validation.

---

## 1. BN254 Host Functions in Stellar Protocol 25+ (CAP-0074)

Stellar Protocol 25 introduced native host functions for the pairing-friendly curve **BN254** (also known as `alt_bn128` in Ethereum EIP-196/197 and `bn128` in Circom/`snarkjs`), exposed in `soroban-sdk` under `soroban_sdk::crypto::bn254`:

| Host Operation | `soroban-sdk` Method | Purpose in Groth16 Verification |
| -------------- | -------------------- | ------------------------------- |
| `bn254_g1_add` | `bn254.g1_add(&p0, &p1)` | Adds two affine points on $G_1$ ($y^2 = x^3 + 3$ over $\mathbb{F}_p$) |
| `bn254_g1_mul` | `bn254.g1_mul(&p0, &scalar)` | Multiplies a $G_1$ point by a scalar in $\mathbb{F}_r$ |
| `bn254_g1_msm` | `bn254.g1_msm(points, scalars)` | Multi-scalar multiplication in $G_1$ |
| `bn254_multi_pairing_check` | `bn254.pairing_check(vp1, vp2)` | Checks whether $\prod_i e(P_i, Q_i) = 1_{G_T}$ |

---

## 2. The Groth16 Verification Algorithm on Soroban

A Groth16 proof consists of three curve points:
- $A \in G_1$ (64 bytes)
- $B \in G_2$ (128 bytes)
- $C \in G_1$ (64 bytes)

A verification key ($VK$) consists of:
- $\alpha \in G_1$, $\beta \in G_2$, $\gamma \in G_2$, $\delta \in G_2$
- $IC_0, IC_1, \dots, IC_n \in G_1$ (where $n$ is the number of public inputs, so $n_{ic} = n + 1$)

Given public inputs $s_1, \dots, s_n \in \mathbb{F}_r$, the prover claims that:

$$e(A, B) = e(\alpha, \beta) \cdot e\left(IC_0 + \sum_{i=1}^{n} s_i \cdot IC_i,\ \gamma\right) \cdot e(C, \delta)$$

Because Soroban provides a single multi-pairing check that tests whether a product of pairings equals the identity $1 \in G_T$, Astrolabe rewrites the equation using bilinearity ($e(A, B)^{-1} = e(-A, B)$):

$$e(-A, B) \cdot e(\alpha, \beta) \cdot e(\text{vk\_x}, \gamma) \cdot e(C, \delta) = 1_{G_T}$$

where:
1. $\text{vk\_x} = IC_0 + \sum_{i=1}^{n} s_i \cdot IC_i$
2. $-A = (A.x,\ p - A.y \bmod p)$

> **Design Rule (`spec/spec.md` Section 4.1):** Off-chain encoders **never** negate $A$. Proof bytes in ACF match the prover's actual point $A$, and negation is performed by the verifier in Step 3 (`spec/spec.md` Section 8).

---

## 3. Why Raw Toolchain Outputs Fail Without an Adapter

Converting `snarkjs` outputs to Soroban by hand is a frequent source of bugs:

### 3.1 `G2` Quadratic Extension ($\mathbb{F}_{p^2}$) Component Order
Elements of $\mathbb{F}_{p^2} = \mathbb{F}_p[u]/(u^2 + 1)$ are written $c_0 + c_1 \cdot u$, where $c_0$ is the real part and $c_1$ is the imaginary part.
- **`snarkjs` JSON** lists coordinates as `[c0, c1]` (`[real, imaginary]`).
- **CAP-0074 / EIP-197 / ACF** requires `be32(c1) || be32(c0)` (`imaginary || real`).

Passing `snarkjs` coordinates in `[c0, c1]` order into Soroban causes `bn254_multi_pairing_check` to trap immediately with `HostError: Error(Crypto, InvalidInput) ("bn254 G2: point not on curve")`. Astrolabe holds this ordering in a single named constant (`FP2_COMPONENT_ORDER = C1ThenC0`) and swaps the components automatically during `snarkjs` parsing.

### 3.2 Homogeneous Projective Coordinates in `snarkjs`
`snarkjs` serializes affine points as length-3 projective arrays (`[x, y, "1"]` for $G_1$ and `[[x0, x1], [y0, y1], ["1", "0"]]` for $G_2$). Astrolabe verifies that the projective $Z$ coordinate is `"1"` (or `["1", "0"]`)—or normalizes canonical infinity representations—and emits compact 64-byte ($G_1$) and 128-byte ($G_2$) uncompressed affine points.

### 3.3 Public Signal Ordering (`public.json`)
In Circom, a circuit's `public.json` orders **public outputs first**, followed by **public inputs**, in declaration order. For example, in `Multiplier2` (`c <== a * b` with `public [a]`), `public.json` is `[c, a] = ["33", "3"]`. Swapping the order of `public.json` causes the pairing check to evaluate to `false` (`ERR_INVALID_PROOF`).

---

## 4. Critical Security Invariants

Astrolabe was designed around five empirical security findings confirmed on Stellar Testnet (documented in [`docs/phase1-findings.md`](phase1-findings.md)):

### 4.1 Preventing Public-Input Scalar Aliasing (`s >= r`)
**The hazard:** Both `soroban-sdk`'s `Bn254Fr` (`From<U256>`, `from_bytes`, `TryFromVal`) and `soroban-env-host`'s `bn254_g1_mul` **silently reduce scalars $\ge r$ modulo $r$ without trapping**. If a contract accepts `Bn254Fr` directly in its entrypoint or fails to check `< r`, an attacker can take a valid proof for public input $s$ (e.g., a nullifier hash) and submit $s + r < 2^{256}$ as a "new" public input—and the pairing check will still return `true`!

**How Astrolabe protects you:**
- Verifier entrypoints accept `Vec<BytesN<32>>` (never `Vec<Bn254Fr>`).
- Both off-chain validators (`astrolabe-core`, `astrolabe-ts`) and on-chain verifiers (`astrolabe-verifier`) check `scalar_bytes < BN254_R_BE` and reject values $\ge r$ with `ERR_NON_CANONICAL_FIELD`.

### 4.2 Rejecting Degenerate Infinity Proofs ($A, B, \text{or } C = \mathcal{O}$)
**The hazard:** In CAP-0074, the point at infinity is represented as all-zero bytes (`[0u8; 64]` for $G_1$, `[0u8; 128]` for $G_2$). `bn254_multi_pairing_check` accepts infinity points without trapping and treats any pair containing infinity as $1 \in G_T$. Furthermore, negating `[0u8; 64]` in guest WASM returns `[0u8; 64]`.

**How Astrolabe protects you:**
- Off-chain decoders (`decode_proof`) and on-chain verifiers (`verify_groth16_bytes`) explicitly reject any proof where $A$, $B$, or $C$ is infinity (`ERR_INVALID_PROOF`).

### 4.3 Validating $A.x < p$ and $A.y < p$ Before Guest Negation
**The hazard:** In `soroban-sdk`, `-Bn254G1Affine` constructs a `Bn254Fp` in guest WASM, which panics with `"Bn254: Invalid Fp"` if $A.y \ge p$.

**How Astrolabe protects you:**
- `astrolabe-verifier` validates $A.x < p$ and $A.y < p$ before negating $A$, returning a deterministic `VerifierError::NonCanonicalField` (`ERR_NON_CANONICAL_FIELD`) instead of an untyped guest panic.

### 4.4 Mandatory $G_2$ Subgroup Checks
The BN254 twist curve $E'(\mathbb{F}_{p^2})$ has a large cofactor. Points on the twist curve that lie outside the prime-order-$r$ subgroup can be exploited in pairing systems if unchecked.
- Both `astrolabe-core` (Rust `no_std`) and `astrolabe-ts` (TypeScript) verify the twist curve equation $y^2 = x^3 + 3/(9 + u)$ (`ERR_NOT_ON_CURVE`) **and** verify $[r]P = \mathcal{O}$ (`ERR_NOT_IN_SUBGROUP`) on every non-infinity $G_2$ point.
- The Soroban host also enforces both checks during `bn254_multi_pairing_check`.

### 4.5 Proof Malleability and Replay Protection
Groth16 proofs are malleable: anyone who sees a valid proof $(A, B, C)$ can re-randomize it into a distinct valid proof $(A', B', C')$ for the same public inputs, or replay the same proof in another transaction.
- **Application rule (`spec/spec.md` Section 8 & 14):** Your circuit and contract **must** bind transaction context—such as the recipient `Address`, a unique nullifier or nonce, the contract ID, or the network—into the public inputs. Never use the raw proof bytes as a uniqueness key.

### 4.6 Trusted Setup Provenance and BN254 Security Margin
- **Trusted setup:** Groth16 relies on a circuit-specific trusted setup (Phase 1 Powers-of-Tau + Phase 2 `.zkey`). If the setup was generated by a single party without destroying the toxic waste, fake proofs can be forged. Always use a verifiable multi-party ceremony for production contracts.
- **BN254 security level:** Due to extended tower number field sieve (exTNFS) advances, BN254 provides roughly ~100 bits of classical security rather than 128 bits. High-value applications should document this assumption.

---

## 5. Baked-in vs. Stored Verification Keys

`astrolabe gen-verifier` supports two contract architectures:

| Mode | Flag | How It Works | Best For |
| ---- | ---- | ------------ | -------- |
| **Baked** *(default)* | `--mode baked` | Embeds `pub const VK_BYTES: [u8; N]` directly in the compiled WASM binary and calls `verify_groth16_slice`. | Production circuits with a fixed verification key; lowest ledger footprint and zero storage reads per verification. |
| **Stored** | `--mode stored` | Stores the verification key in Soroban instance storage (`initialize`, `set_vk`, `get_vk`, `verify`) governed by an `admin: Address`. | Development, staging, or upgradable circuits where an admin needs to rotate the verification key without redeploying WASM. |
