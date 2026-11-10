# Astrolabe Canonical Format (`acf/1.0`) Reference

This document provides a concise developer reference for the **Astrolabe Canonical Format (`acf/1.0`)**. The normative specification is [`spec/spec.md`](spec.md).

---

## 1. Cryptographic Parameters (`spec/spec.md` Section 2)

All multi-byte integers and field elements are encoded as **unsigned big-endian** byte sequences (`be32`).

| Parameter | Symbol | Decimal / Hex Value |
| --------- | ------ | ------------------- |
| **Base field modulus** ($\mathbb{F}_p$) | $p$ | Dec: `21888242871839275222246405745257275088696311157297823662689037894645226208583`<br>Hex: `0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47` |
| **Scalar field modulus / group order** ($\mathbb{F}_r$) | $r$ | Dec: `21888242871839275222246405745257275088548364400416034343698204186575808495617`<br>Hex: `0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001` |
| **$G_1$ curve equation** over $\mathbb{F}_p$ | $E(\mathbb{F}_p)$ | $y^2 = x^3 + 3$ (cofactor $= 1$) |
| **Quadratic extension** | $\mathbb{F}_{p^2}$ | $\mathbb{F}_p[u]/(u^2 + 1)$, elements written $c_0 + c_1 \cdot u$ |
| **$G_2$ twist curve equation** over $\mathbb{F}_{p^2}$ | $E'(\mathbb{F}_{p^2})$ | $y^2 = x^3 + \frac{3}{9 + u}$ (prime-order-$r$ subgroup checked) |

> **Flag bits:** Because $p, r < 2^{254}$, the top two bits (`0x80 | 0x40`) of byte `0` of every canonical 32-byte `Fp` or `Fr` element are always `0`. Both ACF validators and the Soroban host reject points with arkworks compression/infinity flag bits set.

---

## 2. Primitive Encodings (`spec/spec.md` Section 3)

### 2.1 Field Elements (`Fp` and `Fr` — 32 bytes)

```text
+----------------------------------+
|          be32(value)             |
|            32 bytes              |
+----------------------------------+
```
- `Fp`: $0 \le x < p$. Values $\ge p$ are rejected with `ERR_NON_CANONICAL_FIELD`.
- `Fr`: $0 \le s < r$. Values $\ge r$ are rejected with `ERR_NON_CANONICAL_FIELD` (never reduced modulo $r$).

### 2.2 $G_1$ Affine Point (64 bytes)

```text
Byte offset:  0                 32                64
              +-----------------+-----------------+
              |     be32(x)     |     be32(y)     |
              +-----------------+-----------------+
```
- **Point at infinity ($\mathcal{O}_{G_1}$):** 64 zero bytes (`[0u8; 64]`).
- **Validation:** Both $x, y < p$ (`ERR_NON_CANONICAL_FIELD`), and if not all-zero, $y^2 \equiv x^3 + 3 \pmod p$ (`ERR_NOT_ON_CURVE`).

### 2.3 $G_2$ Affine Point (128 bytes)

```text
Byte offset:  0                 32                64                96               128
              +-----------------+-----------------+-----------------+-----------------+
              |   be32(x.c1)    |   be32(x.c0)    |   be32(y.c1)    |   be32(y.c0)    |
              |  (x imaginary)  |    (x real)     |  (y imaginary)  |    (y real)     |
              +-----------------+-----------------+-----------------+-----------------+
```
- **Component ordering (`FP2_COMPONENT_ORDER`):** Imaginary component `c1` first, real component `c0` second—matching Ethereum EIP-197 and Stellar CAP-0074.
- **Point at infinity ($\mathcal{O}_{G_2}$):** 128 zero bytes (`[0u8; 128]`).
- **Validation:**
  1. All four coordinates $< p$ (`ERR_NON_CANONICAL_FIELD`).
  2. Twist curve equation $y^2 = x^3 + 3/(9+u)$ in $\mathbb{F}_{p^2}$ (`ERR_NOT_ON_CURVE`).
  3. Subgroup membership $[r]P = \mathcal{O}_{G_2}$ (`ERR_NOT_IN_SUBGROUP`).

---

## 3. Groth16 Object Layouts (`spec/spec.md` Section 4)

### 3.1 `Proof` (Fixed 256 bytes)

```text
Byte offset:  0                64                         192               256
              +----------------+--------------------------+------------------+
              |    A (G1)      |          B (G2)          |      C (G1)      |
              |   64 bytes     |        128 bytes         |     64 bytes     |
              +----------------+--------------------------+------------------+
```
- **No off-chain negation:** $A$ is stored as emitted by the prover. On-chain verifiers compute $-A = (A.x, p - A.y)$.
- **Degenerate point rule:** None of $A$, $B$, or $C$ may be the point at infinity (`ERR_INVALID_PROOF`).

### 3.2 `VerificationKey` (`452 + 64 * n_ic` bytes)

```text
Byte offset:  0          64         192         320        448       452                 452 + 64*n_ic
              +----------+----------+-----------+----------+---------+-------------------+
              | alpha_g1 | beta_g2  | gamma_g2  | delta_g2 |  n_ic   | IC[0] ... IC[n-1] |
              | 64B (G1) | 128B(G2) | 128B (G2) | 128B(G2) | 4B(u32) |  64B (G1) each    |
              +----------+----------+-----------+----------+---------+-------------------+
```
- `n_ic` is a 4-byte unsigned big-endian integer (`be32_u32(n_ic)`), where `n_ic = n_public + 1 >= 1`.
- For a circuit with 2 public signals (such as `Multiplier2`), `n_ic = 3` and the total `VerificationKey` size is `452 + 3 * 64 = 644` bytes.

### 3.3 `PublicInputs` (`32 * n_public` bytes)

```text
Byte offset:  0                32               64              32 * n_public
              +----------------+----------------+---------------+
              |   be32(s_0)    |   be32(s_1)    |      ...      |
              |  32B (Fr < r)  |  32B (Fr < r)  |               |
              +----------------+----------------+---------------+
```
- Every scalar $s_i$ must satisfy $0 \le s_i < r$ (`ERR_NON_CANONICAL_FIELD`).
- When paired with a `VerificationKey`, `n_public` must equal `VK.n_ic - 1` (`ERR_PUBLIC_INPUT_COUNT`).

---

## 4. Artifact Envelope (`spec/spec.md` Section 5)

For file storage and transport, ACF payloads can be wrapped in a 12-byte self-describing binary header (`.astr`):

```text
Byte offset:  0        4          5      6       7        8             12            12 + len
              +--------+----------+------+-------+--------+-------------+---------------+
              | magic  | spec_ver | kind | curve | system | payload_len |    payload    |
              | "ASTR" |   0x01   |  1B  | 0x01  |  0x01  |  4B (u32)   | payload_len B |
              +--------+----------+------+-------+--------+-------------+---------------+
```

| Header Field | Offset | Size | Valid Values (`acf/0.1`) | Error on Mismatch |
| ------------ | ------ | ---- | ------------------------ | ----------------- |
| `magic` | `0..4` | 4B | `0x41 0x53 0x54 0x52` (ASCII `"ASTR"`) | `ERR_UNSUPPORTED` |
| `spec_ver` | `4` | 1B | `0x01` | `ERR_UNSUPPORTED` |
| `kind` | `5` | 1B | `0x01` (`Proof`), `0x02` (`VerificationKey`), `0x03` (`PublicInputs`) | `ERR_UNSUPPORTED` |
| `curve` | `6` | 1B | `0x01` (`BN254`) *(Reserved: `0x02` `BLS12-381`)* | `ERR_UNSUPPORTED` |
| `system` | `7` | 1B | `0x01` (`Groth16`) *(Reserved: `0x02` `PLONK`, `0x03` `UltraHonk`)* | `ERR_UNSUPPORTED` |
| `payload_len` | `8..12` | 4B | Big-endian `u32` byte length of `payload` | `ERR_BAD_LENGTH` / `ERR_TRAILING_BYTES` |

---

## 5. Canonical JSON Form (`spec/spec.md` Section 6)

Each envelope has a deterministic UTF-8 JSON representation (keys in exact order, lowercase hex without `0x`, LF newlines, single trailing newline):

```json
{
  "acf": "0.1",
  "kind": "proof",
  "curve": "bn254",
  "system": "groth16",
  "hex": "<lowercase hex of raw payload>"
}
```
Allowed `"kind"` strings: `"proof"`, `"verification_key"`, `"public_inputs"`.

---

## 6. Soroban Type Mapping (`spec/spec.md` Section 7)

| ACF Artifact / Primitive | Contract Entrypoint Type | Host Crypto Type (`soroban_sdk::crypto::bn254`) |
| ------------------------ | ------------------------ | ----------------------------------------------- |
| `Fp` (32 bytes) | `BytesN<32>` | `Bn254Fp` |
| `Fr` / Public Signal (32 bytes) | `BytesN<32>` *(checked `< r` first!)* | `Bn254Fr` |
| `G1` (64 bytes) | `BytesN<64>` | `Bn254G1Affine` |
| `G2` (128 bytes) | `BytesN<128>` | `Bn254G2Affine` |
| `Proof` (256 bytes) | `BytesN<256>` (or `Groth16Proof`) | Decomposed into `a`, `b`, `c` |
| `VerificationKey` (`452 + 64*n_ic` B) | `Bytes` / `[u8; N]` (or `Groth16Vk`) | Decomposed into `alpha`, `beta`, `gamma`, `delta`, `ic` |
| `PublicInputs` (`32*n` B) | `Vec<BytesN<32>>` | Converted element-by-element after `< r` check |
