/**
 * Canonical BN254 constants and layout parameters (ACF Specification Sections 2 & 3).
 */

/**
 * BN254 base field modulus `p` (ACF Spec Section 2).
 * `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`
 */
export const BN254_P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;

/**
 * BN254 scalar field modulus (group order) `r` (ACF Spec Section 2).
 * `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
 */
export const BN254_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Canonical byte length of an encoded `Fp` element (ACF Spec Section 3.1).
 */
export const FP_BYTE_LEN = 32;

/**
 * Canonical byte length of an encoded `Fr` scalar (ACF Spec Section 3.1 & 3.4).
 */
export const FR_BYTE_LEN = 32;

/**
 * Canonical byte length of an encoded `Fp2` coordinate (ACF Spec Section 3.3).
 */
export const FP2_BYTE_LEN = 64;

/**
 * Canonical byte length of an uncompressed `G1` point (ACF Spec Section 3.2).
 */
export const G1_BYTE_LEN = 64;

/**
 * Canonical byte length of an uncompressed `G2` point (ACF Spec Section 3.3).
 */
export const G2_BYTE_LEN = 128;

/**
 * Wire component ordering for `Fp2` coordinates inside `G2` points (ACF Spec Section 3.3).
 */
export enum Fp2ComponentOrder {
  /**
   * Imaginary component first, real component second (`be32(c1) || be32(c0)`),
   * matching CAP-0074 and Ethereum EIP-197 (ACF Spec Section 3.3).
   */
  C1ThenC0 = "c1_c0",
  /**
   * Real component first, imaginary component second (`be32(c0) || be32(c1)`).
   */
  C0ThenC1 = "c0_c1",
}

/**
 * Single named constant defining `Fp2` wire component ordering for ACF v0.1
 * (ACF Specification Section 3.3; verified in Phase 1 against CAP-0074,
 * `soroban-sdk 29.0.1`, and Stellar Testnet TX 3d5683f2...).
 */
export const FP2_COMPONENT_ORDER: Fp2ComponentOrder =
  Fp2ComponentOrder.C1ThenC0;

/**
 * Curve constant `b = 3` for BN254 `G1: y^2 = x^3 + 3` over `Fp` (ACF Spec Section 2).
 */
export const G1_COEFF_B = 3n;

/**
 * Twist curve constant `b' = 3 / (9 + u)` for BN254 `G2: y^2 = x^3 + b'` over `Fp2`
 * (CAP-0074 / Ethereum EIP-197 D-twist; cross-checked against `ark_bn254::g2::Config::COEFF_B`
 * and verified via `(9 + u) * b' == 3`).
 */
export const G2_TWIST_COEFF_B = {
  c0: 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5n,
  c1: 0x009713b03af0fed4cd2cafadeed8fdf4a74fa084e52d1852e4a2bd0685c315d2n,
} as const;
