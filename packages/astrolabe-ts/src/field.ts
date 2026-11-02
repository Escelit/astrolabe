import {
  bigintToBytes32,
  bytes32ToBigint,
  concatBytes,
} from "./bytes.js";
import {
  BN254_P,
  BN254_R,
  FP_BYTE_LEN,
  FP2_BYTE_LEN,
  FR_BYTE_LEN,
  FP2_COMPONENT_ORDER,
  Fp2ComponentOrder,
} from "./constants.js";
import { AcfError } from "./errors.js";

/**
 * Canonical element of BN254 base field `Fp = Z/pZ` in `[0, p)`.
 */
export type Fp = bigint;

/**
 * Canonical element of BN254 scalar field `Fr = Z/rZ` in `[0, r)`.
 */
export type Fr = bigint;

/**
 * Element `c0 + c1·u` of the quadratic extension field `Fp2 = Fp[u]/(u^2 + 1)`.
 */
export interface Fp2 {
  readonly c0: Fp;
  readonly c1: Fp;
}

export const FP2_ZERO: Fp2 = { c0: 0n, c1: 0n };
export const FP2_ONE: Fp2 = { c0: 1n, c1: 0n };

// --- Fp Arithmetic ---

export function addFp(a: Fp, b: Fp): Fp {
  const sum = a + b;
  return sum >= BN254_P ? sum - BN254_P : sum;
}

export function doubleFp(a: Fp): Fp {
  return addFp(a, a);
}

export function subFp(a: Fp, b: Fp): Fp {
  return a >= b ? a - b : a + BN254_P - b;
}

export function negFp(a: Fp): Fp {
  return a === 0n ? 0n : BN254_P - a;
}

export function mulFp(a: Fp, b: Fp): Fp {
  return (a * b) % BN254_P;
}

export function squareFp(a: Fp): Fp {
  return (a * a) % BN254_P;
}

// --- Fp2 Arithmetic ---

export function isZeroFp2(a: Fp2): boolean {
  return a.c0 === 0n && a.c1 === 0n;
}

export function equalsFp2(a: Fp2, b: Fp2): boolean {
  return a.c0 === b.c0 && a.c1 === b.c1;
}

export function addFp2(a: Fp2, b: Fp2): Fp2 {
  return { c0: addFp(a.c0, b.c0), c1: addFp(a.c1, b.c1) };
}

export function doubleFp2(a: Fp2): Fp2 {
  return { c0: doubleFp(a.c0), c1: doubleFp(a.c1) };
}

export function subFp2(a: Fp2, b: Fp2): Fp2 {
  return { c0: subFp(a.c0, b.c0), c1: subFp(a.c1, b.c1) };
}

export function negFp2(a: Fp2): Fp2 {
  return { c0: negFp(a.c0), c1: negFp(a.c1) };
}

export function mulFp2(a: Fp2, b: Fp2): Fp2 {
  const a0b0 = mulFp(a.c0, b.c0);
  const a1b1 = mulFp(a.c1, b.c1);
  const c0 = subFp(a0b0, a1b1);
  const c1 = subFp(
    subFp(mulFp(addFp(a.c0, a.c1), addFp(b.c0, b.c1)), a0b0),
    a1b1,
  );
  return { c0, c1 };
}

export function squareFp2(a: Fp2): Fp2 {
  const c0 = mulFp(subFp(a.c0, a.c1), addFp(a.c0, a.c1));
  const c1 = doubleFp(mulFp(a.c0, a.c1));
  return { c0, c1 };
}

// --- Field Codecs ---

/**
 * Decodes and validates a canonical 32-byte big-endian `Fp` element
 * (ACF Spec Section 3.1 & Section 9 Rules 1-2).
 *
 * @throws {AcfError} `ERR_BAD_LENGTH` if `bytes.length !== 32`
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if value `>= p`
 */
export function decodeFp(bytes: Uint8Array): Fp {
  if (bytes.length !== FP_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  const val = bytes32ToBigint(bytes);
  if (val >= BN254_P) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  return val;
}

/**
 * Encodes a canonical `Fp` element into 32 big-endian bytes (`be32`, ACF Spec Section 3.1).
 */
export function encodeFp(val: Fp): Uint8Array {
  if (val < 0n || val >= BN254_P) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  return bigintToBytes32(val);
}

/**
 * Decodes and validates a canonical 32-byte big-endian `Fr` scalar
 * (ACF Spec Section 3.1, Section 3.4 & Section 9 Rules 1-2).
 *
 * Values `>= r` are rejected, NEVER silently reduced.
 *
 * @throws {AcfError} `ERR_BAD_LENGTH` if `bytes.length !== 32`
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if value `>= r`
 */
export function decodeFr(bytes: Uint8Array): Fr {
  if (bytes.length !== FR_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  const val = bytes32ToBigint(bytes);
  if (val >= BN254_R) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  return val;
}

/**
 * Encodes a canonical `Fr` scalar into 32 big-endian bytes (`be32`, ACF Spec Section 3.1 & 3.4).
 */
export function encodeFr(val: Fr): Uint8Array {
  if (val < 0n || val >= BN254_R) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  return bigintToBytes32(val);
}

/**
 * Decodes a 64-byte `Fp2` coordinate using the single named constant `FP2_COMPONENT_ORDER`
 * (ACF Spec Section 3.3 and Section 9 Rules 1-2).
 */
export function decodeFp2(bytes: Uint8Array): Fp2 {
  if (bytes.length !== FP2_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  const first = decodeFp(bytes.subarray(0, 32));
  const second = decodeFp(bytes.subarray(32, 64));

  // Security hotspot: single central switch on `FP2_COMPONENT_ORDER`.
  switch (FP2_COMPONENT_ORDER) {
    case Fp2ComponentOrder.C1ThenC0:
      return { c0: second, c1: first };
    case Fp2ComponentOrder.C0ThenC1:
      return { c0: first, c1: second };
  }
}

/**
 * Encodes an `Fp2` coordinate into 64 bytes using the single named constant `FP2_COMPONENT_ORDER`
 * (ACF Spec Section 3.3).
 */
export function encodeFp2(val: Fp2): Uint8Array {
  const enc0 = encodeFp(val.c0);
  const enc1 = encodeFp(val.c1);

  // Security hotspot: single central switch on `FP2_COMPONENT_ORDER`.
  switch (FP2_COMPONENT_ORDER) {
    case Fp2ComponentOrder.C1ThenC0:
      return concatBytes(enc1, enc0);
    case Fp2ComponentOrder.C0ThenC1:
      return concatBytes(enc0, enc1);
  }
}
