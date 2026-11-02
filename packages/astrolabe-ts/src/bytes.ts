import { AcfError } from "./errors.js";

/**
 * Checks whether all bytes in the given buffer are zero.
 */
export function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b !== undefined && b !== 0) {
      return false;
    }
  }
  return true;
}

/**
 * Encodes an unsigned bigint into a 32-byte big-endian buffer (`be32`, ACF Spec Section 2).
 */
export function bigintToBytes32(n: bigint): Uint8Array {
  if (n < 0n || n >= 1n << 256n) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  const out = new Uint8Array(32);
  let cur = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(cur & 0xffn);
    cur >>= 8n;
  }
  return out;
}

/**
 * Decodes a 32-byte big-endian buffer into an unsigned bigint (`be32`, ACF Spec Section 2).
 */
export function bytes32ToBigint(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  let n = 0n;
  for (let i = 0; i < 32; i++) {
    const b = bytes[i];
    if (b === undefined) {
      throw new AcfError("ERR_BAD_LENGTH");
    }
    n = (n << 8n) | BigInt(b);
  }
  return n;
}

/**
 * Concatenates multiple byte arrays into a single Uint8Array.
 */
export function concatBytes(...arrays: readonly Uint8Array[]): Uint8Array {
  let totalLen = 0;
  for (const arr of arrays) {
    totalLen += arr.length;
  }
  const out = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

/**
 * Converts a byte array to lowercase hex without 0x prefix (ACF Spec Section 6).
 */
export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b !== undefined) {
      s += b.toString(16).padStart(2, "0");
    }
  }
  return s;
}

/**
 * Converts a lowercase hex string (without 0x prefix) to a Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^([0-9a-f]{2})*$/.test(hex)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
