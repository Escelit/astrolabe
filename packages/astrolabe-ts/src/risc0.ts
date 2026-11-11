/**
 * RISC Zero Groth16 adapter conforming to ACF Spec Section 10.3.
 *
 * Converts RISC Zero Groth16 receipts (256-byte seal, image ID, and journal digest)
 * into canonical ACF [`Proof`] and [`PublicInputs`] objects.
 */

import { BN254_R } from "./constants.js";
import { ArtifactKind, Envelope } from "./envelope.js";
import { AcfError } from "./errors.js";
import { decodeProof, Proof, PublicInputs } from "./groth16.js";
import { hexToBytes } from "./bytes.js";

/**
 * Mapping scheme for converting RISC Zero `image_id` and `journal_digest` into [`PublicInputs`].
 */
export type Risc0PublicInputsMode = "limb16" | "direct";

/**
 * Parsed and validated RISC Zero Groth16 receipt.
 */
export interface Risc0Receipt {
  proof: Proof;
  publicInputs: PublicInputs;
  imageId: Uint8Array;
  journalDigest: Uint8Array;
}

function stringToUtf8(str: string): Uint8Array {
  const utf8: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) {
      utf8.push(charcode);
    } else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    } else {
      i++;
      charcode =
        0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f),
      );
    }
  }
  return new Uint8Array(utf8);
}

/**
 * Computes standard NIST SHA-256 of bytes. Pure TypeScript implementation for browser/node portability.
 */
export function sha256(data: Uint8Array | string): Uint8Array {
  const bytes = typeof data === "string" ? stringToUtf8(data) : data;
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
  ];

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const bitLen = BigInt(bytes.length) * 8n;
  const paddingLen = (bytes.length % 64 < 56) ? 56 - (bytes.length % 64) : 120 - (bytes.length % 64);
  const totalLen = bytes.length + paddingLen + 8;
  const buf = new Uint8Array(totalLen);
  buf.set(bytes, 0);
  buf[bytes.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setBigUint64(totalLen - 8, bitLen);

  const w = new Uint32Array(64);
  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4);
    }
    for (let i = 16; i < 64; i++) {
      const w15 = w[i - 15]!;
      const s0 = ((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3);
      const w2 = w[i - 2]!;
      const s1 = ((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    let f = h5;
    let g = h6;
    let h = h7;

    for (let i = 0; i < 64; i++) {
      const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + s1 + ch + K[i]! + w[i]!) >>> 0;
      const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;

      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, h0);
  outView.setUint32(4, h1);
  outView.setUint32(8, h2);
  outView.setUint32(12, h3);
  outView.setUint32(16, h4);
  outView.setUint32(20, h5);
  outView.setUint32(24, h6);
  outView.setUint32(28, h7);
  return out;
}

function parseBytes32(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") {
    const clean = input.startsWith("0x") || input.startsWith("0X") ? input.slice(2) : input;
    if (clean.length !== 64 || !/^[0-9a-fA-F]+$/.test(clean)) {
      throw new AcfError("ERR_MALFORMED_INPUT");
    }
    return hexToBytes(clean);
  }
  if (input instanceof Uint8Array && input.length === 32) {
    return input;
  }
  throw new AcfError("ERR_BAD_LENGTH");
}

/**
 * Maps a 256-byte RISC Zero Groth16 seal into a canonical [`Proof`].
 */
export function mapRisc0Seal(seal: Uint8Array | string): Proof {
  const bytes = typeof seal === "string"
    ? hexToBytes(seal.startsWith("0x") || seal.startsWith("0X") ? seal.slice(2) : seal)
    : seal;
  if (bytes.length !== 256) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  return decodeProof(bytes);
}

/**
 * Maps RISC Zero `image_id` and `journal_digest` into canonical [`PublicInputs`].
 */
export function mapRisc0JournalAndImageId(
  imageId: Uint8Array | string,
  journalDigest: Uint8Array | string,
  mode: Risc0PublicInputsMode = "limb16",
): PublicInputs {
  const idBytes = parseBytes32(imageId);
  const jdBytes = parseBytes32(journalDigest);

  if (mode === "limb16") {
    // 4-scalar representation
    const limb0Bytes = new Uint8Array(32);
    const limb1Bytes = new Uint8Array(32);
    const limb2Bytes = new Uint8Array(32);
    const limb3Bytes = new Uint8Array(32);

    limb0Bytes.set(idBytes.subarray(0, 16), 16);
    limb1Bytes.set(idBytes.subarray(16, 32), 16);
    limb2Bytes.set(jdBytes.subarray(0, 16), 16);
    limb3Bytes.set(jdBytes.subarray(16, 32), 16);

    const s0 = bytesToBigInt(limb0Bytes);
    const s1 = bytesToBigInt(limb1Bytes);
    const s2 = bytesToBigInt(limb2Bytes);
    const s3 = bytesToBigInt(limb3Bytes);

    return new PublicInputs([s0, s1, s2, s3]);
  } else {
    // 2-scalar direct representation
    const s0 = bytesToBigInt(idBytes);
    const s1 = bytesToBigInt(jdBytes);
    if (s0 >= BN254_R || s1 >= BN254_R) {
      throw new AcfError("ERR_NON_CANONICAL_FIELD");
    }
    return new PublicInputs([s0, s1]);
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += (bytes[i]! < 16 ? "0" : "") + bytes[i]!.toString(16);
  }
  return BigInt(`0x${hex}`);
}

function parseJsonValue(input: string | unknown): unknown {
  if (typeof input === "string") {
    try {
      return JSON.parse(input);
    } catch {
      throw new AcfError("ERR_MALFORMED_INPUT");
    }
  }
  return input;
}

/**
 * Parses a RISC Zero Groth16 receipt JSON artifact into a [`Risc0Receipt`].
 */
export function parseRisc0Receipt(
  input: string | unknown,
  mode: Risc0PublicInputsMode = "limb16",
): Risc0Receipt {
  const root = parseJsonValue(input);
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const obj = root as Record<string, unknown>;

  // 1. Extract seal
  let sealVal: unknown = obj.seal;
  if (!sealVal && obj.inner && typeof obj.inner === "object") {
    const inner = obj.inner as Record<string, unknown>;
    if (inner.Groth16 && typeof inner.Groth16 === "object") {
      sealVal = (inner.Groth16 as Record<string, unknown>).seal;
    }
  }
  if (!sealVal) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  let sealBytes: Uint8Array;
  if (typeof sealVal === "string") {
    const clean = sealVal.startsWith("0x") || sealVal.startsWith("0X") ? sealVal.slice(2) : sealVal;
    sealBytes = hexToBytes(clean);
  } else if (Array.isArray(sealVal)) {
    sealBytes = new Uint8Array(sealVal);
  } else {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const proof = mapRisc0Seal(sealBytes);

  // 2. Extract imageId
  let idVal: unknown = obj.image_id ?? obj.imageId;
  if (!idVal && obj.post && typeof obj.post === "object") {
    const claim = (obj.post as Record<string, unknown>).claim;
    if (claim && typeof claim === "object") {
      idVal = (claim as Record<string, unknown>).image_id;
    }
  }
  if (!idVal) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const imageId = parseBytes32(
    typeof idVal === "string" ? idVal : new Uint8Array(idVal as number[]),
  );

  // 3. Extract journal or journalDigest
  let journalDigest: Uint8Array;
  const jdVal = obj.journal_digest ?? obj.journalDigest;
  if (jdVal) {
    journalDigest = parseBytes32(
      typeof jdVal === "string" ? jdVal : new Uint8Array(jdVal as number[]),
    );
  } else if (obj.journal) {
    if (typeof obj.journal === "string") {
      const clean = obj.journal.startsWith("0x") || obj.journal.startsWith("0X")
        ? obj.journal.slice(2)
        : obj.journal;
      if (clean.length === 64) {
        journalDigest = hexToBytes(clean);
      } else {
        journalDigest = sha256(hexToBytes(clean));
      }
    } else if (Array.isArray(obj.journal)) {
      journalDigest = sha256(new Uint8Array(obj.journal));
    } else {
      throw new AcfError("ERR_MALFORMED_INPUT");
    }
  } else {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const publicInputs = mapRisc0JournalAndImageId(imageId, journalDigest, mode);

  return {
    proof,
    publicInputs,
    imageId,
    journalDigest,
  };
}

/**
 * Parses a RISC Zero Groth16 seal JSON and wraps it in a canonical [`Envelope`].
 */
export function parseRisc0ProofEnvelope(
  input: string | unknown,
  mode: Risc0PublicInputsMode = "limb16",
): Envelope {
  const receipt = parseRisc0Receipt(input, mode);
  return new Envelope({
    kind: ArtifactKind.Proof,
    data: receipt.proof,
  });
}

/**
 * Parses a RISC Zero Groth16 receipt JSON and wraps the public inputs in a canonical [`Envelope`].
 */
export function parseRisc0PublicInputsEnvelope(
  input: string | unknown,
  mode: Risc0PublicInputsMode = "limb16",
): Envelope {
  const receipt = parseRisc0Receipt(input, mode);
  return new Envelope({
    kind: ArtifactKind.PublicInputs,
    data: receipt.publicInputs,
  });
}
