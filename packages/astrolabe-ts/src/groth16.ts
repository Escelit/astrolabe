import { concatBytes } from "./bytes.js";
import {
  FR_BYTE_LEN,
  G1_BYTE_LEN,
  PROOF_BYTE_LEN,
  VK_HEADER_BYTE_LEN,
} from "./constants.js";
import { decodeG1, decodeG2, encodeG1, encodeG2, G1, G2 } from "./curve.js";
import { AcfError } from "./errors.js";
import { decodeFr, encodeFr, type Fr } from "./field.js";

/**
 * Validated Groth16 proof payload `A ‖ B ‖ C` (ACF Spec Section 4.1).
 *
 * Point `A` is not negated; negation is performed on-chain by the verifier
 * (ACF Spec Section 4.1, Section 8).
 */
export class Proof {
  public readonly a: G1;
  public readonly b: G2;
  public readonly c: G1;

  public constructor(a: G1, b: G2, c: G1) {
    this.a = a;
    this.b = b;
    this.c = c;
  }
}

/**
 * Decodes and strictly validates a 256-byte Groth16 proof payload `A ‖ B ‖ C`
 * (ACF Spec Section 4.1 and Section 9 Rules 1-4, 6).
 */
export function decodeProof(bytes: Uint8Array): Proof {
  if (bytes.length !== PROOF_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }

  const a = decodeG1(bytes.subarray(0, 64));
  const b = decodeG2(bytes.subarray(64, 192));
  const c = decodeG1(bytes.subarray(192, 256));

  if (a.isInfinity() || b.isInfinity() || c.isInfinity()) {
    throw new AcfError("ERR_INVALID_PROOF");
  }

  return new Proof(a, b, c);
}

/**
 * Encodes a Groth16 proof into its 256-byte canonical representation `A ‖ B ‖ C`
 * (ACF Spec Section 4.1).
 */
export function encodeProof(proof: Proof): Uint8Array {
  return concatBytes(
    encodeG1(proof.a),
    encodeG2(proof.b),
    encodeG1(proof.c),
  );
}

/**
 * Validated Groth16 verification key payload (ACF Spec Section 4.2).
 */
export class VerificationKey {
  public readonly alphaG1: G1;
  public readonly betaG2: G2;
  public readonly gammaG2: G2;
  public readonly deltaG2: G2;
  public readonly ic: readonly G1[];

  public constructor(
    alphaG1: G1,
    betaG2: G2,
    gammaG2: G2,
    deltaG2: G2,
    ic: readonly G1[],
  ) {
    this.alphaG1 = alphaG1;
    this.betaG2 = betaG2;
    this.gammaG2 = gammaG2;
    this.deltaG2 = deltaG2;
    this.ic = ic;
  }

  public get nIc(): number {
    return this.ic.length;
  }

  public get nPublic(): number {
    return Math.max(0, this.ic.length - 1);
  }

  public validatePublicInputs(publicInputs: PublicInputs): void {
    if (this.ic.length !== publicInputs.inputs.length + 1) {
      throw new AcfError("ERR_PUBLIC_INPUT_COUNT");
    }
  }
}

/**
 * Decodes and strictly validates a Groth16 verification key payload (ACF Spec Section 4.2).
 */
export function decodeVerificationKey(bytes: Uint8Array): VerificationKey {
  if (bytes.length < VK_HEADER_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const nIc = view.getUint32(448, false);

  if (nIc === 0) {
    throw new AcfError("ERR_PUBLIC_INPUT_COUNT");
  }

  const expectedLen = VK_HEADER_BYTE_LEN + nIc * G1_BYTE_LEN;
  if (bytes.length !== expectedLen) {
    throw new AcfError("ERR_BAD_LENGTH");
  }

  const alphaG1 = decodeG1(bytes.subarray(0, 64));
  const betaG2 = decodeG2(bytes.subarray(64, 192));
  const gammaG2 = decodeG2(bytes.subarray(192, 320));
  const deltaG2 = decodeG2(bytes.subarray(320, 448));

  const ic: G1[] = [];
  for (let i = 0; i < nIc; i++) {
    const start = VK_HEADER_BYTE_LEN + i * G1_BYTE_LEN;
    const end = start + G1_BYTE_LEN;
    ic.push(decodeG1(bytes.subarray(start, end)));
  }

  return new VerificationKey(alphaG1, betaG2, gammaG2, deltaG2, ic);
}

/**
 * Encodes a Groth16 verification key into canonical byte representation (ACF Spec Section 4.2).
 */
export function encodeVerificationKey(vk: VerificationKey): Uint8Array {
  const parts: Uint8Array[] = [
    encodeG1(vk.alphaG1),
    encodeG2(vk.betaG2),
    encodeG2(vk.gammaG2),
    encodeG2(vk.deltaG2),
  ];
  const nIcBytes = new Uint8Array(4);
  new DataView(nIcBytes.buffer).setUint32(0, vk.ic.length, false);
  parts.push(nIcBytes);
  for (const pt of vk.ic) {
    parts.push(encodeG1(pt));
  }
  return concatBytes(...parts);
}

/**
 * Validated Groth16 public inputs payload (ACF Spec Section 4.3).
 */
export class PublicInputs {
  public readonly inputs: readonly Fr[];

  public constructor(inputs: readonly Fr[]) {
    this.inputs = inputs;
  }

  public get length(): number {
    return this.inputs.length;
  }

  public validateWithVk(vk: VerificationKey): void {
    vk.validatePublicInputs(this);
  }
}

/**
 * Decodes and strictly validates Groth16 public inputs payload (ACF Spec Section 4.3).
 */
export function decodePublicInputs(bytes: Uint8Array): PublicInputs {
  if (bytes.length % FR_BYTE_LEN !== 0) {
    throw new AcfError("ERR_BAD_LENGTH");
  }

  const count = bytes.length / FR_BYTE_LEN;
  const inputs: Fr[] = [];
  for (let i = 0; i < count; i++) {
    const start = i * FR_BYTE_LEN;
    const end = start + FR_BYTE_LEN;
    inputs.push(decodeFr(bytes.subarray(start, end)));
  }

  return new PublicInputs(inputs);
}

/**
 * Encodes Groth16 public inputs into canonical byte representation (ACF Spec Section 4.3).
 */
export function encodePublicInputs(publicInputs: PublicInputs): Uint8Array {
  const parts = publicInputs.inputs.map((fr) => encodeFr(fr));
  return concatBytes(...parts);
}
