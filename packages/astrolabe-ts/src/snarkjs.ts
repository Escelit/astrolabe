/**
 * Adapter for snarkjs / Circom Groth16 BN254 artifacts (ACF Spec Section 10.1).
 *
 * Converts public verification artifacts (`proof.json`, `verification_key.json`,
 * `public.json`) into canonical ACF types (`Proof`, `VerificationKey`, `PublicInputs`),
 * enforcing strict validation per ACF Spec Sections 9 and 10.1.
 */

import { BN254_P, BN254_R } from "./constants.js";
import { G1, G2 } from "./curve.js";
import {
  ArtifactKind,
  Envelope,
} from "./envelope.js";
import { AcfError } from "./errors.js";
import type { Fp2 } from "./field.js";
import { Proof, PublicInputs, VerificationKey } from "./groth16.js";

/**
 * Parses an ASCII decimal string into a canonical BN254 `Fp` coordinate (`< p`).
 *
 * @throws {AcfError} `ERR_MALFORMED_INPUT` if string is empty or contains non-digit characters
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if numeric value is `>= p`
 */
export function parseDecFp(s: string): bigint {
  if (typeof s !== "string" || s.length === 0 || !/^[0-9]+$/.test(s)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const val = BigInt(s);
  if (val >= BN254_P) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  return val;
}

/**
 * Parses an ASCII decimal string into a canonical BN254 `Fr` scalar (`< r`).
 *
 * @throws {AcfError} `ERR_MALFORMED_INPUT` if string is empty or contains non-digit characters
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if numeric value is `>= r`
 */
export function parseDecFr(s: string): bigint {
  if (typeof s !== "string" || s.length === 0 || !/^[0-9]+$/.test(s)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const val = BigInt(s);
  if (val >= BN254_R) {
    throw new AcfError("ERR_NON_CANONICAL_FIELD");
  }
  return val;
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

function parseSnarkjsG1(raw: unknown): G1 {
  if (!Array.isArray(raw) || raw.length !== 3) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  if (raw[2] !== "1") {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const x = parseDecFp(raw[0]);
  const y = parseDecFp(raw[1]);
  return G1.fromCoordinates(x, y);
}

function parseSnarkjsG2(raw: unknown): G2 {
  if (!Array.isArray(raw) || raw.length !== 3) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const trailing = raw[2];
  if (
    !Array.isArray(trailing) ||
    trailing.length !== 2 ||
    trailing[0] !== "1" ||
    trailing[1] !== "0"
  ) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const xArr = raw[0];
  if (!Array.isArray(xArr) || xArr.length !== 2) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const x0 = parseDecFp(xArr[0]);
  const x1 = parseDecFp(xArr[1]);

  const yArr = raw[1];
  if (!Array.isArray(yArr) || yArr.length !== 2) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const y0 = parseDecFp(yArr[0]);
  const y1 = parseDecFp(yArr[1]);

  const x: Fp2 = { c0: x0, c1: x1 };
  const y: Fp2 = { c0: y0, c1: y1 };

  return G2.fromCoordinates(x, y);
}

/**
 * Parses and strictly validates a snarkjs `proof.json` into a canonical [`Proof`].
 *
 * @param input JSON string or parsed object
 * @throws {AcfError} `ERR_UNSUPPORTED` if protocol != "groth16" or curve != "bn128"
 * @throws {AcfError} `ERR_MALFORMED_INPUT` if structure or tokens are malformed
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if coordinates are `>= p`
 * @throws {AcfError} `ERR_NOT_ON_CURVE` if points fail curve equations
 * @throws {AcfError} `ERR_NOT_IN_SUBGROUP` if point B is not in the G2 subgroup
 * @throws {AcfError} `ERR_INVALID_PROOF` if proof points A, B, or C are infinity
 */
export function parseSnarkjsProof(input: string | unknown): Proof {
  const root = parseJsonValue(input) as Record<string, unknown> | null;
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  if (root.protocol !== "groth16" || root.curve !== "bn128") {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  const a = parseSnarkjsG1(root.pi_a);
  const b = parseSnarkjsG2(root.pi_b);
  const c = parseSnarkjsG1(root.pi_c);

  if (a.isInfinity() || b.isInfinity() || c.isInfinity()) {
    throw new AcfError("ERR_INVALID_PROOF");
  }

  return new Proof(a, b, c);
}

/**
 * Parses and strictly validates a snarkjs `verification_key.json` into a canonical [`VerificationKey`].
 *
 * @param input JSON string or parsed object
 * @throws {AcfError} `ERR_UNSUPPORTED` if protocol != "groth16" or curve != "bn128"
 * @throws {AcfError} `ERR_PUBLIC_INPUT_COUNT` if nPublic != IC.length - 1
 * @throws {AcfError} `ERR_MALFORMED_INPUT` if structure or tokens are malformed
 */
export function parseSnarkjsVerificationKey(
  input: string | unknown,
): VerificationKey {
  const root = parseJsonValue(input) as Record<string, unknown> | null;
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  if (root.protocol !== "groth16" || root.curve !== "bn128") {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  let nPublic: number;
  if (typeof root.nPublic === "number" && Number.isInteger(root.nPublic)) {
    nPublic = root.nPublic;
  } else if (
    typeof root.nPublic === "string" &&
    /^[0-9]+$/.test(root.nPublic)
  ) {
    nPublic = Number.parseInt(root.nPublic, 10);
  } else {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const alpha = parseSnarkjsG1(root.vk_alpha_1);
  const beta = parseSnarkjsG2(root.vk_beta_2);
  const gamma = parseSnarkjsG2(root.vk_gamma_2);
  const delta = parseSnarkjsG2(root.vk_delta_2);

  if (!Array.isArray(root.IC)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const ic: G1[] = root.IC.map((entry) => parseSnarkjsG1(entry));

  if (ic.length !== nPublic + 1) {
    throw new AcfError("ERR_PUBLIC_INPUT_COUNT");
  }

  return new VerificationKey(alpha, beta, gamma, delta, ic);
}

/**
 * Parses and strictly validates a snarkjs `public.json` array into a canonical [`PublicInputs`].
 *
 * @param input JSON string or parsed array
 * @throws {AcfError} `ERR_MALFORMED_INPUT` if input is not an array of decimal strings
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if any scalar is `>= r`
 */
export function parseSnarkjsPublicInputs(
  input: string | unknown,
): PublicInputs {
  const root = parseJsonValue(input);
  if (!Array.isArray(root)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const inputs: bigint[] = root.map((item) => {
    if (typeof item !== "string") {
      throw new AcfError("ERR_MALFORMED_INPUT");
    }
    return parseDecFr(item);
  });

  return new PublicInputs(inputs);
}

/** Alias for [`parseSnarkjsProof`]. */
export const convertSnarkjsProof = parseSnarkjsProof;
/** Alias for [`parseSnarkjsVerificationKey`]. */
export const convertSnarkjsVerificationKey = parseSnarkjsVerificationKey;
/** Alias for [`parseSnarkjsPublicInputs`]. */
export const convertSnarkjsPublicInputs = parseSnarkjsPublicInputs;

/**
 * Parses a snarkjs `proof.json` and wraps it in a canonical [`Envelope`].
 */
export function parseSnarkjsProofEnvelope(input: string | unknown): Envelope {
  const proof = parseSnarkjsProof(input);
  return new Envelope({
    kind: ArtifactKind.Proof,
    data: proof,
  });
}

/**
 * Parses a snarkjs `verification_key.json` and wraps it in a canonical [`Envelope`].
 */
export function parseSnarkjsVkEnvelope(input: string | unknown): Envelope {
  const vk = parseSnarkjsVerificationKey(input);
  return new Envelope({
    kind: ArtifactKind.VerificationKey,
    data: vk,
  });
}

/**
 * Parses a snarkjs `public.json` and wraps it in a canonical [`Envelope`].
 */
export function parseSnarkjsPublicInputsEnvelope(
  input: string | unknown,
): Envelope {
  const pub = parseSnarkjsPublicInputs(input);
  return new Envelope({
    kind: ArtifactKind.PublicInputs,
    data: pub,
  });
}
