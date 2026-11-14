/**
 * Noir Groth16 BN254 adapter conforming to ACF Spec Section 10.2.
 *
 * Noir is supported via Groth16 backends (e.g. `sunspot`, `noir-groth16`, `garaga`)
 * that emit snarkjs-compatible artifacts or unified Noir bundles.
 * Toolchain and backend versions are recorded in [`NoirMetadata`] without modifying
 * canonical bytes.
 */

import {
  ArtifactKind,
  Envelope,
} from "./envelope.js";
import { AcfError } from "./errors.js";
import { Proof, PublicInputs, VerificationKey } from "./groth16.js";
import {
  parseNumFr,
  parseSnarkjsProof,
  parseSnarkjsPublicInputs,
  parseSnarkjsVk,
} from "./snarkjs.js";

/**
 * Toolchain and backend provenance metadata for Noir proving artifacts (Spec Section 10.2).
 */
export interface NoirMetadata {
  noirVersion?: string | undefined;
  backend?: string | undefined;
  circuitName?: string | undefined;
}

/**
 * Unified Noir Groth16 proving artifact bundle.
 */
export interface NoirBundle {
  metadata: NoirMetadata;
  proof?: Proof | undefined;
  vk?: VerificationKey | undefined;
  publicInputs?: PublicInputs | undefined;
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
 * Extracts [`NoirMetadata`] from a JSON object or string.
 */
export function extractNoirMetadata(input: string | unknown): NoirMetadata {
  const root = parseJsonValue(input);
  if (!root || typeof root !== "object" || Array.isArray(root)) {
    return {};
  }
  const obj = root as Record<string, unknown>;
  const meta: NoirMetadata = {};

  if (typeof obj.noir_version === "string") {
    meta.noirVersion = obj.noir_version;
  } else if (typeof obj.noirVersion === "string") {
    meta.noirVersion = obj.noirVersion;
  }

  if (typeof obj.backend === "string") {
    meta.backend = obj.backend;
  } else if (typeof obj.prover === "string") {
    meta.backend = obj.prover;
  }

  if (typeof obj.circuit === "string") {
    meta.circuitName = obj.circuit;
  } else if (typeof obj.circuit_name === "string") {
    meta.circuitName = obj.circuit_name;
  } else if (typeof obj.circuitName === "string") {
    meta.circuitName = obj.circuitName;
  }

  if (obj.metadata && typeof obj.metadata === "object" && !Array.isArray(obj.metadata)) {
    const nested = obj.metadata as Record<string, unknown>;
    if (typeof nested.noir_version === "string") {
      meta.noirVersion = nested.noir_version;
    } else if (typeof nested.noirVersion === "string") {
      meta.noirVersion = nested.noirVersion;
    }
    if (typeof nested.backend === "string") {
      meta.backend = nested.backend;
    } else if (typeof nested.prover === "string") {
      meta.backend = nested.prover;
    }
    if (typeof nested.circuit === "string") {
      meta.circuitName = nested.circuit;
    } else if (typeof nested.circuit_name === "string") {
      meta.circuitName = nested.circuit_name;
    } else if (typeof nested.circuitName === "string") {
      meta.circuitName = nested.circuitName;
    }
  }

  return meta;
}

function normalizeNoirCurve(val: unknown): unknown {
  if (val && typeof val === "object" && !Array.isArray(val)) {
    const obj = val as Record<string, unknown>;
    if (obj.curve === "bn254") {
      return { ...obj, curve: "bn128" };
    }
  }
  return val;
}

/**
 * Parses and converts a Noir Groth16 `proof.json` (or bundle) into a canonical [`Proof`].
 */
export function parseNoirProof(input: string | unknown): Proof {
  const root = parseJsonValue(input);
  if (root && typeof root === "object" && !Array.isArray(root)) {
    const obj = root as Record<string, unknown>;
    if (obj.proof) {
      return parseSnarkjsProof(normalizeNoirCurve(obj.proof));
    }
  }
  return parseSnarkjsProof(normalizeNoirCurve(root));
}

/**
 * Parses and converts a Noir Groth16 `verification_key.json` (or bundle) into a canonical [`VerificationKey`].
 */
export function parseNoirVk(input: string | unknown): VerificationKey {
  const root = parseJsonValue(input);
  if (root && typeof root === "object" && !Array.isArray(root)) {
    const obj = root as Record<string, unknown>;
    if (obj.verification_key) {
      return parseSnarkjsVk(normalizeNoirCurve(obj.verification_key));
    }
    if (obj.vk) {
      return parseSnarkjsVk(normalizeNoirCurve(obj.vk));
    }
  }
  return parseSnarkjsVk(normalizeNoirCurve(root));
}

/**
 * Parses and converts a Noir public inputs artifact (or bundle) into a canonical [`PublicInputs`].
 */
export function parseNoirPublicInputs(input: string | unknown): PublicInputs {
  const root = parseJsonValue(input);
  if (root && typeof root === "object" && !Array.isArray(root)) {
    const obj = root as Record<string, unknown>;
    const target = obj.public_inputs ?? obj.public;
    if (Array.isArray(target)) {
      const inputs = target.map((item) => {
        if (typeof item !== "string") {
          throw new AcfError("ERR_MALFORMED_INPUT");
        }
        return parseNumFr(item);
      });
      return new PublicInputs(inputs);
    }
  }
  if (Array.isArray(root)) {
    return parseSnarkjsPublicInputs(root);
  }
  throw new AcfError("ERR_MALFORMED_INPUT");
}

/**
 * Parses a unified Noir Groth16 bundle containing metadata, proof, verification key, and/or public inputs.
 */
export function parseNoirBundle(input: string | unknown): NoirBundle {
  const root = parseJsonValue(input);
  const metadata = extractNoirMetadata(root);

  let proof: Proof | undefined;
  let vk: VerificationKey | undefined;
  let publicInputs: PublicInputs | undefined;

  if (root && typeof root === "object" && !Array.isArray(root)) {
    const obj = root as Record<string, unknown>;
    if (obj.proof) {
      proof = parseSnarkjsProof(normalizeNoirCurve(obj.proof));
    }
    if (obj.verification_key || obj.vk) {
      vk = parseSnarkjsVk(normalizeNoirCurve(obj.verification_key ?? obj.vk));
    }
    const pi = obj.public_inputs ?? obj.public;
    if (Array.isArray(pi)) {
      publicInputs = parseNoirPublicInputs(pi);
    }
  }

  return {
    metadata,
    proof,
    vk,
    publicInputs,
  };
}

/**
 * Parses a Noir `proof.json` and wraps it in a canonical [`Envelope`].
 */
export function parseNoirProofEnvelope(input: string | unknown): Envelope {
  const proof = parseNoirProof(input);
  return new Envelope({
    kind: ArtifactKind.Proof,
    data: proof,
  });
}

/**
 * Parses a Noir `verification_key.json` and wraps it in a canonical [`Envelope`].
 */
export function parseNoirVkEnvelope(input: string | unknown): Envelope {
  const vk = parseNoirVk(input);
  return new Envelope({
    kind: ArtifactKind.VerificationKey,
    data: vk,
  });
}

/**
 * Parses a Noir public inputs artifact and wraps it in a canonical [`Envelope`].
 */
export function parseNoirPublicInputsEnvelope(input: string | unknown): Envelope {
  const publicInputs = parseNoirPublicInputs(input);
  return new Envelope({
    kind: ArtifactKind.PublicInputs,
    data: publicInputs,
  });
}
