import { bytesToHex, hexToBytes } from "./bytes.js";
import {
  ArtifactKind,
  artifactKindToString,
  curveIdToString,
  Envelope,
  proofSystemIdToString,
  stringToArtifactKind,
  stringToCurveId,
  stringToProofSystemId,
} from "./envelope.js";
import { AcfError } from "./errors.js";
import {
  decodeProof,
  decodePublicInputs,
  decodeVerificationKey,
  encodeProof,
  encodePublicInputs,
  encodeVerificationKey,
} from "./groth16.js";

/**
 * Serializes an ACF Envelope into canonical JSON string (ACF Spec Section 6).
 */
export function toCanonicalJson(envelope: Envelope): string {
  let payloadBytes: Uint8Array;
  switch (envelope.payload.kind) {
    case ArtifactKind.Proof:
      payloadBytes = encodeProof(envelope.payload.data);
      break;
    case ArtifactKind.VerificationKey:
      payloadBytes = encodeVerificationKey(envelope.payload.data);
      break;
    case ArtifactKind.PublicInputs:
      payloadBytes = encodePublicInputs(envelope.payload.data);
      break;
  }
  const hex = bytesToHex(payloadBytes);

  return (
    `{\n` +
    `  "acf": "0.1",\n` +
    `  "kind": "${artifactKindToString(envelope.kind)}",\n` +
    `  "curve": "${curveIdToString(envelope.curve)}",\n` +
    `  "system": "${proofSystemIdToString(envelope.system)}",\n` +
    `  "hex": "${hex}"\n` +
    `}\n`
  );
}

/**
 * Parses an ACF Envelope from canonical JSON string (ACF Spec Section 6).
 */
export function parseCanonicalJson(jsonStr: string): Envelope {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(jsonStr) as Record<string, unknown>;
  } catch {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  if (obj.acf !== "0.1") {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  if (typeof obj.kind !== "string") {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  const kind = stringToArtifactKind(obj.kind);

  if (typeof obj.curve !== "string") {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  stringToCurveId(obj.curve);

  if (typeof obj.system !== "string") {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }
  stringToProofSystemId(obj.system);

  if (typeof obj.hex !== "string") {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const hexPattern = /^([0-9a-f]{2})*$/;
  if (!hexPattern.test(obj.hex)) {
    throw new AcfError("ERR_MALFORMED_INPUT");
  }

  const payloadBytes = hexToBytes(obj.hex);
  switch (kind) {
    case ArtifactKind.Proof:
      return new Envelope({
        kind: ArtifactKind.Proof,
        data: decodeProof(payloadBytes),
      });
    case ArtifactKind.VerificationKey:
      return new Envelope({
        kind: ArtifactKind.VerificationKey,
        data: decodeVerificationKey(payloadBytes),
      });
    case ArtifactKind.PublicInputs:
      return new Envelope({
        kind: ArtifactKind.PublicInputs,
        data: decodePublicInputs(payloadBytes),
      });
  }
}
