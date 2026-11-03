import { concatBytes } from "./bytes.js";
import {
  ENVELOPE_HEADER_BYTE_LEN,
  ENVELOPE_SPEC_VER_0_1,
} from "./constants.js";
import { AcfError } from "./errors.js";
import {
  decodeProof,
  decodePublicInputs,
  decodeVerificationKey,
  encodeProof,
  encodePublicInputs,
  encodeVerificationKey,
  Proof,
  PublicInputs,
  VerificationKey,
} from "./groth16.js";

/**
 * Artifact kind identifier (ACF Spec Section 5).
 */
export enum ArtifactKind {
  Proof = 0x01,
  VerificationKey = 0x02,
  PublicInputs = 0x03,
}

export function artifactKindToString(kind: ArtifactKind): string {
  switch (kind) {
    case ArtifactKind.Proof:
      return "proof";
    case ArtifactKind.VerificationKey:
      return "verification_key";
    case ArtifactKind.PublicInputs:
      return "public_inputs";
  }
}

export function stringToArtifactKind(str: string): ArtifactKind {
  switch (str) {
    case "proof":
      return ArtifactKind.Proof;
    case "verification_key":
      return ArtifactKind.VerificationKey;
    case "public_inputs":
      return ArtifactKind.PublicInputs;
    default:
      throw new AcfError("ERR_UNSUPPORTED");
  }
}

/**
 * Curve identifier (ACF Spec Section 5).
 */
export enum CurveId {
  Bn254 = 0x01,
}

export function curveIdToString(curve: CurveId): string {
  switch (curve) {
    case CurveId.Bn254:
      return "bn254";
  }
}

export function stringToCurveId(str: string): CurveId {
  switch (str) {
    case "bn254":
      return CurveId.Bn254;
    default:
      throw new AcfError("ERR_UNSUPPORTED");
  }
}

/**
 * Proof system identifier (ACF Spec Section 5).
 */
export enum ProofSystemId {
  Groth16 = 0x01,
}

export function proofSystemIdToString(sys: ProofSystemId): string {
  switch (sys) {
    case ProofSystemId.Groth16:
      return "groth16";
  }
}

export function stringToProofSystemId(str: string): ProofSystemId {
  switch (str) {
    case "groth16":
      return ProofSystemId.Groth16;
    default:
      throw new AcfError("ERR_UNSUPPORTED");
  }
}

/**
 * Typed envelope payload.
 */
export type EnvelopePayload =
  | { readonly kind: ArtifactKind.Proof; readonly data: Proof }
  | { readonly kind: ArtifactKind.VerificationKey; readonly data: VerificationKey }
  | { readonly kind: ArtifactKind.PublicInputs; readonly data: PublicInputs };

/**
 * Self-describing ACF artifact envelope (ACF Spec Section 5).
 */
export class Envelope {
  public readonly specVer: number;
  public readonly kind: ArtifactKind;
  public readonly curve: CurveId;
  public readonly system: ProofSystemId;
  public readonly payload: EnvelopePayload;

  public constructor(payload: EnvelopePayload) {
    this.specVer = ENVELOPE_SPEC_VER_0_1;
    this.kind = payload.kind;
    this.curve = CurveId.Bn254;
    this.system = ProofSystemId.Groth16;
    this.payload = payload;
  }
}

/**
 * Decodes and strictly validates an ACF artifact envelope (ACF Spec Section 5).
 */
export function decodeEnvelope(bytes: Uint8Array): Envelope {
  if (bytes.length < ENVELOPE_HEADER_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }

  // Check magic: ASTR (0x41 0x53 0x54 0x52)
  if (
    bytes[0] !== 0x41 ||
    bytes[1] !== 0x53 ||
    bytes[2] !== 0x54 ||
    bytes[3] !== 0x52
  ) {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  // Check spec_ver
  if (bytes[4] !== ENVELOPE_SPEC_VER_0_1) {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  // Check kind
  const kindByte = bytes[5];
  if (
    kindByte !== ArtifactKind.Proof &&
    kindByte !== ArtifactKind.VerificationKey &&
    kindByte !== ArtifactKind.PublicInputs
  ) {
    throw new AcfError("ERR_UNSUPPORTED");
  }
  const kind: ArtifactKind = kindByte;

  // Check curve
  const curveByte = bytes[6];
  if (curveByte !== CurveId.Bn254) {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  // Check system
  const systemByte = bytes[7];
  if (systemByte !== ProofSystemId.Groth16) {
    throw new AcfError("ERR_UNSUPPORTED");
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const payloadLen = view.getUint32(8, false);

  const totalExpected = ENVELOPE_HEADER_BYTE_LEN + payloadLen;
  if (bytes.length < totalExpected) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  if (bytes.length > totalExpected) {
    throw new AcfError("ERR_TRAILING_BYTES");
  }

  const payloadBytes = bytes.subarray(ENVELOPE_HEADER_BYTE_LEN, totalExpected);

  let payload: EnvelopePayload;
  switch (kind) {
    case ArtifactKind.Proof:
      payload = { kind: ArtifactKind.Proof, data: decodeProof(payloadBytes) };
      break;
    case ArtifactKind.VerificationKey:
      payload = {
        kind: ArtifactKind.VerificationKey,
        data: decodeVerificationKey(payloadBytes),
      };
      break;
    case ArtifactKind.PublicInputs:
      payload = {
        kind: ArtifactKind.PublicInputs,
        data: decodePublicInputs(payloadBytes),
      };
      break;
  }

  return new Envelope(payload);
}

/**
 * Encodes an ACF artifact envelope into canonical byte representation (ACF Spec Section 5).
 */
export function encodeEnvelope(envelope: Envelope): Uint8Array {
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

  const header = new Uint8Array(ENVELOPE_HEADER_BYTE_LEN);
  header[0] = 0x41;
  header[1] = 0x53;
  header[2] = 0x54;
  header[3] = 0x52;
  header[4] = envelope.specVer;
  header[5] = envelope.kind;
  header[6] = envelope.curve;
  header[7] = envelope.system;
  new DataView(header.buffer).setUint32(8, payloadBytes.length, false);

  return concatBytes(header, payloadBytes);
}
