/**
 * Canonical error codes defined by ACF Specification Section 11 (`acf/0.1`).
 */
export const ACF_ERROR_CODES = {
  BadLength: "ERR_BAD_LENGTH",
  NonCanonicalField: "ERR_NON_CANONICAL_FIELD",
  NotOnCurve: "ERR_NOT_ON_CURVE",
  NotInSubgroup: "ERR_NOT_IN_SUBGROUP",
  PublicInputCount: "ERR_PUBLIC_INPUT_COUNT",
  InvalidProof: "ERR_INVALID_PROOF",
  Unsupported: "ERR_UNSUPPORTED",
  TrailingBytes: "ERR_TRAILING_BYTES",
  MalformedInput: "ERR_MALFORMED_INPUT",
} as const;

/**
 * Union of all stable ACF error code strings (ACF Specification Section 11).
 */
export type AcfErrorCode =
  (typeof ACF_ERROR_CODES)[keyof typeof ACF_ERROR_CODES];

/**
 * Error raised during ACF encoding, decoding, or validation (ACF Specification Section 11).
 */
export class AcfError extends Error {
  public readonly code: AcfErrorCode;

  public constructor(code: AcfErrorCode) {
    super(code);
    this.name = "AcfError";
    this.code = code;
  }
}
