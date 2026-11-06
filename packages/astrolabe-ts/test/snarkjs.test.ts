import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AcfError,
  encodeEnvelope,
  encodeProof,
  encodePublicInputs,
  encodeVerificationKey,
  parseDecFp,
  parseDecFr,
  parseSnarkjsProof,
  parseSnarkjsProofEnvelope,
  parseSnarkjsPublicInputs,
  parseSnarkjsPublicInputsEnvelope,
  parseSnarkjsVerificationKey,
  parseSnarkjsVkEnvelope,
} from "../src/index.js";

const FIXTURES_DIR = resolve(
  __dirname,
  "../../../spec/fixtures/snarkjs",
);

describe("snarkjs adapter (ACF Spec Section 10.1)", () => {
  const circuits = [
    { name: "multiplier2", nPublic: 2, nIc: 3 },
    { name: "square", nPublic: 1, nIc: 2 },
    { name: "linear3", nPublic: 3, nIc: 4 },
  ];

  for (const { name, nPublic, nIc } of circuits) {
    it(`parses valid artifacts for ${name}`, () => {
      const dir = resolve(FIXTURES_DIR, name);
      const proofStr = readFileSync(resolve(dir, "proof.json"), "utf8");
      const vkStr = readFileSync(
        resolve(dir, "verification_key.json"),
        "utf8",
      );
      const pubStr = readFileSync(resolve(dir, "public.json"), "utf8");

      const proof = parseSnarkjsProof(proofStr);
      const vk = parseSnarkjsVerificationKey(vkStr);
      const pub = parseSnarkjsPublicInputs(pubStr);

      expect(vk.nPublic).toBe(nPublic);
      expect(vk.nIc).toBe(nIc);
      expect(pub.inputs.length).toBe(nPublic);
      expect(() => vk.validatePublicInputs(pub)).not.toThrow();

      expect(proof.a.isInfinity()).toBe(false);
      expect(proof.b.isInfinity()).toBe(false);
      expect(proof.c.isInfinity()).toBe(false);

      const proofEnv = parseSnarkjsProofEnvelope(proofStr);
      const vkEnv = parseSnarkjsVkEnvelope(vkStr);
      const pubEnv = parseSnarkjsPublicInputsEnvelope(pubStr);

      expect(encodeEnvelope(proofEnv)).toBeDefined();
      expect(encodeEnvelope(vkEnv)).toBeDefined();
      expect(encodeEnvelope(pubEnv)).toBeDefined();
      expect(encodeProof(proof).length).toBe(256);
      expect(encodeVerificationKey(vk).length).toBe(452 + 64 * nIc);
      expect(encodePublicInputs(pub).length).toBe(32 * nPublic);
    });
  }

  it("rejects invalid snarkjs fixtures with stable ACF error codes", () => {
    const invalidDir = resolve(FIXTURES_DIR, "invalid");

    // Unsupported protocol
    const unsupportedProto = readFileSync(
      resolve(invalidDir, "unsupported_protocol.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(unsupportedProto)).toThrowError(
      expect.objectContaining({ code: "ERR_UNSUPPORTED" }),
    );
    expect(() => parseSnarkjsVerificationKey(unsupportedProto)).toThrowError(
      expect.objectContaining({ code: "ERR_UNSUPPORTED" }),
    );

    // Unsupported curve
    const unsupportedCurve = readFileSync(
      resolve(invalidDir, "unsupported_curve.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(unsupportedCurve)).toThrowError(
      expect.objectContaining({ code: "ERR_UNSUPPORTED" }),
    );
    expect(() => parseSnarkjsVerificationKey(unsupportedCurve)).toThrowError(
      expect.objectContaining({ code: "ERR_UNSUPPORTED" }),
    );

    // Malformed proof A length
    const badALen = readFileSync(
      resolve(invalidDir, "malformed_proof_a_len.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(badALen)).toThrowError(
      expect.objectContaining({ code: "ERR_MALFORMED_INPUT" }),
    );

    // Malformed proof A trailing
    const badATrailing = readFileSync(
      resolve(invalidDir, "malformed_proof_a_trailing.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(badATrailing)).toThrowError(
      expect.objectContaining({ code: "ERR_MALFORMED_INPUT" }),
    );

    // Malformed proof B trailing
    const badBTrailing = readFileSync(
      resolve(invalidDir, "malformed_proof_b_trailing.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(badBTrailing)).toThrowError(
      expect.objectContaining({ code: "ERR_MALFORMED_INPUT" }),
    );

    // Malformed decimal
    const badDec = readFileSync(
      resolve(invalidDir, "malformed_decimal.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(badDec)).toThrowError(
      expect.objectContaining({ code: "ERR_MALFORMED_INPUT" }),
    );

    // Non-canonical field in proof
    const nonCanonField = readFileSync(
      resolve(invalidDir, "non_canonical_field.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(nonCanonField)).toThrowError(
      expect.objectContaining({ code: "ERR_NON_CANONICAL_FIELD" }),
    );

    // Non-canonical scalar in public.json
    const nonCanonScalar = readFileSync(
      resolve(invalidDir, "public_non_canonical_scalar.json"),
      "utf8",
    );
    expect(() => parseSnarkjsPublicInputs(nonCanonScalar)).toThrowError(
      expect.objectContaining({ code: "ERR_NON_CANONICAL_FIELD" }),
    );

    // VK IC count mismatch
    const icMismatch = readFileSync(
      resolve(invalidDir, "vk_ic_count_mismatch.json"),
      "utf8",
    );
    expect(() => parseSnarkjsVerificationKey(icMismatch)).toThrowError(
      expect.objectContaining({ code: "ERR_PUBLIC_INPUT_COUNT" }),
    );

    // Degenerate proof infinity
    const degenInfinity = readFileSync(
      resolve(invalidDir, "degenerate_proof_infinity.json"),
      "utf8",
    );
    expect(() => parseSnarkjsProof(degenInfinity)).toThrowError(
      expect.objectContaining({ code: "ERR_INVALID_PROOF" }),
    );
  });

  it("handles parseDecFp and parseDecFr helpers strictly", () => {
    expect(() => parseDecFp("")).toThrow(AcfError);
    expect(() => parseDecFp("abc")).toThrow(AcfError);
    expect(() => parseDecFr("")).toThrow(AcfError);
    expect(() => parseDecFr("xyz")).toThrow(AcfError);

    const pStr =
      "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    expect(() => parseDecFp(pStr)).toThrowError(
      expect.objectContaining({ code: "ERR_NON_CANONICAL_FIELD" }),
    );

    const rStr =
      "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    expect(() => parseDecFr(rStr)).toThrowError(
      expect.objectContaining({ code: "ERR_NON_CANONICAL_FIELD" }),
    );
  });
});
