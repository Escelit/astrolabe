import { describe, expect, it } from "vitest";
import {
  AcfError,
  ArtifactKind,
  CurveId,
  decodeEnvelope,
  decodeProof,
  decodePublicInputs,
  decodeVerificationKey,
  encodeEnvelope,
  encodeProof,
  encodePublicInputs,
  encodeVerificationKey,
  Envelope,
  G1,
  G2,
  parseCanonicalJson,
  Proof,
  ProofSystemId,
  PublicInputs,
  toCanonicalJson,
  VerificationKey,
} from "../src/index.js";

describe("Groth16 objects, Envelope, and Canonical JSON in TypeScript", () => {
  it("losslessly encodes and decodes Proof, VerificationKey, and PublicInputs", () => {
    const proof = new Proof(G1.GENERATOR, G2.GENERATOR, G1.GENERATOR);
    const proofBytes = encodeProof(proof);
    expect(proofBytes.length).toBe(256);
    const decodedProof = decodeProof(proofBytes);
    expect(encodeProof(decodedProof)).toEqual(proofBytes);

    const vk = new VerificationKey(
      G1.GENERATOR,
      G2.GENERATOR,
      G2.GENERATOR,
      G2.GENERATOR,
      [G1.GENERATOR, G1.GENERATOR],
    );
    expect(vk.nIc).toBe(2);
    expect(vk.nPublic).toBe(1);
    const vkBytes = encodeVerificationKey(vk);
    expect(vkBytes.length).toBe(452 + 2 * 64);
    const decodedVk = decodeVerificationKey(vkBytes);
    expect(encodeVerificationKey(decodedVk)).toEqual(vkBytes);

    const pi = new PublicInputs([1n]);
    expect(pi.length).toBe(1);
    const piBytes = encodePublicInputs(pi);
    expect(piBytes.length).toBe(32);
    const decodedPi = decodePublicInputs(piBytes);
    expect(encodePublicInputs(decodedPi)).toEqual(piBytes);

    expect(() => vk.validatePublicInputs(pi)).not.toThrow();
    expect(() => pi.validateWithVk(vk)).not.toThrow();

    const badPi = new PublicInputs([1n, 2n]);
    expect(() => vk.validatePublicInputs(badPi)).toThrowError(
      new AcfError("ERR_PUBLIC_INPUT_COUNT"),
    );
  });

  it("losslessly encodes, decodes, and parses Envelope and Canonical JSON", () => {
    const proof = new Proof(G1.GENERATOR, G2.GENERATOR, G1.GENERATOR);
    const env = new Envelope({
      kind: ArtifactKind.Proof,
      data: proof,
    });
    expect(env.kind).toBe(ArtifactKind.Proof);
    expect(env.curve).toBe(CurveId.Bn254);
    expect(env.system).toBe(ProofSystemId.Groth16);

    const envBytes = encodeEnvelope(env);
    expect(envBytes.length).toBe(12 + 256);
    const decodedEnv = decodeEnvelope(envBytes);
    expect(encodeEnvelope(decodedEnv)).toEqual(envBytes);

    const jsonStr = toCanonicalJson(env);
    expect(jsonStr).toContain('"acf": "0.1"');
    expect(jsonStr).toContain('"kind": "proof"');
    expect(jsonStr).toContain('"curve": "bn254"');
    expect(jsonStr).toContain('"system": "groth16"');
    expect(jsonStr.endsWith("\n")).toBe(true);

    const parsedEnv = parseCanonicalJson(jsonStr);
    expect(encodeEnvelope(parsedEnv)).toEqual(envBytes);
  });

  it("strictly rejects malformed canonical JSON", () => {
    expect(() => parseCanonicalJson("not json")).toThrowError(
      expect.objectContaining({ code: "ERR_MALFORMED_INPUT" }),
    );
    expect(() => parseCanonicalJson('{"acf":"0.2"}')).toThrowError(
      expect.objectContaining({ code: "ERR_UNSUPPORTED" }),
    );
    expect(() =>
      parseCanonicalJson(
        '{"acf":"0.1","kind":"unknown","curve":"bn254","system":"groth16","hex":"00"}',
      ),
    ).toThrowError(expect.objectContaining({ code: "ERR_UNSUPPORTED" }));
    expect(() =>
      parseCanonicalJson(
        '{"acf":"0.1","kind":"proof","curve":"bn254","system":"groth16","hex":"0x12"}',
      ),
    ).toThrowError(expect.objectContaining({ code: "ERR_MALFORMED_INPUT" }));
  });
});
