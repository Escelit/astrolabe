import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  extractNoirMetadata,
  encodeEnvelope,
  parseNoirBundle,
  parseNoirProof,
  parseNoirProofEnvelope,
  parseNoirPublicInputs,
  parseNoirPublicInputsEnvelope,
  parseNoirVk,
  parseNoirVkEnvelope,
  AcfError,
} from "../src/index.js";

function fixturePath(circuit: string, file: string): string {
  const p = path.resolve(__dirname, `../../../spec/fixtures/snarkjs/${circuit}/${file}`);
  return fs.readFileSync(p, "utf-8");
}

describe("Noir Groth16 Adapter", () => {
  it("parses snarkjs-compatible Noir Groth16 artifacts", () => {
    const proofStr = fixturePath("multiplier2", "proof.json");
    const vkStr = fixturePath("multiplier2", "verification_key.json");
    const pubStr = fixturePath("multiplier2", "public.json");

    const proof = parseNoirProof(proofStr);
    const vk = parseNoirVk(vkStr);
    const pubInputs = parseNoirPublicInputs(pubStr);

    expect(proof.a.isInfinity()).toBe(false);
    expect(vk.nPublic).toBe(2);
    expect(pubInputs.inputs.length).toBe(2);
    expect(() => vk.validatePublicInputs(pubInputs)).not.toThrow();

    const proofEnv = parseNoirProofEnvelope(proofStr);
    const vkEnv = parseNoirVkEnvelope(vkStr);
    const pubEnv = parseNoirPublicInputsEnvelope(pubStr);

    expect(encodeEnvelope(proofEnv)).toBeDefined();
    expect(encodeEnvelope(vkEnv)).toBeDefined();
    expect(encodeEnvelope(pubEnv)).toBeDefined();
  });

  it("extracts Noir metadata and parses unified bundle with hex scalar", () => {
    const proofRaw = fixturePath("square", "proof.json");
    const vkRaw = fixturePath("square", "verification_key.json");

    const bundleJson = JSON.stringify({
      noir_version: "0.33.0",
      backend: "sunspot",
      circuit: "noir_square_circuit",
      proof: JSON.parse(proofRaw),
      verification_key: JSON.parse(vkRaw),
      public_inputs: ["0x09"],
    });

    const meta = extractNoirMetadata(bundleJson);
    expect(meta).toEqual({
      noirVersion: "0.33.0",
      backend: "sunspot",
      circuitName: "noir_square_circuit",
    });

    const bundle = parseNoirBundle(bundleJson);
    expect(bundle.metadata).toEqual(meta);
    expect(bundle.proof).toBeDefined();
    expect(bundle.vk).toBeDefined();
    expect(bundle.publicInputs).toBeDefined();
    expect(bundle.vk?.nPublic).toBe(1);
    expect(bundle.publicInputs?.inputs[0]).toBe(9n);
  });

  it("strictly enforces validation rules and error codes", () => {
    expect(() => parseNoirProof("invalid json")).toThrow(AcfError);

    // Unsupported protocol
    expect(() =>
      parseNoirProof(JSON.stringify({ protocol: "plonk", curve: "bn128" })),
    ).toThrowError("ERR_UNSUPPORTED");

    // Non-canonical scalar (r)
    const badScalar = JSON.stringify([
      "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
    ]);
    expect(() => parseNoirPublicInputs(badScalar)).toThrowError(
      "ERR_NON_CANONICAL_FIELD",
    );
  });
});
