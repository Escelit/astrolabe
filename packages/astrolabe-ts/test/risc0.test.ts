import { describe, expect, it } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  bytesToHex,
  encodeEnvelope,
  encodeProof,
  hexToBytes,
  mapRisc0JournalAndImageId,
  mapRisc0Seal,
  parseRisc0ProofEnvelope,
  parseRisc0PublicInputsEnvelope,
  parseRisc0Receipt,
  parseSnarkjsProof,
  sha256,
} from "../src/index.js";

describe("RISC Zero Groth16 Adapter", () => {
  it("verifies NIST SHA-256 standard test vectors", () => {
    const hEmpty = sha256("");
    expect(bytesToHex(hEmpty)).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    const hAbc = sha256("abc");
    expect(bytesToHex(hAbc)).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("maps 256-byte seal and derives public inputs from image_id and journal", () => {
    const proofPath = path.resolve(
      __dirname,
      "../../../spec/fixtures/snarkjs/multiplier2/proof.json",
    );
    const proofRaw = fs.readFileSync(proofPath, "utf-8");
    const originalProof = parseSnarkjsProof(proofRaw);
    const sealBytes = encodeProof(originalProof);
    const sealHex = bytesToHex(sealBytes);

    // 1. mapRisc0Seal
    const mapped = mapRisc0Seal(sealBytes);
    expect(encodeProof(mapped)).toEqual(sealBytes);

    // 2. mapRisc0JournalAndImageId
    const imageId = new Uint8Array(32).fill(0x22);
    const journal = new Uint8Array([1, 2, 3, 4, 5]);
    const journalDigest = sha256(journal);

    // Mode: limb16 (4 scalars)
    const pub4 = mapRisc0JournalAndImageId(imageId, journalDigest, "limb16");
    expect(pub4.inputs.length).toBe(4);

    // Mode: direct (2 scalars)
    const validDirectId = new Uint8Array(32).fill(0x01);
    const validDirectJd = new Uint8Array(32).fill(0x02);
    const pub2 = mapRisc0JournalAndImageId(validDirectId, validDirectJd, "direct");
    expect(pub2.inputs.length).toBe(2);

    // 3. parseRisc0Receipt JSON
    const receiptJson = JSON.stringify({
      seal: `0x${sealHex}`,
      image_id: `0x${bytesToHex(imageId)}`,
      journal: `0x${bytesToHex(journal)}`,
    });

    const receipt = parseRisc0Receipt(receiptJson, "limb16");
    expect(encodeProof(receipt.proof)).toEqual(sealBytes);
    expect(receipt.imageId).toEqual(imageId);
    expect(receipt.journalDigest).toEqual(journalDigest);
    expect(receipt.publicInputs.inputs.length).toBe(4);

    // 4. Envelope parsers
    const pEnv = parseRisc0ProofEnvelope(receiptJson, "limb16");
    const piEnv = parseRisc0PublicInputsEnvelope(receiptJson, "limb16");
    expect(encodeEnvelope(pEnv)).toBeDefined();
    expect(encodeEnvelope(piEnv)).toBeDefined();
  });

  it("strictly enforces validation rules and error codes", () => {
    // Bad seal length
    expect(() => mapRisc0Seal(new Uint8Array(128))).toThrowError("ERR_BAD_LENGTH");

    // Non-canonical scalar in direct mode (BN254 r)
    const rHex =
      "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
    const rBytes = hexToBytes(rHex);
    expect(() =>
      mapRisc0JournalAndImageId(rBytes, new Uint8Array(32), "direct"),
    ).toThrowError("ERR_NON_CANONICAL_FIELD");
  });
});
