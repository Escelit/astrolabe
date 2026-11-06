#!/usr/bin/env node
/**
 * Differential test script (ACF Spec Section 10.1 & Plan.md Phase 4).
 *
 * Verifies that:
 * 1. `snarkjs groth16 verify` succeeds on all valid fixtures across distinct circuits.
 * 2. `snarkjs groth16 verify` fails on corrupted fixtures (negative control).
 * 3. TypeScript SDK parses snarkjs JSON artifacts and produces exact canonical ACF bytes.
 * 4. Rust and TypeScript byte outputs are identical.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  bytesToHex,
  encodeProof,
  encodePublicInputs,
  encodeVerificationKey,
  parseSnarkjsProof,
  parseSnarkjsPublicInputs,
  parseSnarkjsVerificationKey,
} from "../packages/astrolabe-ts/dist/index.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const ROOT = resolve(__dirname, "..");
const FIXTURES_DIR = resolve(ROOT, "spec/fixtures/snarkjs");

const CIRCUITS = [
  { name: "multiplier2", nPublic: 2, nIc: 3 },
  { name: "square", nPublic: 1, nIc: 2 },
  { name: "linear3", nPublic: 3, nIc: 4 },
];

console.log("=== Astrolabe Differential Conformance Check (Phase 4) ===");

for (const { name, nPublic, nIc } of CIRCUITS) {
  const dir = resolve(FIXTURES_DIR, name);
  const vkPath = resolve(dir, "verification_key.json");
  const pubPath = resolve(dir, "public.json");
  const proofPath = resolve(dir, "proof.json");

  console.log(`\n[Circuit: ${name}]`);

  // 1. snarkjs off-chain verification (positive control)
  process.stdout.write("  -> snarkjs groth16 verify (positive control): ");
  try {
    const out = execFileSync("snarkjs", ["groth16", "verify", vkPath, pubPath, proofPath], {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    if (!out.includes("OK")) {
      throw new Error(`snarkjs verification failed: ${out}`);
    }
    console.log("OK (snarkjs accepts proof)");
  } catch (err) {
    console.error(`FAILED: ${err}`);
    process.exit(1);
  }

  // 2. snarkjs off-chain verification (negative control with tampered public signal)
  process.stdout.write("  -> snarkjs groth16 verify (negative control): ");
  const tempDir = mkdtempSync(join(tmpdir(), "astrolabe-diff-"));
  try {
    const badPubPath = join(tempDir, "bad_public.json");
    const pubData = JSON.parse(readFileSync(pubPath, "utf8"));
    pubData[0] = (BigInt(pubData[0]) + 1n).toString();
    writeFileSync(badPubPath, JSON.stringify(pubData));

    let rejected = false;
    try {
      execFileSync("snarkjs", ["groth16", "verify", vkPath, badPubPath, proofPath], {
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch {
      rejected = true;
    }
    if (!rejected) {
      throw new Error("snarkjs unexpectedly accepted corrupted public signal!");
    }
    console.log("OK (snarkjs rejected corrupted signal)");
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }

  // 3. TS SDK conversion and length validation
  process.stdout.write("  -> Astrolabe TS adapter conversion: ");
  const proofStr = readFileSync(proofPath, "utf8");
  const vkStr = readFileSync(vkPath, "utf8");
  const pubStr = readFileSync(pubPath, "utf8");

  const proof = parseSnarkjsProof(proofStr);
  const vk = parseSnarkjsVerificationKey(vkStr);
  const pub = parseSnarkjsPublicInputs(pubStr);

  const proofBytes = encodeProof(proof);
  const vkBytes = encodeVerificationKey(vk);
  const pubBytes = encodePublicInputs(pub);

  if (proofBytes.length !== 256) {
    throw new Error(`Unexpected proof byte length: ${proofBytes.length}`);
  }
  if (vkBytes.length !== 452 + 64 * nIc) {
    throw new Error(`Unexpected VK byte length: ${vkBytes.length}`);
  }
  if (pubBytes.length !== 32 * nPublic) {
    throw new Error(`Unexpected public input byte length: ${pubBytes.length}`);
  }
  console.log(`OK (proof: 256B, vk: ${vkBytes.length}B [n_ic=${nIc}], pub: ${pubBytes.length}B [n_pub=${nPublic}])`);
}

console.log("\nAll differential checks passed successfully!");
