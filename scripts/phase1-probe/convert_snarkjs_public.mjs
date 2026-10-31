#!/usr/bin/env node
/**
 * Phase 1 throwaway public-artifact converter (ACF Spec Sections 3, 4, 10.1).
 *
 * Converts public snarkjs Groth16 BN254 files (`verification_key.json`,
 * `proof.json`, `public.json`) into raw ACF hex payloads, plus a negative-control
 * encoding with swapped Fp2 order (`c0 || c1`) to test CAP-0074 G2 byte order.
 *
 * Processes ONLY public verification artifacts. Never reads witnesses or keys.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const BN254_P =
  21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const BN254_R =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function be32Hex(decStr, modulus, label) {
  const n = BigInt(decStr);
  if (n < 0n || n >= modulus) {
    throw new Error(`${label} out of canonical range: ${decStr}`);
  }
  return n.toString(16).padStart(64, "0");
}

function beU32Hex(num) {
  if (!Number.isInteger(num) || num < 0 || num > 0xffffffff) {
    throw new Error(`Invalid u32: ${num}`);
  }
  return num.toString(16).padStart(8, "0");
}

function encodeG1(pt, label) {
  return (
    be32Hex(pt[0], BN254_P, `${label}.x`) +
    be32Hex(pt[1], BN254_P, `${label}.y`)
  );
}

/**
 * Spec Section 3.3 / 10.1: snarkjs emits `[c0, c1]` (real, imaginary).
 * - `c1_first` (ACF / EIP-197): `be32(x.c1) || be32(x.c0) || be32(y.c1) || be32(y.c0)`
 * - `c0_first` (negative control): `be32(x.c0) || be32(x.c1) || be32(y.c0) || be32(y.c1)`
 */
function encodeG2(pt, order, label) {
  const x0 = be32Hex(pt[0][0], BN254_P, `${label}.x.c0`);
  const x1 = be32Hex(pt[0][1], BN254_P, `${label}.x.c1`);
  const y0 = be32Hex(pt[1][0], BN254_P, `${label}.y.c0`);
  const y1 = be32Hex(pt[1][1], BN254_P, `${label}.y.c1`);
  if (order === "c1_first") {
    return x1 + x0 + y1 + y0;
  }
  return x0 + x1 + y0 + y1;
}

export function convertSnarkjsArtifacts(vkJson, proofJson, publicJson) {
  if (vkJson.protocol !== "groth16" || vkJson.curve !== "bn128") {
    throw new Error("ERR_UNSUPPORTED: VK protocol/curve");
  }
  if (proofJson.protocol !== "groth16" || proofJson.curve !== "bn128") {
    throw new Error("ERR_UNSUPPORTED: proof protocol/curve");
  }
  if (vkJson.IC.length !== vkJson.nPublic + 1) {
    throw new Error("ERR_PUBLIC_INPUT_COUNT: VK IC length mismatch");
  }
  if (publicJson.length !== vkJson.nPublic) {
    throw new Error("ERR_PUBLIC_INPUT_COUNT: public.json length mismatch");
  }

  const encodeProofWithOrder = (order) =>
    encodeG1(proofJson.pi_a, "pi_a") +
    encodeG2(proofJson.pi_b, order, "pi_b") +
    encodeG1(proofJson.pi_c, "pi_c");

  const encodeVkWithOrder = (order) =>
    encodeG1(vkJson.vk_alpha_1, "vk_alpha_1") +
    encodeG2(vkJson.vk_beta_2, order, "vk_beta_2") +
    encodeG2(vkJson.vk_gamma_2, order, "vk_gamma_2") +
    encodeG2(vkJson.vk_delta_2, order, "vk_delta_2") +
    beU32Hex(vkJson.IC.length) +
    vkJson.IC.map((ic, idx) => encodeG1(ic, `IC[${idx}]`)).join("");

  const publicSignalsHex = publicJson.map((s, idx) =>
    be32Hex(s, BN254_R, `public[${idx}]`),
  );

  return {
    proof_c1_first_hex: encodeProofWithOrder("c1_first"),
    proof_c0_first_hex: encodeProofWithOrder("c0_first"),
    vk_c1_first_hex: encodeVkWithOrder("c1_first"),
    vk_c0_first_hex: encodeVkWithOrder("c0_first"),
    public_signals_hex: publicSignalsHex,
    public_inputs_concat_hex: publicSignalsHex.join(""),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const dir = process.argv[2];
  if (!dir) {
    console.error("Usage: node convert_snarkjs_public.mjs <artifacts-dir>");
    process.exit(1);
  }
  const vk = JSON.parse(
    readFileSync(resolve(dir, "verification_key.json"), "utf8"),
  );
  const proof = JSON.parse(readFileSync(resolve(dir, "proof.json"), "utf8"));
  const pub = JSON.parse(readFileSync(resolve(dir, "public.json"), "utf8"));
  console.log(JSON.stringify(convertSnarkjsArtifacts(vk, proof, pub), null, 2));
}
