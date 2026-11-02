import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  AcfError,
  bytesToHex,
  decodeFp,
  decodeFr,
  decodeG1,
  decodeG2,
  encodeFp,
  encodeFr,
  encodeG1,
  encodeG2,
  hexToBytes,
} from "../src/index.js";

interface Expected {
  readonly ok: boolean;
  readonly output_hex?: string;
  readonly error?: string;
}

interface TestVector {
  readonly id: string;
  readonly description: string;
  readonly operation: string;
  readonly input_hex: string;
  readonly expected: Expected;
  readonly tags: readonly string[];
  readonly tx_hash?: string;
}

const currentDir = dirname(fileURLToPath(import.meta.url));
const vectorsRoot = resolve(currentDir, "../../../spec/vectors");

function collectVectorFiles(dir: string, out: string[]): void {
  const entries = readdirSync(dir).sort();
  for (const entry of entries) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      collectVectorFiles(full, out);
    } else if (entry.endsWith(".json") && entry !== "schema.json") {
      out.push(full);
    }
  }
}

function runPrimitiveOp(
  operation: string,
  input: Uint8Array,
): Uint8Array | null {
  switch (operation) {
    case "decode_fp":
      return encodeFp(decodeFp(input));
    case "decode_fr":
      return encodeFr(decodeFr(input));
    case "decode_g1":
      return encodeG1(decodeG1(input));
    case "decode_g2":
      return encodeG2(decodeG2(input));
    case "decode_proof":
    case "decode_vk":
    case "decode_public_inputs":
      return null;
    default:
      throw new Error(`unknown vector operation: ${operation}`);
  }
}

describe("ACF conformance test vectors in TypeScript (Spec Section 12)", () => {
  const files: string[] = [];
  collectVectorFiles(vectorsRoot, files);

  it("finds vector files", () => {
    expect(files.length).toBeGreaterThan(0);
  });

  const seenIds = new Set<string>();
  let executedCount = 0;

  for (const file of files) {
    const relFile = file.slice(vectorsRoot.length + 1);
    const content = readFileSync(file, "utf8");
    const vectors: readonly TestVector[] = JSON.parse(content) as TestVector[];

    describe(`File: ${relFile}`, () => {
      for (const vec of vectors) {
        it(`Vector: ${vec.id}`, () => {
          expect(seenIds.has(vec.id)).toBe(false);
          seenIds.add(vec.id);

          expect(vec.description.length).toBeGreaterThan(0);
          expect(vec.tags.length).toBeGreaterThan(0);

          const inputBytes = hexToBytes(vec.input_hex);

          if (vec.expected.ok) {
            let encoded: Uint8Array | null = null;
            try {
              encoded = runPrimitiveOp(vec.operation, inputBytes);
            } catch (err: unknown) {
              if (err instanceof AcfError) {
                throw new Error(
                  `Vector '${vec.id}' expected ok=true, got error ${err.code}`,
                );
              }
              throw err;
            }

            if (encoded === null) {
              // Skipped (Phase 3 Groth16 objects)
              return;
            }

            executedCount++;
            // Lossless round-trip check
            expect(bytesToHex(encoded)).toBe(vec.input_hex);

            if (vec.expected.output_hex !== undefined) {
              expect(bytesToHex(encoded)).toBe(vec.expected.output_hex);
            }
          } else {
            let threw = false;
            let actualCode: string | undefined;

            try {
              runPrimitiveOp(vec.operation, inputBytes);
            } catch (err: unknown) {
              if (err instanceof AcfError) {
                threw = true;
                actualCode = err.code;
              } else {
                throw err;
              }
            }

            executedCount++;
            expect(threw).toBe(true);
            expect(actualCode).toBe(vec.expected.error);
          }
        });
      }
    });
  }

  it("executed at least 60 primitive vectors", () => {
    expect(executedCount).toBeGreaterThanOrEqual(60);
  });
});
