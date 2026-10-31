import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ACF_ERROR_CODES, AcfError } from "../src/index.js";

const currentDir = dirname(fileURLToPath(import.meta.url));
const rustLibPath = resolve(
  currentDir,
  "../../../crates/astrolabe-core/src/lib.rs",
);

describe("ACF error codes (Spec Section 11)", () => {
  it("matches the Rust AcfError variants and string codes one-to-one", () => {
    const rustSource = readFileSync(rustLibPath, "utf8");
    const matchArmRegex = /Self::(\w+)\s*=>\s*"(ERR_[A-Z0-9_]+)"/g;
    const rustEntries: Array<readonly [string, string]> = [];

    for (const match of rustSource.matchAll(matchArmRegex)) {
      const variant = match[1];
      const code = match[2];
      if (variant !== undefined && code !== undefined) {
        rustEntries.push([variant, code]);
      }
    }

    expect(rustEntries.length).toBeGreaterThan(0);

    const tsEntries = Object.entries(ACF_ERROR_CODES);
    expect(tsEntries).toEqual(rustEntries);

    for (const [, code] of tsEntries) {
      const err = new AcfError(code);
      expect(err.code).toBe(code);
      expect(err.message).toBe(code);
    }
  });
});
