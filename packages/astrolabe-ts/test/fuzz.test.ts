import { describe, it, expect } from "vitest";
import {
  decodeG1,
  decodeG2,
  decodeProof,
  decodeVerificationKey,
  decodePublicInputs,
  decodeEnvelope,
  encodeG1,
  encodeG2,
  encodeProof,
  encodeVerificationKey,
  encodePublicInputs,
  encodeEnvelope,
  parseSnarkjsProof,
  parseSnarkjsVk,
  parseSnarkjsPublicInputs,
  parseDecFp,
  parseDecFr,
  AcfError,
} from "../src/index.js";

class SimpleRng {
  private state: bigint;

  constructor(seed: bigint = 0x123456789abcdefn) {
    this.state = seed === 0n ? 0xdeadbeefcafebaben : seed;
  }

  nextU8(): number {
    this.state = (this.state * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
    return Number((this.state >> 56n) & 0xffn);
  }

  fillBytes(arr: Uint8Array): void {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = this.nextU8();
    }
  }
}

describe("Phase 7: TypeScript Codec & Parser Fuzzing Suite", () => {
  it("decodeG1 never panics and roundtrips valid outputs", () => {
    const rng = new SimpleRng(0x1111n);
    const buf = new Uint8Array(64);

    for (let i = 0; i < 2_000; i++) {
      rng.fillBytes(buf);
      try {
        const pt = decodeG1(buf);
        const enc = encodeG1(pt);
        expect(enc).toEqual(buf);
        const rt = decodeG1(enc);
        expect(encodeG1(rt)).toEqual(enc);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }
    }
  });

  it("decodeG2 never panics and roundtrips valid outputs", () => {
    const rng = new SimpleRng(0x2222n);
    const buf = new Uint8Array(128);

    for (let i = 0; i < 2_000; i++) {
      rng.fillBytes(buf);
      try {
        const pt = decodeG2(buf);
        const enc = encodeG2(pt);
        expect(enc).toEqual(buf);
        const rt = decodeG2(enc);
        expect(encodeG2(rt)).toEqual(enc);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }
    }
  });

  it("decodeProof never panics and roundtrips valid outputs", () => {
    const rng = new SimpleRng(0x3333n);
    const buf = new Uint8Array(256);

    for (let i = 0; i < 1_000; i++) {
      rng.fillBytes(buf);
      try {
        const proof = decodeProof(buf);
        const enc = encodeProof(proof);
        expect(enc).toEqual(buf);
        const rt = decodeProof(enc);
        expect(encodeProof(rt)).toEqual(enc);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }
    }
  });

  it("decodeVerificationKey and decodePublicInputs never throw non-AcfError", () => {
    const rng = new SimpleRng(0x4444n);
    const buf = new Uint8Array(516);

    for (let i = 0; i < 500; i++) {
      rng.fillBytes(buf);
      try {
        const vk = decodeVerificationKey(buf);
        const enc = encodeVerificationKey(vk);
        expect(enc).toEqual(buf);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }

      try {
        const pi = decodePublicInputs(buf.slice(0, 64));
        const enc = encodePublicInputs(pi);
        expect(enc).toEqual(buf.slice(0, 64));
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }

      try {
        const env = decodeEnvelope(buf.slice(0, 268));
        const enc = encodeEnvelope(env);
        expect(enc).toEqual(buf.slice(0, 268));
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }
    }
  });

  it("snarkjs parser gracefully rejects adversarial strings without throwing non-AcfError", () => {
    const adversarial = [
      "",
      "0",
      "-1",
      "000",
      "123abc456",
      " 123 ",
      "null",
      "undefined",
      "true",
      "false",
      "{}",
      "[]",
      "{\"pi_a\": null}",
      "{\"pi_a\": [1, 2, 3]}",
      "[[1, 2], [3, 4], [5, 6]]",
      "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
      "21888242871839275222246405745257275088696311157297823662689037894645226208583",
      "21888242871839275222246405745257275088548364400416034343698204186575808495617",
      "99999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
    ];

    for (const s of adversarial) {
      try {
        parseDecFp(s);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }

      try {
        parseDecFr(s);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }

      try {
        parseSnarkjsProof(s);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }

      try {
        parseSnarkjsVk(s);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }

      try {
        parseSnarkjsPublicInputs(s);
      } catch (err) {
        expect(err).toBeInstanceOf(AcfError);
      }
    }
  });
});
