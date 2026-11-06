import { concatBytes } from "./bytes.js";
import {
  BN254_R,
  G1_BYTE_LEN,
  G1_COEFF_B,
  G2_BYTE_LEN,
  G2_TWIST_COEFF_B,
} from "./constants.js";
import { AcfError } from "./errors.js";
import {
  addFp,
  addFp2,
  decodeFp,
  decodeFp2,
  doubleFp2,
  encodeFp,
  encodeFp2,
  equalsFp2,
  type Fp,
  type Fp2,
  FP2_ONE,
  FP2_ZERO,
  isZeroFp2,
  mulFp,
  mulFp2,
  squareFp,
  squareFp2,
  subFp2,
} from "./field.js";

/**
 * Validated BN254 G1 point on `y^2 = x^3 + 3` over `Fp`, or the point at infinity
 * (ACF Specification Section 3.2 and Section 9 Rules 1-3).
 */
export class G1 {
  public static readonly INFINITY = new G1(null);
  public static readonly GENERATOR = new G1({ x: 1n, y: 2n });

  public readonly coordinates: { readonly x: Fp; readonly y: Fp } | null;

  public constructor(
    coords: { readonly x: Fp; readonly y: Fp } | null,
  ) {
    this.coordinates = coords;
  }

  public isInfinity(): boolean {
    return this.coordinates === null;
  }

  public static fromCoordinates(x: Fp, y: Fp): G1 {
    if (x === 0n && y === 0n) {
      return G1.INFINITY;
    }
    const lhs = squareFp(y);
    const rhs = addFp(mulFp(squareFp(x), x), G1_COEFF_B);
    if (lhs !== rhs) {
      throw new AcfError("ERR_NOT_ON_CURVE");
    }
    return new G1({ x, y });
  }
}

/**
 * Validated BN254 G2 point in the prime-order-`r` subgroup of the twist curve
 * `y^2 = x^3 + 3/(9 + u)` over `Fp2`, or the point at infinity
 * (ACF Specification Section 3.3 and Section 9 Rules 1-4).
 */
export class G2 {
  public static readonly INFINITY = new G2(null);
  public static readonly GENERATOR = new G2({
    x: {
      c0: 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6edn,
      c1: 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2n,
    },
    y: {
      c0: 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daan,
      c1: 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975bn,
    },
  });

  public readonly coordinates: { readonly x: Fp2; readonly y: Fp2 } | null;

  public constructor(
    coords: { readonly x: Fp2; readonly y: Fp2 } | null,
  ) {
    this.coordinates = coords;
  }

  public isInfinity(): boolean {
    return this.coordinates === null;
  }

  public static fromCoordinates(x: Fp2, y: Fp2): G2 {
    if (isZeroFp2(x) && isZeroFp2(y)) {
      return G2.INFINITY;
    }
    const lhs = squareFp2(y);
    const rhs = addFp2(mulFp2(squareFp2(x), x), G2_TWIST_COEFF_B);
    if (!equalsFp2(lhs, rhs)) {
      throw new AcfError("ERR_NOT_ON_CURVE");
    }
    if (!isInG2Subgroup(x, y)) {
      throw new AcfError("ERR_NOT_IN_SUBGROUP");
    }
    return new G2({ x, y });
  }
}

// --- Jacobian projective arithmetic for G2 subgroup membership ---

interface G2Jacobian {
  readonly x: Fp2;
  readonly y: Fp2;
  readonly z: Fp2;
}

const G2_JACOBIAN_INFINITY: G2Jacobian = {
  x: FP2_ONE,
  y: FP2_ONE,
  z: FP2_ZERO,
};

function doubleG2(p: G2Jacobian): G2Jacobian {
  if (isZeroFp2(p.z) || isZeroFp2(p.y)) {
    return G2_JACOBIAN_INFINITY;
  }
  const a = squareFp2(p.x);
  const b = squareFp2(p.y);
  const c = squareFp2(b);
  const d = doubleFp2(subFp2(subFp2(squareFp2(addFp2(p.x, b)), a), c));
  const e = addFp2(doubleFp2(a), a);
  const f = squareFp2(e);
  const x3 = subFp2(f, doubleFp2(d));
  const eightC = doubleFp2(doubleFp2(doubleFp2(c)));
  const y3 = subFp2(mulFp2(e, subFp2(d, x3)), eightC);
  const z3 = doubleFp2(mulFp2(p.y, p.z));
  return { x: x3, y: y3, z: z3 };
}

function addG2(p: G2Jacobian, q: G2Jacobian): G2Jacobian {
  if (isZeroFp2(p.z)) return q;
  if (isZeroFp2(q.z)) return p;

  const z1z1 = squareFp2(p.z);
  const z2z2 = squareFp2(q.z);
  const u1 = mulFp2(p.x, z2z2);
  const u2 = mulFp2(q.x, z1z1);
  const s1 = mulFp2(mulFp2(p.y, q.z), z2z2);
  const s2 = mulFp2(mulFp2(q.y, p.z), z1z1);

  if (equalsFp2(u1, u2)) {
    if (equalsFp2(s1, s2)) {
      return doubleG2(p);
    }
    return G2_JACOBIAN_INFINITY;
  }

  const h = subFp2(u2, u1);
  const i = squareFp2(doubleFp2(h));
  const j = mulFp2(h, i);
  const r = doubleFp2(subFp2(s2, s1));
  const v = mulFp2(u1, i);

  const x3 = subFp2(subFp2(squareFp2(r), j), doubleFp2(v));
  const y3 = subFp2(mulFp2(r, subFp2(v, x3)), doubleFp2(mulFp2(s1, j)));
  const z3 = doubleFp2(mulFp2(mulFp2(p.z, q.z), h));

  return { x: x3, y: y3, z: z3 };
}

/**
 * Security hotspot (AGENTS.md Section 11): checks whether an on-curve twist point
 * `(x, y)` lies in the prime-order-`r` G2 subgroup by checking `[r](x, y) == O`.
 */
function isInG2Subgroup(x: Fp2, y: Fp2): boolean {
  const base: G2Jacobian = { x, y, z: FP2_ONE };
  let acc: G2Jacobian = G2_JACOBIAN_INFINITY;
  for (let bit = 254; bit >= 0; bit--) {
    acc = doubleG2(acc);
    if (((BN254_R >> BigInt(bit)) & 1n) === 1n) {
      acc = addG2(acc, base);
    }
  }
  return isZeroFp2(acc.z);
}

// --- Curve Codecs ---

/**
 * Decodes and validates a 64-byte uncompressed G1 point
 * (ACF Spec Section 3.2 and Section 9 Rules 1-3).
 *
 * @throws {AcfError} `ERR_BAD_LENGTH` if `bytes.length !== 64`
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if coordinates `>= p`
 * @throws {AcfError} `ERR_NOT_ON_CURVE` if non-infinity point fails `y^2 = x^3 + 3`
 */
export function decodeG1(bytes: Uint8Array): G1 {
  if (bytes.length !== G1_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  const x = decodeFp(bytes.subarray(0, 32));
  const y = decodeFp(bytes.subarray(32, 64));
  return G1.fromCoordinates(x, y);
}

/**
 * Encodes a G1 point into 64 uncompressed bytes (or 64 zero bytes for infinity, ACF Spec Section 3.2).
 */
export function encodeG1(point: G1): Uint8Array {
  if (point.isInfinity() || point.coordinates === null) {
    return new Uint8Array(G1_BYTE_LEN);
  }
  return concatBytes(
    encodeFp(point.coordinates.x),
    encodeFp(point.coordinates.y),
  );
}

/**
 * Decodes and validates a 128-byte uncompressed G2 point
 * (ACF Spec Section 3.3 and Section 9 Rules 1-4).
 *
 * @throws {AcfError} `ERR_BAD_LENGTH` if `bytes.length !== 128`
 * @throws {AcfError} `ERR_NON_CANONICAL_FIELD` if components `>= p`
 * @throws {AcfError} `ERR_NOT_ON_CURVE` if non-infinity point fails twist curve equation
 * @throws {AcfError} `ERR_NOT_IN_SUBGROUP` if point is on twist curve but not in order-`r` subgroup
 */
export function decodeG2(bytes: Uint8Array): G2 {
  if (bytes.length !== G2_BYTE_LEN) {
    throw new AcfError("ERR_BAD_LENGTH");
  }
  const x = decodeFp2(bytes.subarray(0, 64));
  const y = decodeFp2(bytes.subarray(64, 128));
  return G2.fromCoordinates(x, y);
}

/**
 * Encodes a G2 point into 128 uncompressed bytes (or 128 zero bytes for infinity, ACF Spec Section 3.3).
 */
export function encodeG2(point: G2): Uint8Array {
  if (point.isInfinity() || point.coordinates === null) {
    return new Uint8Array(G2_BYTE_LEN);
  }
  return concatBytes(
    encodeFp2(point.coordinates.x),
    encodeFp2(point.coordinates.y),
  );
}
