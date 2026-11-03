import json
import os

PROOF_HEX = (
    "0d7878bb471f16e0e8366778a28829db4d5ff09baf9517695cd0d23cd2c1b2e8"
    "0f0e8336dd5bd193b1918a13dce96010b06db87f9d99af62e28eb1d134124d58"
    "100792e3175ff2f52bb403fb1b33eb62db1e30b06dea369186faaaaae25f6b74"
    "27108db79d78a66e9de40d156b0afd421265f7c50e53aa068a896698fb586ac1"
    "0fe25410b2b341224247825bd25acce576201d3d828781ffe6ca4a5c81b3e356"
    "09d861e52f7de282f16a79f0b0d895a19e063af5c3a265ecbcf9f65c1598acd2"
    "06e4d97e80404e4de3d846689cb020de2e02d2594bd93c19a7ccea4241f33609"
    "2556ecd9998b1858547bed640f06afdb213a0af2ccff62421be219c5546162e8"
)

VK_HEX = (
    "2c3eca3b96938a231158ff0690bd4af0a7b020cc9bf9ec649bfd1a6f9fedc284"
    "1e81947887a20eff0366a4cc56891097b8f2c07f27dd57fd47df7f24aab2e161"
    "0c02c8193eedbc72fd4a8fb8422cb4632057134d80413a668c9987719ad27c31"
    "2a239d5389fe740be6918dcc95e259280368f518df3c77a800925d9d368996e4"
    "2534e71a3d36a2f7dc927fc673a87299788d7a214f1151f7abf9723c4ee31535"
    "1d9a94d377c6dc20b8bc05dcb1f9adaa2fabe4c540645eda3c7594b85676990e"
    "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"
    "1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"
    "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"
    "12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
    "2f31a9ffbec70638647f26bc7a49c866fcbf7ac20aa7408e695004da9ef5e25e"
    "165ff901385851b84ecf6c366fe61e641b7dab33cb9926e8288d65d36e168962"
    "1238f3a5cc6a9c9fe7e18f02041403c1124164ef5b00b7e7ff635a498d09c242"
    "0d71091d690ae6268f2db7e7cc97e9e67415ba92e0e90ea2f9172da571523152"
    "00000003"
    "1f9ca84019247d9ea29cc5d1d3cee12b76bbc2385586cdbad63a6cd65addd2e6"
    "1af0ff10ff1e6b6e4be920f6328ca0f437d45ea4cf9223bb2ef2e38ff1fc6c31"
    "11584ff9c88f8138175bd526cd78145da96cba2021e87f8af4c74a24dd82d1a3"
    "1296a9041b061089d28d65f1a7807316a6927151dd3c359f4f2a8ec71f0a5a60"
    "2f0776c05fc028592d2a05f66c4798e39eaf595a5a8aebc07bb583d03affd7da"
    "09790bda24e938bba6be23e1a7cfdd6bd635e1ed49c5204da7c25ad32354ad19"
)

PI_HEX = (
    "0000000000000000000000000000000000000000000000000000000000000021"
    "0000000000000000000000000000000000000000000000000000000000000003"
)

G2_NON_SUBGROUP_HEX = (
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "28a7a81c6bf2a75dc9f0125bb581747e9e6b33fc3b2710a2309cef97a3163c65"
    "23712136978ed49faf2120ca4f7f71cfd4e7b46ffa0ea89edbc94ddc59238e9f"
)

P_HEX = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
R_HEX = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"

# Envelope headers (12 bytes = 24 hex)
PROOF_ENV_HDR = "415354520101010100000100"  # ASTR, 01, Proof(01), BN254(01), Groth16(01), 256
VK_ENV_HDR = "415354520102010100000284"     # ASTR, 01, VK(02), BN254(01), Groth16(01), 644
PI_ENV_HDR = "415354520103010100000040"     # ASTR, 01, PI(03), BN254(01), Groth16(01), 64

# Valid envelopes
envelopes_valid = [
    {
        "id": "circom-multiplier-proof-envelope-valid",
        "description": "Valid ACF v0.1 envelope wrapping 256-byte Groth16 proof (ASTR magic, spec_ver 0x01, kind 0x01 proof, curve 0x01 bn254, system 0x01 groth16). Source: snarkjs 0.7.6 + ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR + PROOF_HEX,
        "expected": {
            "ok": True,
            "output_hex": PROOF_ENV_HDR + PROOF_HEX
        },
        "tags": ["envelope", "proof", "groth16", "valid"]
    },
    {
        "id": "circom-multiplier-vk-envelope-valid",
        "description": "Valid ACF v0.1 envelope wrapping 644-byte Groth16 verification key (kind 0x02 vk, curve 0x01 bn254, system 0x01 groth16, n_ic = 3). Source: snarkjs 0.7.6 + ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": VK_ENV_HDR + VK_HEX,
        "expected": {
            "ok": True,
            "output_hex": VK_ENV_HDR + VK_HEX
        },
        "tags": ["envelope", "vk", "groth16", "valid"]
    },
    {
        "id": "circom-multiplier-public-inputs-envelope-valid",
        "description": "Valid ACF v0.1 envelope wrapping 64-byte Groth16 public inputs (kind 0x03 public_inputs, curve 0x01 bn254, system 0x01 groth16, 2 inputs). Source: snarkjs 0.7.6 + ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PI_ENV_HDR + PI_HEX,
        "expected": {
            "ok": True,
            "output_hex": PI_ENV_HDR + PI_HEX
        },
        "tags": ["envelope", "public-inputs", "groth16", "valid"]
    }
]

# Public input count vectors
count_vectors = [
    {
        "id": "groth16-public-input-count-match-valid",
        "description": "Public inputs count (2 inputs: s_0, s_1) matches VK IC length minus 1 (n_ic = 3 => n_public = 2). Source: ACF Spec Section 4.3, Section 9 Rule 5, and Circom Multiplier2.",
        "operation": "verify_public_inputs_count",
        "input_hex": VK_HEX + PI_HEX,
        "expected": {
            "ok": True
        },
        "tags": ["groth16", "public-inputs", "count", "valid"]
    },
    {
        "id": "groth16-public-input-count-too-few-invalid",
        "description": "Public inputs count (1 input: 32 bytes) is less than VK IC length minus 1 (n_ic = 3 => n_public = 2); rejected with ERR_PUBLIC_INPUT_COUNT. Source: ACF Spec Section 4.3 and Section 9 Rule 5.",
        "operation": "verify_public_inputs_count",
        "input_hex": VK_HEX + PI_HEX[:64],
        "expected": {
            "ok": False,
            "error": "ERR_PUBLIC_INPUT_COUNT"
        },
        "tags": ["groth16", "public-inputs", "count", "invalid"]
    },
    {
        "id": "groth16-public-input-count-too-many-invalid",
        "description": "Public inputs count (3 inputs: 96 bytes) is greater than VK IC length minus 1 (n_ic = 3 => n_public = 2); rejected with ERR_PUBLIC_INPUT_COUNT. Source: ACF Spec Section 4.3 and Section 9 Rule 5.",
        "operation": "verify_public_inputs_count",
        "input_hex": VK_HEX + PI_HEX + "0000000000000000000000000000000000000000000000000000000000000007",
        "expected": {
            "ok": False,
            "error": "ERR_PUBLIC_INPUT_COUNT"
        },
        "tags": ["groth16", "public-inputs", "count", "invalid"]
    },
    {
        "id": "groth16-vk-zero-ic-count-invalid",
        "description": "Groth16 VK with n_ic = 0 (452 bytes); rejected with ERR_PUBLIC_INPUT_COUNT because n_ic = n_public + 1 requires n_ic >= 1. Source: ACF Spec Section 4.2 and Section 9 Rule 5.",
        "operation": "decode_vk",
        "input_hex": VK_HEX[:448*2] + "00000000",
        "expected": {
            "ok": False,
            "error": "ERR_PUBLIC_INPUT_COUNT"
        },
        "tags": ["groth16", "vk", "count", "invalid"]
    }
]

# Invalid length vectors
length_vectors = [
    {
        "id": "groth16-proof-truncated-255-bytes-invalid",
        "description": "Groth16 proof payload truncated to 255 bytes (expected 256 bytes); rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 4.1.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:-2],
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["groth16", "proof", "length", "invalid"]
    },
    {
        "id": "groth16-proof-overlong-257-bytes-invalid",
        "description": "Groth16 proof payload extended to 257 bytes with trailing byte; rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 4.1.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX + "00",
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["groth16", "proof", "length", "invalid"]
    },
    {
        "id": "groth16-vk-truncated-header-451-bytes-invalid",
        "description": "Groth16 verification key payload truncated to 451 bytes (less than 452-byte header); rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 4.2.",
        "operation": "decode_vk",
        "input_hex": VK_HEX[:451*2],
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["groth16", "vk", "length", "invalid"]
    },
    {
        "id": "groth16-vk-truncated-ic-643-bytes-invalid",
        "description": "Groth16 verification key declaring n_ic = 3 (expected 644 bytes) truncated to 643 bytes; rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 4.2.",
        "operation": "decode_vk",
        "input_hex": VK_HEX[:-2],
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["groth16", "vk", "length", "invalid"]
    },
    {
        "id": "groth16-vk-overlong-ic-645-bytes-invalid",
        "description": "Groth16 verification key declaring n_ic = 3 (expected 644 bytes) extended to 645 bytes; rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 4.2.",
        "operation": "decode_vk",
        "input_hex": VK_HEX + "00",
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["groth16", "vk", "length", "invalid"]
    },
    {
        "id": "groth16-public-inputs-not-multiple-32-invalid",
        "description": "Groth16 public inputs payload of 63 bytes (not a multiple of 32 bytes); rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 4.3.",
        "operation": "decode_public_inputs",
        "input_hex": PI_HEX[:-2],
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["groth16", "public-inputs", "length", "invalid"]
    },
    {
        "id": "envelope-truncated-header-11-bytes-invalid",
        "description": "ACF envelope truncated to 11 bytes (header requires 12 bytes); rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": (PROOF_ENV_HDR + PROOF_HEX)[:22],
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["envelope", "length", "invalid"]
    },
    {
        "id": "envelope-payload-truncated-invalid",
        "description": "ACF envelope declaring 256 payload bytes but truncated to 255 payload bytes; rejected with ERR_BAD_LENGTH. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR + PROOF_HEX[:-2],
        "expected": {
            "ok": False,
            "error": "ERR_BAD_LENGTH"
        },
        "tags": ["envelope", "length", "invalid"]
    },
    {
        "id": "envelope-trailing-bytes-invalid",
        "description": "ACF envelope with 1 extra trailing byte after declared payload_len; rejected with ERR_TRAILING_BYTES. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR + PROOF_HEX + "aa",
        "expected": {
            "ok": False,
            "error": "ERR_TRAILING_BYTES"
        },
        "tags": ["envelope", "trailing-bytes", "invalid"]
    },
    {
        "id": "envelope-bad-magic-invalid",
        "description": "ACF envelope with incorrect magic bytes (NOPE instead of ASTR); rejected with ERR_UNSUPPORTED. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": "4e4f5045" + PROOF_ENV_HDR[8:] + PROOF_HEX,
        "expected": {
            "ok": False,
            "error": "ERR_UNSUPPORTED"
        },
        "tags": ["envelope", "magic", "invalid"]
    },
    {
        "id": "envelope-unsupported-spec-ver-invalid",
        "description": "ACF envelope with unknown spec_ver 0x02 (only 0x01 supported in ACF 0.x); rejected with ERR_UNSUPPORTED. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR[:8] + "02" + PROOF_ENV_HDR[10:] + PROOF_HEX,
        "expected": {
            "ok": False,
            "error": "ERR_UNSUPPORTED"
        },
        "tags": ["envelope", "version", "invalid"]
    },
    {
        "id": "envelope-unsupported-kind-invalid",
        "description": "ACF envelope with unknown kind 0x99; rejected with ERR_UNSUPPORTED. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR[:10] + "99" + PROOF_ENV_HDR[12:] + PROOF_HEX,
        "expected": {
            "ok": False,
            "error": "ERR_UNSUPPORTED"
        },
        "tags": ["envelope", "kind", "invalid"]
    },
    {
        "id": "envelope-unsupported-curve-invalid",
        "description": "ACF envelope with unsupported curve 0x02 (BLS12-381 reserved, not v0.1); rejected with ERR_UNSUPPORTED. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR[:12] + "02" + PROOF_ENV_HDR[14:] + PROOF_HEX,
        "expected": {
            "ok": False,
            "error": "ERR_UNSUPPORTED"
        },
        "tags": ["envelope", "curve", "invalid"]
    },
    {
        "id": "envelope-unsupported-system-invalid",
        "description": "ACF envelope with unsupported proof system 0x02 (PLONK reserved, not v0.1); rejected with ERR_UNSUPPORTED. Source: ACF Spec Section 5.",
        "operation": "decode_envelope",
        "input_hex": PROOF_ENV_HDR[:14] + "02" + PROOF_ENV_HDR[16:] + PROOF_HEX,
        "expected": {
            "ok": False,
            "error": "ERR_UNSUPPORTED"
        },
        "tags": ["envelope", "system", "invalid"]
    }
]

# Invalid field vectors
field_vectors = [
    {
        "id": "groth16-proof-point-a-field-ge-p-invalid",
        "description": "Groth16 proof with A.x set to field modulus p; rejected with ERR_NON_CANONICAL_FIELD. Source: ACF Spec Section 3.1 and Section 9 Rule 2.",
        "operation": "decode_proof",
        "input_hex": P_HEX + PROOF_HEX[64:],
        "expected": {
            "ok": False,
            "error": "ERR_NON_CANONICAL_FIELD"
        },
        "tags": ["groth16", "proof", "field", "invalid"]
    },
    {
        "id": "groth16-proof-point-b-field-ge-p-invalid",
        "description": "Groth16 proof with B.x.c1 set to field modulus p; rejected with ERR_NON_CANONICAL_FIELD. Source: ACF Spec Section 3.1, Section 3.3, and Section 9 Rule 2.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:128] + P_HEX + PROOF_HEX[128+64:],
        "expected": {
            "ok": False,
            "error": "ERR_NON_CANONICAL_FIELD"
        },
        "tags": ["groth16", "proof", "field", "invalid"]
    },
    {
        "id": "groth16-proof-point-c-field-ge-p-invalid",
        "description": "Groth16 proof with C.y set to field modulus p; rejected with ERR_NON_CANONICAL_FIELD. Source: ACF Spec Section 3.1 and Section 9 Rule 2.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:192*2 + 64] + P_HEX,
        "expected": {
            "ok": False,
            "error": "ERR_NON_CANONICAL_FIELD"
        },
        "tags": ["groth16", "proof", "field", "invalid"]
    },
    {
        "id": "groth16-public-inputs-scalar-ge-r-invalid",
        "description": "Groth16 public input s_0 set to scalar modulus r; rejected with ERR_NON_CANONICAL_FIELD (must never reduce modulo r). Source: ACF Spec Section 3.4 and Phase 1 Experiment 4.",
        "operation": "decode_public_inputs",
        "input_hex": R_HEX + PI_HEX[64:],
        "expected": {
            "ok": False,
            "error": "ERR_NON_CANONICAL_FIELD"
        },
        "tags": ["groth16", "public-inputs", "field", "invalid"]
    },
    {
        "id": "groth16-vk-alpha-field-ge-p-invalid",
        "description": "Groth16 verification key with alpha.x set to field modulus p; rejected with ERR_NON_CANONICAL_FIELD. Source: ACF Spec Section 3.1 and Section 9 Rule 2.",
        "operation": "decode_vk",
        "input_hex": P_HEX + VK_HEX[64:],
        "expected": {
            "ok": False,
            "error": "ERR_NON_CANONICAL_FIELD"
        },
        "tags": ["groth16", "vk", "field", "invalid"]
    }
]

# Invalid curve vectors
# In Proof, A.y is at chars 64..128. Change byte to make it off curve.
# For A: (x, y) = (PROOF_HEX[0..64], PROOF_HEX[64..128]).
# If y is incremented by 1, (x, y+1) is off curve y^2 = x^3 + 3.
# Let's compute y + 1 hex:
ay_int = int(PROOF_HEX[64:128], 16)
ay_off = f"{(ay_int + 1):064x}"

# In VK, alpha.y is at chars 64..128:
alpha_y_int = int(VK_HEX[64:128], 16)
alpha_y_off = f"{(alpha_y_int + 1):064x}"

curve_vectors = [
    {
        "id": "groth16-proof-point-a-off-curve-invalid",
        "description": "Groth16 proof with point A off curve y^2 = x^3 + 3; rejected with ERR_NOT_ON_CURVE. Source: ACF Spec Section 3.2 and Section 9 Rule 3.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:64] + ay_off + PROOF_HEX[128:],
        "expected": {
            "ok": False,
            "error": "ERR_NOT_ON_CURVE"
        },
        "tags": ["groth16", "proof", "curve", "invalid"]
    },
    {
        "id": "groth16-vk-alpha-off-curve-invalid",
        "description": "Groth16 verification key with point alpha off curve y^2 = x^3 + 3; rejected with ERR_NOT_ON_CURVE. Source: ACF Spec Section 3.2 and Section 9 Rule 3.",
        "operation": "decode_vk",
        "input_hex": VK_HEX[:64] + alpha_y_off + VK_HEX[128:],
        "expected": {
            "ok": False,
            "error": "ERR_NOT_ON_CURVE"
        },
        "tags": ["groth16", "vk", "curve", "invalid"]
    }
]

# Invalid subgroup vectors
subgroup_vectors = [
    {
        "id": "groth16-proof-point-b-not-in-subgroup-invalid",
        "description": "Groth16 proof with point B on twist curve but outside order-r subgroup; rejected with ERR_NOT_IN_SUBGROUP. Source: ACF Spec Section 3.3, Section 9 Rule 4, and Phase 1 Experiment 2.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:128] + G2_NON_SUBGROUP_HEX + PROOF_HEX[128+256:],
        "expected": {
            "ok": False,
            "error": "ERR_NOT_IN_SUBGROUP"
        },
        "tags": ["groth16", "proof", "subgroup", "invalid"]
    },
    {
        "id": "groth16-vk-point-beta-not-in-subgroup-invalid",
        "description": "Groth16 verification key with point beta on twist curve but outside order-r subgroup; rejected with ERR_NOT_IN_SUBGROUP. Source: ACF Spec Section 3.3, Section 9 Rule 4, and Phase 1 Experiment 2.",
        "operation": "decode_vk",
        "input_hex": VK_HEX[:128] + G2_NON_SUBGROUP_HEX + VK_HEX[128+256:],
        "expected": {
            "ok": False,
            "error": "ERR_NOT_IN_SUBGROUP"
        },
        "tags": ["groth16", "vk", "subgroup", "invalid"]
    }
]

# Degenerate proof infinity vectors (Spec §9 Rule 6)
G1_ZERO = "00" * 64
G2_ZERO = "00" * 128

infinity_vectors = [
    {
        "id": "groth16-proof-point-a-infinity-invalid",
        "description": "Groth16 proof with degenerate point A at infinity (64 zero bytes); rejected with ERR_INVALID_PROOF. Source: ACF Spec Section 8 Step 3 and Section 9 Rule 6.",
        "operation": "decode_proof",
        "input_hex": G1_ZERO + PROOF_HEX[128:],
        "expected": {
            "ok": False,
            "error": "ERR_INVALID_PROOF"
        },
        "tags": ["groth16", "proof", "infinity", "invalid"]
    },
    {
        "id": "groth16-proof-point-b-infinity-invalid",
        "description": "Groth16 proof with degenerate point B at infinity (128 zero bytes); rejected with ERR_INVALID_PROOF. Source: ACF Spec Section 8 Step 3 and Section 9 Rule 6.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:128] + G2_ZERO + PROOF_HEX[128+256:],
        "expected": {
            "ok": False,
            "error": "ERR_INVALID_PROOF"
        },
        "tags": ["groth16", "proof", "infinity", "invalid"]
    },
    {
        "id": "groth16-proof-point-c-infinity-invalid",
        "description": "Groth16 proof with degenerate point C at infinity (64 zero bytes); rejected with ERR_INVALID_PROOF. Source: ACF Spec Section 8 Step 3 and Section 9 Rule 6.",
        "operation": "decode_proof",
        "input_hex": PROOF_HEX[:192*2] + G1_ZERO,
        "expected": {
            "ok": False,
            "error": "ERR_INVALID_PROOF"
        },
        "tags": ["groth16", "proof", "infinity", "invalid"]
    }
]

files = [
    ("spec/vectors/valid/groth16-envelopes.json", envelopes_valid),
    ("spec/vectors/public-input-count/groth16-count.json", count_vectors),
    ("spec/vectors/invalid-length/groth16-length.json", length_vectors),
    ("spec/vectors/invalid-field/groth16-field.json", field_vectors),
    ("spec/vectors/invalid-curve/groth16-curve.json", curve_vectors),
    ("spec/vectors/invalid-subgroup/groth16-subgroup.json", subgroup_vectors),
    ("spec/vectors/infinity/groth16-infinity.json", infinity_vectors),
]

for path, data in files:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print(f"Wrote {len(data)} vectors to {path}")
