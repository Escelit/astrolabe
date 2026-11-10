//! Continuous fuzzing regression suite for Astrolabe core codecs and parsers.
//!
//! Generates thousands of randomized inputs, mutations, edge cases, bit flips,
//! and malformed structures to verify that decoders and parsers never panic,
//! crash, or loop indefinitely, and that any valid decode round-trips losslessly.

use astrolabe_core::snarkjs::{
    parse_dec_fp, parse_dec_fr, parse_snarkjs_proof, parse_snarkjs_proof_envelope,
    parse_snarkjs_public_inputs, parse_snarkjs_public_inputs_envelope, parse_snarkjs_vk,
    parse_snarkjs_vk_envelope,
};
use astrolabe_core::{
    decode_envelope, decode_g1, decode_g2, decode_proof, decode_public_inputs, decode_vk,
    encode_envelope, encode_g1, encode_g2, encode_proof, encode_public_inputs, encode_vk, G1, G2,
};

/// Deterministic pseudo-random number generator (xorshift64) for reproducible fuzzing.
struct Prng {
    state: u64,
}

impl Prng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 {
                0xdead_beef_cafe_babe
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() as usize) % bound
        }
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_u8();
        }
    }
}

#[test]
fn fuzz_decode_g1_never_panics_and_roundtrips_when_ok() {
    let mut rng = Prng::new(0x1111);
    let mut buf = [0u8; 64];

    // 1. Completely random 64-byte buffers
    for _ in 0..10_000 {
        rng.fill_bytes(&mut buf);
        if let Ok(pt) = decode_g1(&buf) {
            let enc = encode_g1(pt);
            assert_eq!(enc, buf);
            let rt = decode_g1(&enc).expect("decoded G1 must round-trip");
            assert_eq!(pt, rt);
        }
    }

    // 2. Variable length buffers (0 to 128 bytes)
    let mut var_buf = [0u8; 128];
    for len in 0..128 {
        rng.fill_bytes(&mut var_buf[..len]);
        let _ = decode_g1(&var_buf[..len]);
    }

    // 3. Known valid G1 generator with single bit flips
    let gen_bytes = G1::GENERATOR.encode();
    for byte_idx in 0..64 {
        for bit_idx in 0..8 {
            let mut mutated = gen_bytes;
            mutated[byte_idx] ^= 1 << bit_idx;
            if let Ok(pt) = decode_g1(&mutated) {
                let enc = encode_g1(pt);
                assert_eq!(enc, mutated);
            }
        }
    }
}

#[test]
fn fuzz_decode_g2_never_panics_and_roundtrips_when_ok() {
    let mut rng = Prng::new(0x2222);
    let mut buf = [0u8; 128];

    // 1. Completely random 128-byte buffers
    for _ in 0..10_000 {
        rng.fill_bytes(&mut buf);
        if let Ok(pt) = decode_g2(&buf) {
            let enc = encode_g2(pt);
            assert_eq!(enc, buf);
            let rt = decode_g2(&enc).expect("decoded G2 must round-trip");
            assert_eq!(pt, rt);
        }
    }

    // 2. Variable length buffers (0 to 200 bytes)
    let mut var_buf = [0u8; 200];
    for len in 0..200 {
        rng.fill_bytes(&mut var_buf[..len]);
        let _ = decode_g2(&var_buf[..len]);
    }

    // 3. Known valid G2 generator with single bit flips
    let gen_bytes = G2::GENERATOR.encode();
    for byte_idx in 0..128 {
        for bit_idx in 0..8 {
            let mut mutated = gen_bytes;
            mutated[byte_idx] ^= 1 << bit_idx;
            if let Ok(pt) = decode_g2(&mutated) {
                let enc = encode_g2(pt);
                assert_eq!(enc, mutated);
            }
        }
    }
}

#[test]
fn fuzz_decode_proof_never_panics_and_roundtrips_when_ok() {
    let mut rng = Prng::new(0x3333);
    let mut buf = [0u8; 256];

    for _ in 0..5_000 {
        rng.fill_bytes(&mut buf);
        if let Ok(proof) = decode_proof(&buf) {
            let enc = encode_proof(&proof);
            assert_eq!(enc, buf);
            let rt = decode_proof(&enc).expect("decoded proof must round-trip");
            assert_eq!(proof, rt);
        }
    }

    // Variable lengths around 256
    let mut var_buf = [0u8; 300];
    for len in 0..300 {
        rng.fill_bytes(&mut var_buf[..len]);
        let _ = decode_proof(&var_buf[..len]);
    }
}

#[test]
fn fuzz_decode_vk_never_panics() {
    let mut rng = Prng::new(0x4444);

    // Random lengths and data
    for _ in 0..2_000 {
        let len = rng.next_usize(1024);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        if let Ok(vk) = decode_vk(&buf) {
            let enc = encode_vk(&vk);
            assert_eq!(enc, buf);
            let rt = decode_vk(&enc).expect("decoded VK must round-trip");
            assert_eq!(vk, rt);
        }
    }
}

#[test]
fn fuzz_decode_public_inputs_never_panics() {
    let mut rng = Prng::new(0x5555);

    for _ in 0..2_000 {
        let len = rng.next_usize(512);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        if let Ok(pi) = decode_public_inputs(&buf) {
            let enc = encode_public_inputs(&pi);
            assert_eq!(enc, buf);
            let rt = decode_public_inputs(&enc).expect("decoded public inputs must round-trip");
            assert_eq!(pi, rt);
        }
    }
}

#[test]
fn fuzz_decode_envelope_never_panics() {
    let mut rng = Prng::new(0x6666);

    for _ in 0..2_000 {
        let len = rng.next_usize(1024);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        if let Ok(env) = decode_envelope(&buf) {
            let enc = encode_envelope(&env);
            assert_eq!(enc, buf);
            let rt = decode_envelope(&enc).expect("decoded envelope must round-trip");
            assert_eq!(env, rt);
        }
    }
}

#[test]
fn fuzz_snarkjs_json_parsers_never_panic() {
    let mut rng = Prng::new(0x7777);

    // 1. Extreme and adversarial decimal strings
    let test_strings = [
        "",
        "0",
        "-1",
        "+5",
        "00",
        "123a456",
        " 123 ",
        "9999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
        "21888242871839275222246405745257275088696311157297823662689037894645226208583", // p
        "21888242871839275222246405745257275088548364400416034343698204186575808495617", // r
        "null",
        "true",
        "false",
        "{}",
        "[]",
        "\"123\"",
        "\\",
        "\"\\\"",
    ];

    for s in test_strings {
        let _ = parse_dec_fp(s);
        let _ = parse_dec_fr(s);
        let _ = parse_snarkjs_proof(s);
        let _ = parse_snarkjs_vk(s);
        let _ = parse_snarkjs_public_inputs(s);
    }

    // 2. Randomized JSON-like garbage bytes
    for _ in 0..5_000 {
        let len = rng.next_usize(256);
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        if let Ok(s) = core::str::from_utf8(&buf) {
            let _ = parse_dec_fp(s);
            let _ = parse_dec_fr(s);
            let _ = parse_snarkjs_proof(s);
            let _ = parse_snarkjs_proof_envelope(s);
            let _ = parse_snarkjs_vk(s);
            let _ = parse_snarkjs_vk_envelope(s);
            let _ = parse_snarkjs_public_inputs(s);
            let _ = parse_snarkjs_public_inputs_envelope(s);
        }
    }

    // 3. Deeply nested JSON structures (recursion limit test)
    let deep_brackets = "[".repeat(200) + &"]".repeat(200);
    let _ = parse_snarkjs_proof(&deep_brackets);
    let _ = parse_snarkjs_vk(&deep_brackets);
    let _ = parse_snarkjs_public_inputs(&deep_brackets);

    let deep_objects = "{\"a\":".repeat(200) + "1" + &"}".repeat(200);
    let _ = parse_snarkjs_proof(&deep_objects);
    let _ = parse_snarkjs_vk(&deep_objects);
}
