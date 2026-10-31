//! Phase 1 Soroban BN254 host probe and minimal Groth16 verifier (ACF Spec Section 8).
//!
//! Used strictly for Phase 1 ground-truth experiments locally (`cargo test`) and
//! on Stellar Testnet. Processes only public verification keys, proofs, and
//! public inputs.

#![no_std]
#![deny(unsafe_code)]

use soroban_sdk::{
    contract, contracterror, contractimpl,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, Bytes, BytesN, Env, Vec, U256,
};

/// BN254 base field modulus `p` in big-endian bytes (ACF Spec Section 2).
/// `p = 21888242871839275222246405745257275088696311157297823662689037894645226208583`
pub const BN254_P_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// BN254 scalar field modulus `r` in big-endian bytes (ACF Spec Section 2).
/// `r = 21888242871839275222246405745257275088548364400416034343698204186575808495617`
pub const BN254_R_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Contract-level error codes corresponding to ACF Spec Section 11.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProbeError {
    BadLength = 1,
    NonCanonicalField = 2,
    PublicInputCount = 5,
    InvalidProof = 6,
}

fn slice_array_64(bytes: &Bytes, start: u32) -> [u8; 64] {
    let mut out = [0u8; 64];
    bytes.slice(start..start + 64).copy_into_slice(&mut out);
    out
}

fn slice_array_128(bytes: &Bytes, start: u32) -> [u8; 128] {
    let mut out = [0u8; 128];
    bytes.slice(start..start + 128).copy_into_slice(&mut out);
    out
}

fn is_all_zero(buf: &[u8]) -> bool {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

#[contract]
pub struct Phase1ProbeContract;

#[contractimpl]
impl Phase1ProbeContract {
    /// Strict Groth16 verifier implementing ACF Specification Sections 8 and 9.
    ///
    /// Enforces:
    /// - Exact VK payload size (`64 + 3*128 + 4 + 64*n_ic`)
    /// - `pub_signals.len() + 1 == n_ic`
    /// - Canonical scalar range `< r` BEFORE `Bn254Fr` conversion (preventing silent reduction)
    /// - Non-infinity check on proof points `A`, `B`, `C`
    /// - Canonical `< p` check on `A` coordinates before guest-side negation
    pub fn verify_acf(
        env: Env,
        vk_bytes: Bytes,
        proof_bytes: BytesN<256>,
        pub_signals: Vec<BytesN<32>>,
    ) -> Result<bool, ProbeError> {
        let vk_len = vk_bytes.len();
        if vk_len < 452 || !(vk_len - 452).is_multiple_of(64) {
            return Err(ProbeError::BadLength);
        }

        let mut n_ic_buf = [0u8; 4];
        vk_bytes.slice(448..452).copy_into_slice(&mut n_ic_buf);
        let n_ic = u32::from_be_bytes(n_ic_buf);
        let expected_vk_len = 452u32
            .checked_add(n_ic.checked_mul(64).ok_or(ProbeError::BadLength)?)
            .ok_or(ProbeError::BadLength)?;
        if vk_len != expected_vk_len {
            return Err(ProbeError::BadLength);
        }

        if pub_signals.len().checked_add(1) != Some(n_ic) {
            return Err(ProbeError::PublicInputCount);
        }

        let proof_arr = proof_bytes.to_array();
        let mut a_arr = [0u8; 64];
        let mut b_arr = [0u8; 128];
        let mut c_arr = [0u8; 64];
        a_arr.copy_from_slice(&proof_arr[0..64]);
        b_arr.copy_from_slice(&proof_arr[64..192]);
        c_arr.copy_from_slice(&proof_arr[192..256]);

        // Spec Section 8 Step 3 & Section 9 Rule 6: reject infinity A, B, or C.
        if is_all_zero(&a_arr) || is_all_zero(&b_arr) || is_all_zero(&c_arr) {
            return Err(ProbeError::InvalidProof);
        }

        // Spec Section 9 Rule 2: check A.x < p and A.y < p before guest negation
        // (`-Bn254G1Affine` panics in guest if A.y >= p).
        let mut ax = [0u8; 32];
        let mut ay = [0u8; 32];
        ax.copy_from_slice(&a_arr[0..32]);
        ay.copy_from_slice(&a_arr[32..64]);
        if ax >= BN254_P_BE || ay >= BN254_P_BE {
            return Err(ProbeError::NonCanonicalField);
        }

        let bn254 = env.crypto().bn254();
        let alpha = Bn254G1Affine::from_array(&env, &slice_array_64(&vk_bytes, 0));
        let beta = Bn254G2Affine::from_array(&env, &slice_array_128(&vk_bytes, 64));
        let gamma = Bn254G2Affine::from_array(&env, &slice_array_128(&vk_bytes, 192));
        let delta = Bn254G2Affine::from_array(&env, &slice_array_128(&vk_bytes, 320));

        // Spec Section 8 Step 2: vk_x = IC[0] + sum_{i=0..n-1} s_i * IC[i + 1]
        let mut vk_x = Bn254G1Affine::from_array(&env, &slice_array_64(&vk_bytes, 452));
        let mut i = 0u32;
        while i < pub_signals.len() {
            let sig = pub_signals.get(i).ok_or(ProbeError::PublicInputCount)?;
            // Spec Section 3.4: reject scalars >= r rather than reducing modulo r.
            if sig.to_array() >= BN254_R_BE {
                return Err(ProbeError::NonCanonicalField);
            }
            let fr = Bn254Fr::from_bytes(sig);
            let ic_pt =
                Bn254G1Affine::from_array(&env, &slice_array_64(&vk_bytes, 452 + (i + 1) * 64));
            let term = bn254.g1_mul(&ic_pt, &fr);
            vk_x = bn254.g1_add(&vk_x, &term);
            i += 1;
        }

        let neg_a = -Bn254G1Affine::from_array(&env, &a_arr);
        let b_g2 = Bn254G2Affine::from_array(&env, &b_arr);
        let c_g1 = Bn254G1Affine::from_array(&env, &c_arr);

        let vp1 = vec![&env, neg_a, alpha, vk_x, c_g1];
        let vp2 = vec![&env, b_g2, beta, gamma, delta];

        if bn254.pairing_check(vp1, vp2) {
            Ok(true)
        } else {
            Err(ProbeError::InvalidProof)
        }
    }

    /// Unguarded verifier that delegates directly to `soroban-sdk` BN254 types
    /// without range-checking `pub_signals < r` or rejecting infinity `A, B, C`.
    /// Used in Phase 1 negative controls to demonstrate why explicit contract
    /// checks are mandatory.
    pub fn verify_raw(
        env: Env,
        vk_bytes: Bytes,
        proof_bytes: BytesN<256>,
        pub_signals: Vec<BytesN<32>>,
    ) -> bool {
        let proof_arr = proof_bytes.to_array();
        let mut a_arr = [0u8; 64];
        let mut b_arr = [0u8; 128];
        let mut c_arr = [0u8; 64];
        a_arr.copy_from_slice(&proof_arr[0..64]);
        b_arr.copy_from_slice(&proof_arr[64..192]);
        c_arr.copy_from_slice(&proof_arr[192..256]);

        let bn254 = env.crypto().bn254();
        let alpha = Bn254G1Affine::from_array(&env, &slice_array_64(&vk_bytes, 0));
        let beta = Bn254G2Affine::from_array(&env, &slice_array_128(&vk_bytes, 64));
        let gamma = Bn254G2Affine::from_array(&env, &slice_array_128(&vk_bytes, 192));
        let delta = Bn254G2Affine::from_array(&env, &slice_array_128(&vk_bytes, 320));

        let mut vk_x = Bn254G1Affine::from_array(&env, &slice_array_64(&vk_bytes, 452));
        let mut i = 0u32;
        while i < pub_signals.len() {
            if let Some(sig) = pub_signals.get(i) {
                let fr = Bn254Fr::from_bytes(sig);
                let ic_pt =
                    Bn254G1Affine::from_array(&env, &slice_array_64(&vk_bytes, 452 + (i + 1) * 64));
                let term = bn254.g1_mul(&ic_pt, &fr);
                vk_x = bn254.g1_add(&vk_x, &term);
            }
            i += 1;
        }

        let neg_a = -Bn254G1Affine::from_array(&env, &a_arr);
        let b_g2 = Bn254G2Affine::from_array(&env, &b_arr);
        let c_g1 = Bn254G1Affine::from_array(&env, &c_arr);

        bn254.pairing_check(
            vec![&env, neg_a, alpha, vk_x, c_g1],
            vec![&env, b_g2, beta, gamma, delta],
        )
    }

    /// Direct host probe for `bn254_g1_add`.
    pub fn probe_g1_add(env: Env, p0: BytesN<64>, p1: BytesN<64>) -> BytesN<64> {
        let g0 = Bn254G1Affine::from_bytes(p0);
        let g1 = Bn254G1Affine::from_bytes(p1);
        env.crypto().bn254().g1_add(&g0, &g1).to_bytes()
    }

    /// Direct host probe for `bn254_g1_mul` via `U256::from_be_bytes` -> `Bn254Fr`.
    pub fn probe_g1_mul(env: Env, p0: BytesN<64>, scalar_be: BytesN<32>) -> BytesN<64> {
        let g0 = Bn254G1Affine::from_bytes(p0);
        let u = U256::from_be_bytes(&env, scalar_be.as_ref());
        let fr = Bn254Fr::from_u256(u);
        env.crypto().bn254().g1_mul(&g0, &fr).to_bytes()
    }

    /// Direct host probe for `bn254_multi_pairing_check`.
    pub fn probe_pairing(env: Env, vp1: Vec<BytesN<64>>, vp2: Vec<BytesN<128>>) -> bool {
        let mut g1s = Vec::new(&env);
        let mut i = 0u32;
        while i < vp1.len() {
            if let Some(b) = vp1.get(i) {
                g1s.push_back(Bn254G1Affine::from_bytes(b));
            }
            i += 1;
        }
        let mut g2s = Vec::new(&env);
        let mut j = 0u32;
        while j < vp2.len() {
            if let Some(b) = vp2.get(j) {
                g2s.push_back(Bn254G2Affine::from_bytes(b));
            }
            j += 1;
        }
        env.crypto().bn254().pairing_check(g1s, g2s)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use ark_bn254::{Fq, Fq2, G1Affine as ArkG1, G2Affine as ArkG2};
    use ark_ec::AffineRepr;
    use ark_ff::BigInteger;
    use ark_ff::PrimeField;
    use soroban_env_host::{BytesObject, Env as RawHostEnv, TryFromVal as HostTryFromVal, U256Val};

    // Public Circom Multiplier2 (`a * b == c` with `a = 3, b = 11 => c = 33`)
    // verified off-chain by `snarkjs@0.7.6 groth16 verify`.
    const PROOF_C1_FIRST_HEX: &str = "0d7878bb471f16e0e8366778a28829db4d5ff09baf9517695cd0d23cd2c1b2e80f0e8336dd5bd193b1918a13dce96010b06db87f9d99af62e28eb1d134124d58100792e3175ff2f52bb403fb1b33eb62db1e30b06dea369186faaaaae25f6b7427108db79d78a66e9de40d156b0afd421265f7c50e53aa068a896698fb586ac10fe25410b2b341224247825bd25acce576201d3d828781ffe6ca4a5c81b3e35609d861e52f7de282f16a79f0b0d895a19e063af5c3a265ecbcf9f65c1598acd206e4d97e80404e4de3d846689cb020de2e02d2594bd93c19a7ccea4241f336092556ecd9998b1858547bed640f06afdb213a0af2ccff62421be219c5546162e8";
    const PROOF_C0_FIRST_HEX: &str = "0d7878bb471f16e0e8366778a28829db4d5ff09baf9517695cd0d23cd2c1b2e80f0e8336dd5bd193b1918a13dce96010b06db87f9d99af62e28eb1d134124d5827108db79d78a66e9de40d156b0afd421265f7c50e53aa068a896698fb586ac1100792e3175ff2f52bb403fb1b33eb62db1e30b06dea369186faaaaae25f6b7409d861e52f7de282f16a79f0b0d895a19e063af5c3a265ecbcf9f65c1598acd20fe25410b2b341224247825bd25acce576201d3d828781ffe6ca4a5c81b3e35606e4d97e80404e4de3d846689cb020de2e02d2594bd93c19a7ccea4241f336092556ecd9998b1858547bed640f06afdb213a0af2ccff62421be219c5546162e8";
    const VK_C1_FIRST_HEX: &str = "2c3eca3b96938a231158ff0690bd4af0a7b020cc9bf9ec649bfd1a6f9fedc2841e81947887a20eff0366a4cc56891097b8f2c07f27dd57fd47df7f24aab2e1610c02c8193eedbc72fd4a8fb8422cb4632057134d80413a668c9987719ad27c312a239d5389fe740be6918dcc95e259280368f518df3c77a800925d9d368996e42534e71a3d36a2f7dc927fc673a87299788d7a214f1151f7abf9723c4ee315351d9a94d377c6dc20b8bc05dcb1f9adaa2fabe4c540645eda3c7594b85676990e198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa2f31a9ffbec70638647f26bc7a49c866fcbf7ac20aa7408e695004da9ef5e25e165ff901385851b84ecf6c366fe61e641b7dab33cb9926e8288d65d36e1689621238f3a5cc6a9c9fe7e18f02041403c1124164ef5b00b7e7ff635a498d09c2420d71091d690ae6268f2db7e7cc97e9e67415ba92e0e90ea2f9172da571523152000000031f9ca84019247d9ea29cc5d1d3cee12b76bbc2385586cdbad63a6cd65addd2e61af0ff10ff1e6b6e4be920f6328ca0f437d45ea4cf9223bb2ef2e38ff1fc6c3111584ff9c88f8138175bd526cd78145da96cba2021e87f8af4c74a24dd82d1a31296a9041b061089d28d65f1a7807316a6927151dd3c359f4f2a8ec71f0a5a602f0776c05fc028592d2a05f66c4798e39eaf595a5a8aebc07bb583d03affd7da09790bda24e938bba6be23e1a7cfdd6bd635e1ed49c5204da7c25ad32354ad19";
    const VK_C0_FIRST_HEX: &str = "2c3eca3b96938a231158ff0690bd4af0a7b020cc9bf9ec649bfd1a6f9fedc2841e81947887a20eff0366a4cc56891097b8f2c07f27dd57fd47df7f24aab2e1612a239d5389fe740be6918dcc95e259280368f518df3c77a800925d9d368996e40c02c8193eedbc72fd4a8fb8422cb4632057134d80413a668c9987719ad27c311d9a94d377c6dc20b8bc05dcb1f9adaa2fabe4c540645eda3c7594b85676990e2534e71a3d36a2f7dc927fc673a87299788d7a214f1151f7abf9723c4ee315351800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c212c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b165ff901385851b84ecf6c366fe61e641b7dab33cb9926e8288d65d36e1689622f31a9ffbec70638647f26bc7a49c866fcbf7ac20aa7408e695004da9ef5e25e0d71091d690ae6268f2db7e7cc97e9e67415ba92e0e90ea2f9172da5715231521238f3a5cc6a9c9fe7e18f02041403c1124164ef5b00b7e7ff635a498d09c242000000031f9ca84019247d9ea29cc5d1d3cee12b76bbc2385586cdbad63a6cd65addd2e61af0ff10ff1e6b6e4be920f6328ca0f437d45ea4cf9223bb2ef2e38ff1fc6c3111584ff9c88f8138175bd526cd78145da96cba2021e87f8af4c74a24dd82d1a31296a9041b061089d28d65f1a7807316a6927151dd3c359f4f2a8ec71f0a5a602f0776c05fc028592d2a05f66c4798e39eaf595a5a8aebc07bb583d03affd7da09790bda24e938bba6be23e1a7cfdd6bd635e1ed49c5204da7c25ad32354ad19";

    fn decode_hex_vec(s: &str) -> std::vec::Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        let v = decode_hex_vec(s);
        v.try_into().unwrap()
    }

    fn encode_hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write;
        let mut s = std::string::String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(&mut s, "{b:02x}");
        }
        s
    }

    fn ark_fq_to_be32(fq: Fq) -> [u8; 32] {
        let be = fq.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - be.len()..].copy_from_slice(&be);
        out
    }

    fn ark_g1_to_acf(pt: ArkG1) -> [u8; 64] {
        if pt.is_zero() {
            return [0u8; 64];
        }
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(&ark_fq_to_be32(pt.x));
        out[32..64].copy_from_slice(&ark_fq_to_be32(pt.y));
        out
    }

    /// Serializes an arkworks G2 point in `c1 || c0` (ACF / EIP-197) order.
    fn ark_g2_to_acf(pt: ArkG2) -> [u8; 128] {
        if pt.is_zero() {
            return [0u8; 128];
        }
        let mut out = [0u8; 128];
        out[0..32].copy_from_slice(&ark_fq_to_be32(pt.x.c1));
        out[32..64].copy_from_slice(&ark_fq_to_be32(pt.x.c0));
        out[64..96].copy_from_slice(&ark_fq_to_be32(pt.y.c1));
        out[96..128].copy_from_slice(&ark_fq_to_be32(pt.y.c0));
        out
    }

    /// Deterministically finds the smallest `u64` `k` where `x = k + 1*u` lies on the
    /// BN254 twist curve `y^2 = x^3 + 3/(9+u)` and the resulting point is NOT in the
    /// prime-order-`r` G2 subgroup.
    fn deterministic_twist_point_outside_subgroup() -> (u64, [u8; 128]) {
        for k in 0u64..100 {
            let x = Fq2::new(Fq::from(k), Fq::from(1u64));
            if let Some(p) = ArkG2::get_point_from_x_unchecked(x, true) {
                assert!(p.is_on_curve());
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    return (k, ark_g2_to_acf(p));
                }
            }
        }
        panic!("expected twist point outside subgroup within k < 100");
    }

    #[test]
    fn exp1_fp2_component_order_and_negative_controls() {
        let env = Env::default();
        let contract_id = env.register(Phase1ProbeContract, ());
        let client = Phase1ProbeContractClient::new(&env, &contract_id);

        let mut s0 = [0u8; 32];
        s0[31] = 33; // c = 33
        let mut s1 = [0u8; 32];
        s1[31] = 3; // a = 3
        let pub_signals = vec![
            &env,
            BytesN::from_array(&env, &s0),
            BytesN::from_array(&env, &s1),
        ];

        // 1a. Positive: `c1 || c0` passes both strict ACF and raw verifier.
        let vk_c1 = Bytes::from_slice(&env, &decode_hex_vec(VK_C1_FIRST_HEX));
        let proof_c1 = BytesN::from_array(&env, &decode_hex::<256>(PROOF_C1_FIRST_HEX));
        assert!(client.verify_acf(&vk_c1, &proof_c1, &pub_signals));
        assert!(client.verify_raw(&vk_c1, &proof_c1, &pub_signals));

        // 1b. Negative control: `c0 || c1` across BOTH proof and VK traps in host
        // because swapped Fp2 coordinates do not lie on the BN254 twist curve.
        let vk_c0 = Bytes::from_slice(&env, &decode_hex_vec(VK_C0_FIRST_HEX));
        let proof_c0 = BytesN::from_array(&env, &decode_hex::<256>(PROOF_C0_FIRST_HEX));
        assert!(client
            .try_verify_raw(&vk_c0, &proof_c0, &pub_signals)
            .is_err());
        assert!(client
            .try_verify_raw(&vk_c1, &proof_c0, &pub_signals)
            .is_err());

        // 1c. Negative control (valid curve/subgroup points, wrong public input `c = 34`):
        // Host does NOT trap; pairing check returns `false` (`ProbeError::InvalidProof`).
        let mut wrong_s0 = [0u8; 32];
        wrong_s0[31] = 34;
        let wrong_signals = vec![
            &env,
            BytesN::from_array(&env, &wrong_s0),
            BytesN::from_array(&env, &s1),
        ];
        assert!(!client.verify_raw(&vk_c1, &proof_c1, &wrong_signals));
        assert_eq!(
            client.try_verify_acf(&vk_c1, &proof_c1, &wrong_signals),
            Err(Ok(ProbeError::InvalidProof))
        );
    }

    #[test]
    fn exp2_host_on_curve_and_g2_subgroup_checks() {
        let env = Env::default();
        let contract_id = env.register(Phase1ProbeContract, ());
        let client = Phase1ProbeContractClient::new(&env, &contract_id);

        let g1_gen = ark_g1_to_acf(ArkG1::generator());
        let neg_g1_gen = ark_g1_to_acf(-ArkG1::generator());
        let g2_gen = ark_g2_to_acf(ArkG2::generator());

        std::println!("G1_GEN_HEX={}", encode_hex(&g1_gen));
        std::println!("NEG_G1_GEN_HEX={}", encode_hex(&neg_g1_gen));
        std::println!("G2_GEN_HEX={}", encode_hex(&g2_gen));

        // Positive control: e(-G1, G2) * e(G1, G2) == 1 -> true.
        let vp1_ok = vec![
            &env,
            BytesN::from_array(&env, &neg_g1_gen),
            BytesN::from_array(&env, &g1_gen),
        ];
        let vp2_ok = vec![
            &env,
            BytesN::from_array(&env, &g2_gen),
            BytesN::from_array(&env, &g2_gen),
        ];
        assert!(client.probe_pairing(&vp1_ok, &vp2_ok));

        // Twist point ON `y^2 = x^3 + 3/(9+u)` but OUTSIDE the prime-order-`r` G2 subgroup:
        let (k, bad_subgroup_g2) = deterministic_twist_point_outside_subgroup();
        std::println!(
            "TWIST_OUTSIDE_SUBGROUP (x = {k} + u): {}",
            encode_hex(&bad_subgroup_g2)
        );
        let vp1_single = vec![&env, BytesN::from_array(&env, &g1_gen)];
        let vp2_bad_sub = vec![&env, BytesN::from_array(&env, &bad_subgroup_g2)];
        // Host MUST trap on G2 point outside subgroup!
        assert!(client.try_probe_pairing(&vp1_single, &vp2_bad_sub).is_err());

        // G1 point not on curve `(1, 3)` -> host traps on `g1_add` and `pairing_check`.
        let mut g1_not_on_curve = [0u8; 64];
        g1_not_on_curve[31] = 1;
        g1_not_on_curve[63] = 3;
        assert!(client
            .try_probe_g1_add(
                &BytesN::from_array(&env, &g1_gen),
                &BytesN::from_array(&env, &g1_not_on_curve),
            )
            .is_err());

        // G1 non-canonical Fp (`x = p, y = 2`) -> host traps.
        let mut g1_non_canonical = [0u8; 64];
        g1_non_canonical[0..32].copy_from_slice(&BN254_P_BE);
        g1_non_canonical[63] = 2;
        assert!(client
            .try_probe_g1_add(
                &BytesN::from_array(&env, &g1_gen),
                &BytesN::from_array(&env, &g1_non_canonical),
            )
            .is_err());

        // G1 flag bit `0x40` (arkworks infinity flag) set on all-zero buffer -> host traps!
        let mut g1_flagged = [0u8; 64];
        g1_flagged[0] = 0x40;
        assert!(client
            .try_probe_g1_add(
                &BytesN::from_array(&env, &g1_gen),
                &BytesN::from_array(&env, &g1_flagged),
            )
            .is_err());
    }

    #[test]
    fn exp3_infinity_handling_across_host_functions() {
        let env = Env::default();
        let contract_id = env.register(Phase1ProbeContract, ());
        let client = Phase1ProbeContractClient::new(&env, &contract_id);

        let g1_zero = BytesN::from_array(&env, &[0u8; 64]);
        let g2_zero = BytesN::from_array(&env, &[0u8; 128]);
        let g1_gen = BytesN::from_array(&env, &ark_g1_to_acf(ArkG1::generator()));
        let neg_g1_gen = BytesN::from_array(&env, &ark_g1_to_acf(-ArkG1::generator()));
        let g2_gen = BytesN::from_array(&env, &ark_g2_to_acf(ArkG2::generator()));

        // g1_add with infinity in each/both positions, and P + (-P) == 0:
        assert_eq!(client.probe_g1_add(&g1_zero, &g1_gen), g1_gen);
        assert_eq!(client.probe_g1_add(&g1_gen, &g1_zero), g1_gen);
        assert_eq!(client.probe_g1_add(&g1_zero, &g1_zero), g1_zero);
        assert_eq!(client.probe_g1_add(&g1_gen, &neg_g1_gen), g1_zero);

        // g1_mul with infinity point or zero scalar:
        let mut scalar_five = [0u8; 32];
        scalar_five[31] = 5;
        let scalar_zero = [0u8; 32];
        assert_eq!(
            client.probe_g1_mul(&g1_zero, &BytesN::from_array(&env, &scalar_five)),
            g1_zero
        );
        assert_eq!(
            client.probe_g1_mul(&g1_gen, &BytesN::from_array(&env, &scalar_zero)),
            g1_zero
        );

        // multi_pairing_check accepts G1 infinity and G2 infinity without trapping,
        // treating each pair containing infinity as 1 in GT:
        assert!(client.probe_pairing(&vec![&env, g1_zero.clone()], &vec![&env, g2_gen.clone()],));
        assert!(client.probe_pairing(&vec![&env, g1_gen.clone()], &vec![&env, g2_zero.clone()],));
        assert!(client.probe_pairing(&vec![&env, g1_zero.clone()], &vec![&env, g2_zero],));

        // Guest `-Bn254G1Affine` on `[0u8; 64]` returns `[0u8; 64]` without trapping,
        // proving `verify_acf` MUST explicitly reject infinity proof points A, B, C!
        let neg_inf = -Bn254G1Affine::from_bytes(g1_zero);
        assert_eq!(neg_inf.to_bytes().to_array(), [0u8; 64]);

        let vk_c1 = Bytes::from_slice(&env, &decode_hex_vec(VK_C1_FIRST_HEX));
        let mut s0 = [0u8; 32];
        s0[31] = 33;
        let mut s1 = [0u8; 32];
        s1[31] = 3;
        let pub_signals = vec![
            &env,
            BytesN::from_array(&env, &s0),
            BytesN::from_array(&env, &s1),
        ];

        let mut proof_inf_a = decode_hex::<256>(PROOF_C1_FIRST_HEX);
        proof_inf_a[0..64].fill(0);
        assert_eq!(
            client.try_verify_acf(
                &vk_c1,
                &BytesN::from_array(&env, &proof_inf_a),
                &pub_signals
            ),
            Err(Ok(ProbeError::InvalidProof))
        );
    }

    #[test]
    fn exp4_scalar_reduction_and_aliasing_hazard() {
        let env = Env::default();
        let contract_id = env.register(Phase1ProbeContract, ());
        let client = Phase1ProbeContractClient::new(&env, &contract_id);

        let g1_zero = BytesN::from_array(&env, &[0u8; 64]);
        let g1_gen = BytesN::from_array(&env, &ark_g1_to_acf(ArkG1::generator()));

        // `r` reduces to `0`: `G1 * r == 0`
        let scalar_r = BytesN::from_array(&env, &BN254_R_BE);
        assert_eq!(client.probe_g1_mul(&g1_gen, &scalar_r), g1_zero);

        // `r + 1` reduces to `1`: `G1 * (r + 1) == G1`
        let mut r_plus_1 = BN254_R_BE;
        r_plus_1[31] += 1; // 0x01 + 1 = 0x02 (no carry)
        assert_eq!(
            client.probe_g1_mul(&g1_gen, &BytesN::from_array(&env, &r_plus_1)),
            g1_gen
        );

        // Also test calling the RAW host `bn254_g1_mul` directly with an unreduced `U256Val`
        // (`r + 1`), bypassing `Bn254Fr::from_u256`: confirms the host itself reduces mod `r`!
        let unreduced_u256 = U256::from_be_bytes(&env, &Bytes::from_array(&env, &r_plus_1));
        let raw_u256_val = U256Val::try_from_val(env.host(), unreduced_u256.as_val()).unwrap();
        let g1_bo = BytesObject::try_from_val(env.host(), g1_gen.as_val()).unwrap();
        let raw_mul_bo = RawHostEnv::bn254_g1_mul(env.host(), g1_bo, raw_u256_val).unwrap();
        let raw_mul_val: soroban_sdk::Val = raw_mul_bo.to_val();
        let raw_mul_g1: BytesN<64> =
            soroban_sdk::TryFromVal::try_from_val(&env, &raw_mul_val).unwrap();
        assert_eq!(raw_mul_g1, g1_gen);

        // CRITICAL NEGATIVE CONTROL:
        // Aliased public input `s0_aliased = 33 + r` (`0x...f0000022` < 2^256):
        // - Unguarded `verify_raw` ACCEPTS `33 + r` as valid for the `c = 33` proof!
        // - Guarded `verify_acf` REJECTS `33 + r` with `ProbeError::NonCanonicalField`!
        let mut s0_plus_r = BN254_R_BE;
        s0_plus_r[31] = 0x01 + 33; // 0x22
        std::println!("ALIASED_S0_PLUS_R_HEX={}", encode_hex(&s0_plus_r));
        let mut s1 = [0u8; 32];
        s1[31] = 3;
        let aliased_signals = vec![
            &env,
            BytesN::from_array(&env, &s0_plus_r),
            BytesN::from_array(&env, &s1),
        ];

        let vk_c1 = Bytes::from_slice(&env, &decode_hex_vec(VK_C1_FIRST_HEX));
        let proof_c1 = BytesN::from_array(&env, &decode_hex::<256>(PROOF_C1_FIRST_HEX));
        assert!(client.verify_raw(&vk_c1, &proof_c1, &aliased_signals));
        assert_eq!(
            client.try_verify_acf(&vk_c1, &proof_c1, &aliased_signals),
            Err(Ok(ProbeError::NonCanonicalField))
        );
    }

    #[test]
    fn exp5_sdk_surface_g1_is_on_curve_and_msm() {
        let env = Env::default();
        let bn254 = env.crypto().bn254();

        let g1_gen = Bn254G1Affine::from_array(&env, &ark_g1_to_acf(ArkG1::generator()));
        let g1_zero = Bn254G1Affine::from_array(&env, &[0u8; 64]);
        let mut off_curve = [0u8; 64];
        off_curve[31] = 1;
        off_curve[63] = 3;
        let g1_off = Bn254G1Affine::from_array(&env, &off_curve);

        // `g1_is_on_curve` returns `true` for generator and infinity, `false` (no trap!) for `(1, 3)`
        assert!(bn254.g1_is_on_curve(&g1_gen));
        assert!(bn254.g1_is_on_curve(&g1_zero));
        assert!(!bn254.g1_is_on_curve(&g1_off));

        // `g1_msm` matches `g1_mul` + `g1_add`: `3*G1 + 5*G1 == 8*G1`
        let f3 = Bn254Fr::from_u256(U256::from_u32(&env, 3));
        let f5 = Bn254Fr::from_u256(U256::from_u32(&env, 5));
        let f8 = Bn254Fr::from_u256(U256::from_u32(&env, 8));
        let msm_res = bn254.g1_msm(
            vec![&env, g1_gen.clone(), g1_gen.clone()],
            vec![&env, f3, f5],
        );
        let expected = bn254.g1_mul(&g1_gen, &f8);
        assert_eq!(msm_res, expected);
    }
}
