//! Soroban contract helpers and Groth16 verifier template for Astrolabe (`acf/1.0`).
//!
//! Implements strict, on-chain Groth16 verification over BN254 host functions
//! conforming to ACF Specification Sections 7, 8, 9, and 11.

#![no_std]
#![deny(unsafe_code)]

#[cfg(any(not(target_family = "wasm"), feature = "stored-contract"))]
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Symbol};
use soroban_sdk::{
    contracterror, contracttype,
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    vec, Bytes, BytesN, Env, Vec,
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

/// Contract-level error codes corresponding 1:1 to ACF Spec Section 11.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum VerifierError {
    /// `ERR_BAD_LENGTH`: Byte length does not match expected size.
    BadLength = 1,
    /// `ERR_NON_CANONICAL_FIELD`: Value is not below the field modulus.
    NonCanonicalField = 2,
    /// `ERR_NOT_ON_CURVE`: Point does not satisfy the curve equation.
    NotOnCurve = 3,
    /// `ERR_NOT_IN_SUBGROUP`: G2 point is not in the order-`r` subgroup.
    NotInSubgroup = 4,
    /// `ERR_PUBLIC_INPUT_COUNT`: Public-input count does not match the verification key.
    PublicInputCount = 5,
    /// `ERR_INVALID_PROOF`: Degenerate proof element or failed pairing check.
    InvalidProof = 6,
    /// `ERR_UNSUPPORTED`: Unknown version, kind, curve, system, or protocol.
    Unsupported = 7,
    /// `ERR_TRAILING_BYTES`: Extra bytes after declared payload.
    TrailingBytes = 8,
    /// `ERR_MALFORMED_INPUT`: Malformed input bytes.
    MalformedInput = 9,
}

impl VerifierError {
    /// Returns the stable string error code specified in ACF Spec Section 11.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BadLength => "ERR_BAD_LENGTH",
            Self::NonCanonicalField => "ERR_NON_CANONICAL_FIELD",
            Self::NotOnCurve => "ERR_NOT_ON_CURVE",
            Self::NotInSubgroup => "ERR_NOT_IN_SUBGROUP",
            Self::PublicInputCount => "ERR_PUBLIC_INPUT_COUNT",
            Self::InvalidProof => "ERR_INVALID_PROOF",
            Self::Unsupported => "ERR_UNSUPPORTED",
            Self::TrailingBytes => "ERR_TRAILING_BYTES",
            Self::MalformedInput => "ERR_MALFORMED_INPUT",
        }
    }
}

/// Groth16 proof coordinates in uncompressed affine form (Spec Section 4.1 & 7).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Proof {
    /// Point `A` in G1 (64 bytes).
    pub a: BytesN<64>,
    /// Point `B` in G2 (128 bytes, `c1 || c0` order).
    pub b: BytesN<128>,
    /// Point `C` in G1 (64 bytes).
    pub c: BytesN<64>,
}

/// Groth16 verification key points (Spec Section 4.2 & 7).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Groth16Vk {
    /// Alpha in G1 (64 bytes).
    pub alpha: BytesN<64>,
    /// Beta in G2 (128 bytes).
    pub beta: BytesN<128>,
    /// Gamma in G2 (128 bytes).
    pub gamma: BytesN<128>,
    /// Delta in G2 (128 bytes).
    pub delta: BytesN<128>,
    /// IC points in G1 (`n_public + 1` elements, 64 bytes each).
    pub ic: Vec<BytesN<64>>,
}

#[cfg(any(not(target_family = "wasm"), feature = "stored-contract"))]
const STORAGE_KEY_ADMIN: Symbol = symbol_short!("admin");
#[cfg(any(not(target_family = "wasm"), feature = "stored-contract"))]
const STORAGE_KEY_VK: Symbol = symbol_short!("vk");

fn is_all_zero(buf: &[u8]) -> bool {
    for &b in buf {
        if b != 0 {
            return false;
        }
    }
    true
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

/// Strictly verifies a Groth16 proof against raw ACF verification key bytes.
///
/// Implements ACF Spec Section 8 and enforces all security checks from Spec Section 9:
/// - Rejects degenerate (all-zero / infinity) `A`, `B`, or `C` points (`ERR_INVALID_PROOF`).
/// - Checks `A.x < p` and `A.y < p` before guest negation (`ERR_NON_CANONICAL_FIELD`).
/// - Rejects public input scalars `>= r` before `Bn254Fr` conversion (`ERR_NON_CANONICAL_FIELD`).
/// - Rejects length mismatches (`ERR_BAD_LENGTH`) and public input count mismatches (`ERR_PUBLIC_INPUT_COUNT`).
/// - Performs pairing check: `e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1`.
pub fn verify_groth16_bytes(
    env: &Env,
    vk_bytes: &Bytes,
    proof_bytes: &BytesN<256>,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<bool, VerifierError> {
    let vk_len = vk_bytes.len();
    if vk_len < 452 || !(vk_len - 452).is_multiple_of(64) {
        return Err(VerifierError::BadLength);
    }

    let mut n_ic_buf = [0u8; 4];
    vk_bytes.slice(448..452).copy_into_slice(&mut n_ic_buf);
    let n_ic = u32::from_be_bytes(n_ic_buf);
    if n_ic == 0 {
        return Err(VerifierError::PublicInputCount);
    }
    let expected_vk_len = 452u32
        .checked_add(n_ic.checked_mul(64).ok_or(VerifierError::BadLength)?)
        .ok_or(VerifierError::BadLength)?;
    if vk_len != expected_vk_len {
        return Err(VerifierError::BadLength);
    }

    if public_inputs.len().checked_add(1) != Some(n_ic) {
        return Err(VerifierError::PublicInputCount);
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
        return Err(VerifierError::InvalidProof);
    }

    // Spec Section 9 Rule 2: check A.x < p and A.y < p before guest negation.
    let mut ax = [0u8; 32];
    let mut ay = [0u8; 32];
    ax.copy_from_slice(&a_arr[0..32]);
    ay.copy_from_slice(&a_arr[32..64]);
    if ax >= BN254_P_BE || ay >= BN254_P_BE {
        return Err(VerifierError::NonCanonicalField);
    }

    let bn254 = env.crypto().bn254();
    let alpha = Bn254G1Affine::from_array(env, &slice_array_64(vk_bytes, 0));
    let beta = Bn254G2Affine::from_array(env, &slice_array_128(vk_bytes, 64));
    let gamma = Bn254G2Affine::from_array(env, &slice_array_128(vk_bytes, 192));
    let delta = Bn254G2Affine::from_array(env, &slice_array_128(vk_bytes, 320));

    // Spec Section 8 Step 2: vk_x = IC[0] + sum_{i=0..n-1} s_i * IC[i + 1]
    let mut vk_x = Bn254G1Affine::from_array(env, &slice_array_64(vk_bytes, 452));
    let mut i = 0u32;
    while i < public_inputs.len() {
        let sig = public_inputs
            .get(i)
            .ok_or(VerifierError::PublicInputCount)?;
        // Spec Section 3.4: reject scalars >= r rather than reducing modulo r.
        if sig.to_array() >= BN254_R_BE {
            return Err(VerifierError::NonCanonicalField);
        }
        let fr = Bn254Fr::from_bytes(sig);
        let ic_pt = Bn254G1Affine::from_array(env, &slice_array_64(vk_bytes, 452 + (i + 1) * 64));
        let term = bn254.g1_mul(&ic_pt, &fr);
        vk_x = bn254.g1_add(&vk_x, &term);
        i += 1;
    }

    let neg_a = -Bn254G1Affine::from_array(env, &a_arr);
    let b_g2 = Bn254G2Affine::from_array(env, &b_arr);
    let c_g1 = Bn254G1Affine::from_array(env, &c_arr);

    let vp1 = vec![env, neg_a, alpha, vk_x, c_g1];
    let vp2 = vec![env, b_g2, beta, gamma, delta];

    if bn254.pairing_check(vp1, vp2) {
        Ok(true)
    } else {
        Err(VerifierError::InvalidProof)
    }
}

/// Strictly verifies a Groth16 proof against a static in-memory slice of ACF verification key bytes.
///
/// Intended for contracts with baked-in verification keys (`const VK_BYTES: &[u8] = &[...];`).
pub fn verify_groth16_slice(
    env: &Env,
    vk_slice: &[u8],
    proof_bytes: &BytesN<256>,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<bool, VerifierError> {
    let vk_bytes = Bytes::from_slice(env, vk_slice);
    verify_groth16_bytes(env, &vk_bytes, proof_bytes, public_inputs)
}

/// Parses raw ACF verification key bytes into a structured [`Groth16Vk`].
pub fn parse_vk(env: &Env, vk_bytes: &Bytes) -> Result<Groth16Vk, VerifierError> {
    let vk_len = vk_bytes.len();
    if vk_len < 452 || !(vk_len - 452).is_multiple_of(64) {
        return Err(VerifierError::BadLength);
    }
    let mut n_ic_buf = [0u8; 4];
    vk_bytes.slice(448..452).copy_into_slice(&mut n_ic_buf);
    let n_ic = u32::from_be_bytes(n_ic_buf);
    if n_ic == 0 {
        return Err(VerifierError::PublicInputCount);
    }
    let expected_len = 452u32
        .checked_add(n_ic.checked_mul(64).ok_or(VerifierError::BadLength)?)
        .ok_or(VerifierError::BadLength)?;
    if vk_len != expected_len {
        return Err(VerifierError::BadLength);
    }

    let mut alpha_arr = [0u8; 64];
    let mut beta_arr = [0u8; 128];
    let mut gamma_arr = [0u8; 128];
    let mut delta_arr = [0u8; 128];
    vk_bytes.slice(0..64).copy_into_slice(&mut alpha_arr);
    vk_bytes.slice(64..192).copy_into_slice(&mut beta_arr);
    vk_bytes.slice(192..320).copy_into_slice(&mut gamma_arr);
    vk_bytes.slice(320..448).copy_into_slice(&mut delta_arr);

    let mut ic_vec = Vec::new(env);
    let mut offset = 452u32;
    for _ in 0..n_ic {
        let mut pt = [0u8; 64];
        vk_bytes.slice(offset..offset + 64).copy_into_slice(&mut pt);
        ic_vec.push_back(BytesN::from_array(env, &pt));
        offset += 64;
    }

    Ok(Groth16Vk {
        alpha: BytesN::from_array(env, &alpha_arr),
        beta: BytesN::from_array(env, &beta_arr),
        gamma: BytesN::from_array(env, &gamma_arr),
        delta: BytesN::from_array(env, &delta_arr),
        ic: ic_vec,
    })
}

/// Parses a 256-byte ACF Groth16 proof into a structured [`Groth16Proof`].
pub fn parse_proof(env: &Env, proof_bytes: &BytesN<256>) -> Result<Groth16Proof, VerifierError> {
    let arr = proof_bytes.to_array();
    let mut a = [0u8; 64];
    let mut b = [0u8; 128];
    let mut c = [0u8; 64];
    a.copy_from_slice(&arr[0..64]);
    b.copy_from_slice(&arr[64..192]);
    c.copy_from_slice(&arr[192..256]);

    if is_all_zero(&a) || is_all_zero(&b) || is_all_zero(&c) {
        return Err(VerifierError::InvalidProof);
    }

    Ok(Groth16Proof {
        a: BytesN::from_array(env, &a),
        b: BytesN::from_array(env, &b),
        c: BytesN::from_array(env, &c),
    })
}

/// Deployable Soroban contract with stored verification key in instance storage.
#[cfg(any(not(target_family = "wasm"), feature = "stored-contract"))]
#[contract]
pub struct StoredVkVerifierContract;

#[cfg(any(not(target_family = "wasm"), feature = "stored-contract"))]
#[contractimpl]
impl StoredVkVerifierContract {
    /// Initializes the contract with an admin address and an initial verification key.
    pub fn initialize(env: Env, admin: Address, vk: Bytes) -> Result<(), VerifierError> {
        if env.storage().instance().has(&STORAGE_KEY_ADMIN) {
            return Err(VerifierError::Unsupported);
        }
        let _parsed = parse_vk(&env, &vk)?;
        env.storage().instance().set(&STORAGE_KEY_ADMIN, &admin);
        env.storage().instance().set(&STORAGE_KEY_VK, &vk);
        Ok(())
    }

    /// Updates the stored verification key. Requires admin authorization.
    pub fn set_vk(env: Env, admin: Address, vk: Bytes) -> Result<(), VerifierError> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_ADMIN)
            .ok_or(VerifierError::Unsupported)?;
        if admin != stored_admin {
            return Err(VerifierError::Unsupported);
        }
        let _parsed = parse_vk(&env, &vk)?;
        env.storage().instance().set(&STORAGE_KEY_VK, &vk);
        Ok(())
    }

    /// Returns the currently stored verification key.
    pub fn get_vk(env: Env) -> Result<Bytes, VerifierError> {
        env.storage()
            .instance()
            .get(&STORAGE_KEY_VK)
            .ok_or(VerifierError::Unsupported)
    }

    /// Verifies a proof against the stored verification key.
    pub fn verify(
        env: Env,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, VerifierError> {
        let vk: Bytes = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_VK)
            .ok_or(VerifierError::Unsupported)?;
        verify_groth16_bytes(&env, &vk, &proof, &public_inputs)
    }

    /// Directly verifies a proof against an explicitly provided verification key.
    pub fn verify_with_vk(
        env: Env,
        vk: Bytes,
        proof: BytesN<256>,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, VerifierError> {
        verify_groth16_bytes(&env, &vk, &proof, &public_inputs)
    }
}
