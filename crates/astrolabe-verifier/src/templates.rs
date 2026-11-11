//! Production-ready Soroban ZK application contract templates.
//!
//! Provides three foundational ZK contract archetypes:
//! 1. [`MerkleMembershipContract`]: Private set/tree membership verification against authorized roots.
//! 2. [`PrivateVoteContract`]: Anonymous voting with Groth16 eligibility proof and nullifier replay protection.
//! 3. [`NullifierClaimContract`]: Private airdrop/claim redemption with nullifier tracking and replay protection.

#![cfg(any(not(target_family = "wasm"), feature = "stored-contract"))]

use crate::{parse_vk, verify_groth16_bytes, VerifierError};
use soroban_sdk::{contract, contractimpl, symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};

const STORAGE_KEY_ADMIN: Symbol = symbol_short!("admin");
const STORAGE_KEY_VK: Symbol = symbol_short!("vk");
const STORAGE_KEY_ROOT: Symbol = symbol_short!("root");
const STORAGE_KEY_PROPOSAL: Symbol = symbol_short!("proposal");

/// Soroban contract template for private Merkle tree leaf membership verification.
#[contract]
pub struct MerkleMembershipContract;

#[contractimpl]
impl MerkleMembershipContract {
    /// Initializes contract with administrator, verification key, and initial authorized root.
    pub fn initialize(
        env: Env,
        admin: Address,
        vk: Bytes,
        root: BytesN<32>,
    ) -> Result<(), VerifierError> {
        if env.storage().instance().has(&STORAGE_KEY_ADMIN) {
            return Err(VerifierError::Unsupported);
        }
        let _parsed = parse_vk(&env, &vk)?;
        env.storage().instance().set(&STORAGE_KEY_ADMIN, &admin);
        env.storage().instance().set(&STORAGE_KEY_VK, &vk);
        env.storage().instance().set(&STORAGE_KEY_ROOT, &root);
        Ok(())
    }

    /// Updates the authorized Merkle root. Requires admin authorization.
    pub fn set_root(env: Env, admin: Address, new_root: BytesN<32>) -> Result<(), VerifierError> {
        admin.require_auth();
        let stored_admin: Address = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_ADMIN)
            .ok_or(VerifierError::Unsupported)?;
        if admin != stored_admin {
            return Err(VerifierError::Unsupported);
        }
        env.storage().instance().set(&STORAGE_KEY_ROOT, &new_root);
        Ok(())
    }

    /// Returns the currently authorized Merkle root.
    pub fn get_root(env: Env) -> Result<BytesN<32>, VerifierError> {
        env.storage()
            .instance()
            .get(&STORAGE_KEY_ROOT)
            .ok_or(VerifierError::Unsupported)
    }

    /// Verifies that a private leaf is included in the authorized Merkle root.
    pub fn verify_membership(
        env: Env,
        proof: BytesN<256>,
        root: BytesN<32>,
    ) -> Result<bool, VerifierError> {
        let current_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_ROOT)
            .ok_or(VerifierError::Unsupported)?;
        if root != current_root {
            return Ok(false);
        }
        let vk: Bytes = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_VK)
            .ok_or(VerifierError::Unsupported)?;
        let mut pub_vec = Vec::new(&env);
        pub_vec.push_back(root);
        verify_groth16_bytes(&env, &vk, &proof, &pub_vec)
    }
}

/// Soroban contract template for anonymous private voting.
#[contract]
pub struct PrivateVoteContract;

#[contractimpl]
impl PrivateVoteContract {
    /// Initializes voting poll with admin, verification key, eligible voter roll root, and proposal ID.
    pub fn initialize(
        env: Env,
        admin: Address,
        vk: Bytes,
        voter_root: BytesN<32>,
        proposal_id: BytesN<32>,
    ) -> Result<(), VerifierError> {
        if env.storage().instance().has(&STORAGE_KEY_ADMIN) {
            return Err(VerifierError::Unsupported);
        }
        let _parsed = parse_vk(&env, &vk)?;
        env.storage().instance().set(&STORAGE_KEY_ADMIN, &admin);
        env.storage().instance().set(&STORAGE_KEY_VK, &vk);
        env.storage().instance().set(&STORAGE_KEY_ROOT, &voter_root);
        env.storage()
            .instance()
            .set(&STORAGE_KEY_PROPOSAL, &proposal_id);
        Ok(())
    }

    /// Casts an anonymous vote with ZK eligibility proof and nullifier replay protection.
    pub fn cast_vote(
        env: Env,
        proof: BytesN<256>,
        nullifier: BytesN<32>,
        option: u32,
    ) -> Result<u64, VerifierError> {
        // Prevent double-voting: nullifier must not have been spent
        if env.storage().persistent().has(&nullifier) {
            return Err(VerifierError::InvalidProof);
        }

        let vk: Bytes = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_VK)
            .ok_or(VerifierError::Unsupported)?;
        let voter_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_ROOT)
            .ok_or(VerifierError::Unsupported)?;
        let proposal: BytesN<32> = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_PROPOSAL)
            .ok_or(VerifierError::Unsupported)?;

        let mut option_scalar = [0u8; 32];
        if let Some(target) = option_scalar.get_mut(28..32) {
            target.copy_from_slice(&option.to_be_bytes());
        }
        let option_bytes = BytesN::from_array(&env, &option_scalar);

        // Public inputs: [voter_root, nullifier, proposal, option]
        let mut pub_inputs = Vec::new(&env);
        pub_inputs.push_back(voter_root);
        pub_inputs.push_back(nullifier.clone());
        pub_inputs.push_back(proposal);
        pub_inputs.push_back(option_bytes);

        let valid = verify_groth16_bytes(&env, &vk, &proof, &pub_inputs)?;
        if !valid {
            return Err(VerifierError::InvalidProof);
        }

        // Mark nullifier spent
        env.storage().persistent().set(&nullifier, &true);

        // Increment tally for option
        let current_tally: u64 = env.storage().persistent().get(&option).unwrap_or(0);
        let new_tally = current_tally.saturating_add(1);
        env.storage().persistent().set(&option, &new_tally);

        Ok(new_tally)
    }

    /// Returns `true` iff the specified nullifier has already voted.
    pub fn has_voted(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&nullifier)
    }

    /// Returns the current vote count for a given option.
    pub fn get_tally(env: Env, option: u32) -> u64 {
        env.storage().persistent().get(&option).unwrap_or(0)
    }
}

/// Soroban contract template for private nullifier claims and airdrop redemptions.
#[contract]
pub struct NullifierClaimContract;

#[contractimpl]
impl NullifierClaimContract {
    /// Initializes claim contract with admin, verification key, and eligible claims root.
    pub fn initialize(
        env: Env,
        admin: Address,
        vk: Bytes,
        claim_root: BytesN<32>,
    ) -> Result<(), VerifierError> {
        if env.storage().instance().has(&STORAGE_KEY_ADMIN) {
            return Err(VerifierError::Unsupported);
        }
        let _parsed = parse_vk(&env, &vk)?;
        env.storage().instance().set(&STORAGE_KEY_ADMIN, &admin);
        env.storage().instance().set(&STORAGE_KEY_VK, &vk);
        env.storage().instance().set(&STORAGE_KEY_ROOT, &claim_root);
        Ok(())
    }

    /// Redeems an authorized private claim, preventing double-claims via nullifier registry.
    pub fn claim(
        env: Env,
        proof: BytesN<256>,
        nullifier: BytesN<32>,
        recipient: BytesN<32>,
        amount: u64,
    ) -> Result<bool, VerifierError> {
        // Prevent double-claim
        if env.storage().persistent().has(&nullifier) {
            return Err(VerifierError::InvalidProof);
        }

        let vk: Bytes = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_VK)
            .ok_or(VerifierError::Unsupported)?;
        let claim_root: BytesN<32> = env
            .storage()
            .instance()
            .get(&STORAGE_KEY_ROOT)
            .ok_or(VerifierError::Unsupported)?;

        let mut amount_scalar = [0u8; 32];
        if let Some(target) = amount_scalar.get_mut(24..32) {
            target.copy_from_slice(&amount.to_be_bytes());
        }
        let amount_bytes = BytesN::from_array(&env, &amount_scalar);

        // Public inputs: [claim_root, nullifier, recipient, amount]
        let mut pub_inputs = Vec::new(&env);
        pub_inputs.push_back(claim_root);
        pub_inputs.push_back(nullifier.clone());
        pub_inputs.push_back(recipient);
        pub_inputs.push_back(amount_bytes);

        let valid = verify_groth16_bytes(&env, &vk, &proof, &pub_inputs)?;
        if !valid {
            return Err(VerifierError::InvalidProof);
        }

        // Mark nullifier spent
        env.storage().persistent().set(&nullifier, &true);

        Ok(true)
    }

    /// Returns `true` iff the specified claim nullifier has already been claimed.
    pub fn is_claimed(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&nullifier)
    }
}
