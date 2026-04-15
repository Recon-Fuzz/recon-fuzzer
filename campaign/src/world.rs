//! World state for fuzzing
//!
//! Rust equivalent of Echidna's Types/World.hs

use abi::types::SignatureMap;
use alloy_primitives::{Address, FixedBytes, U256};

use std::collections::{BTreeSet, HashMap, HashSet};

/// The world state for fuzzing
#[derive(Debug, Clone, Default)]
pub struct World {
    /// Sender addresses to use for transactions
    /// Uses BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
    pub senders: BTreeSet<Address>,

    /// High-priority function signatures (main contract)
    pub high_signature_map: SignatureMap,

    /// Low-priority function signatures (other contracts)
    pub low_signature_map: Option<SignatureMap>,

    /// Function selectors of payable functions
    pub payable_sigs: Vec<FixedBytes<4>>,

    /// Function selectors with assert() calls
    pub assert_sigs: Vec<FixedBytes<4>>,

    /// Event signatures for logging
    pub event_map: HashMap<FixedBytes<32>, String>,

    /// Names of view/pure functions that don't modify state
    /// Used during shrinking to convert these calls to NoCall
    pub view_pure_functions: HashSet<String>,
}

impl World {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a sender address
    pub fn add_sender(&mut self, addr: Address) {
        self.senders.insert(addr);
    }

    /// Add default sender addresses
    pub fn with_default_senders(mut self) -> Self {
        // Default senders like echidna - use U256 conversion
        self.senders
            .insert(Address::from_word(U256::from(0x10000u64).into()));
        self.senders
            .insert(Address::from_word(U256::from(0x20000u64).into()));
        self.senders
            .insert(Address::from_word(U256::from(0x30000u64).into()));
        self
    }

    /// Set sender addresses
    pub fn with_senders(mut self, senders: Vec<Address>) -> Self {
        self.senders = senders.into_iter().collect();
        self
    }

    /// Get a random sender
    /// BTreeSet maintains sorted order, so iteration is deterministic (matches Haskell's Data.Set)
    pub fn random_sender<R: rand::Rng>(&self, rng: &mut R) -> Option<Address> {
        if self.senders.is_empty() {
            return None;
        }
        // BTreeSet iteration is already sorted, just collect and pick
        let senders: Vec<_> = self.senders.iter().copied().collect();
        let idx = rng.gen_range(0..senders.len());
        Some(senders[idx])
    }

    /// Get signatures with priority selection
    /// Uses usuallyVeryRarely: 99.9% high priority, 0.1% low priority
    pub fn get_signatures<R: rand::Rng>(&self, rng: &mut R) -> &SignatureMap {
        match &self.low_signature_map {
            None => &self.high_signature_map,
            Some(low_map) => {
                // usuallyVeryRarely: byFrequency [(999, high), (1, low)]
                if rng.gen_ratio(999, 1000) {
                    &self.high_signature_map
                } else {
                    low_map
                }
            }
        }
    }
}

/// Default sender addresses (matching echidna)
pub fn default_senders() -> BTreeSet<Address> {
    let mut senders = BTreeSet::new();
    senders.insert(Address::from_word(U256::from(0x10000u64).into()));
    senders.insert(Address::from_word(U256::from(0x20000u64).into()));
    senders.insert(Address::from_word(U256::from(0x30000u64).into()));
    senders
}
