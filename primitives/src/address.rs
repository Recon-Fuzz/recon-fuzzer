//! Address utilities for fuzzing
//!
//! Pre-generated addresses and parsing utilities.

use alloy_primitives::{Address, U256};

/// Pre-generated dummy addresses for fuzzing
pub fn pregen_addresses() -> Vec<Address> {
    (1u64..=3)
        .map(|i| Address::from_word(U256::from(i * 0xffffffff).into()))
        .collect()
}

/// Default deployer address
pub const DEFAULT_DEPLOYER: Address = Address::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xde, 0xad, 0xbe, 0xef,
]);

/// Default sender addresses for fuzzing
pub fn default_senders() -> Vec<Address> {
    vec![
        Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
        ]),
        Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        ]),
        Address::new([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        ]),
    ]
}

/// Parse an address from a hex string
pub fn parse_address(s: &str) -> Option<Address> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    Some(Address::from_slice(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pregen_addresses() {
        let addrs = pregen_addresses();
        assert_eq!(addrs.len(), 3);
        // Addresses should be unique
        assert_ne!(addrs[0], addrs[1]);
        assert_ne!(addrs[1], addrs[2]);
    }

    #[test]
    fn test_parse_address() {
        let addr = parse_address("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(addr.is_some());

        let addr = parse_address("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(addr.is_some());

        let addr = parse_address("invalid");
        assert!(addr.is_none());
    }
}
