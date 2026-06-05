//! Storage layout parsing and path resolution for the `vm.hook()` cheatcode.
//!
//! Parses Solidity compiler `storageLayout` JSON and resolves dot-separated
//! paths (e.g. `"vaults.primary.data.value"`) plus ABI-encoded keys into
//! concrete `(slot, byte_offset, byte_size)` tuples for direct storage reads.

use alloy_dyn_abi::DynSolType;
use alloy_primitives::{keccak256, U256};
use serde::Deserialize;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Serde types mirroring solc's storageLayout JSON
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct StorageLayout {
    pub storage: Vec<StorageEntry>,
    #[serde(default)]
    pub types: HashMap<String, StorageType>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageEntry {
    pub label: String,
    pub offset: usize,
    pub slot: String,
    #[serde(rename = "type")]
    pub type_id: String,
    #[serde(default)]
    pub contract: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageType {
    pub encoding: String,
    pub label: String,
    #[serde(rename = "numberOfBytes")]
    pub number_of_bytes: String,
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub base: Option<String>,
    #[serde(default)]
    pub members: Option<Vec<StorageEntry>>,
}

// ---------------------------------------------------------------------------
// Resolved result
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSlot {
    pub slot: U256,
    pub offset: usize,
    pub size: usize,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("variable not found: {0}")]
    VariableNotFound(String),
    #[error("type not found in layout: {0}")]
    TypeNotFound(String),
    #[error("member not found: {0}")]
    MemberNotFound(String),
    #[error("not enough keys for path (need a key for mapping/array at `{0}`)")]
    MissingKey(String),
    #[error("key decode failed at `{0}`: {1}")]
    KeyDecode(String, String),
    #[error("path continues into non-struct type: {0}")]
    NotAStruct(String),
    #[error("unsupported encoding: {0}")]
    UnsupportedEncoding(String),
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

impl StorageLayout {
    /// Resolve a dot-separated path (e.g. `"vaults.primary.data.value"`) and
    /// ABI-encoded keys into a concrete storage location.
    ///
    /// Keys are consumed left-to-right each time the traversal hits a mapping
    /// or dynamic array. The caller should pass them as
    /// `abi.encode(key1, key2, …)` — standard 32-byte-padded ABI encoding.
    pub fn resolve(&self, path: &str, keys: &[u8]) -> Result<ResolvedSlot, ResolveError> {
        let parts: Vec<&str> = path.split('.').collect();
        if parts.is_empty() {
            return Err(ResolveError::VariableNotFound(path.to_string()));
        }

        // Try progressively longer prefixes to match dotted labels
        // (e.g. "example.main" as a single label for ERC-7201 namespaces)
        let mut matched = None;
        for prefix_len in 1..=parts.len() {
            let candidate = parts[..prefix_len].join(".");
            if let Some(entry) = self.storage.iter().find(|e| e.label == candidate) {
                matched = Some((entry, prefix_len));
            }
        }

        let (entry, consumed) = matched
            .ok_or_else(|| ResolveError::VariableNotFound(parts[0].to_string()))?;

        let base_slot = parse_slot(&entry.slot);
        let mut key_cursor = 0usize;

        self.resolve_inner(
            base_slot,
            entry.offset,
            &entry.type_id,
            &parts[consumed..],
            keys,
            &mut key_cursor,
        )
    }

    fn resolve_inner(
        &self,
        slot: U256,
        byte_offset: usize,
        type_id: &str,
        remaining_path: &[&str],
        keys: &[u8],
        key_cursor: &mut usize,
    ) -> Result<ResolvedSlot, ResolveError> {
        let ty = self
            .types
            .get(type_id)
            .ok_or_else(|| ResolveError::TypeNotFound(type_id.to_string()))?;

        match ty.encoding.as_str() {
            "inplace" => {
                if let Some(members) = &ty.members {
                    // Struct — navigate into member
                    if remaining_path.is_empty() {
                        // Returning the whole struct slot (first slot)
                        let size = parse_num_bytes(&ty.number_of_bytes);
                        return Ok(ResolvedSlot {
                            slot,
                            offset: byte_offset,
                            size,
                        });
                    }
                    let member_name = remaining_path[0];
                    let member = members
                        .iter()
                        .find(|m| m.label == member_name)
                        .ok_or_else(|| ResolveError::MemberNotFound(member_name.to_string()))?;
                    let member_slot = slot + U256::from(parse_slot(&member.slot));
                    self.resolve_inner(
                        member_slot,
                        member.offset,
                        &member.type_id,
                        &remaining_path[1..],
                        keys,
                        key_cursor,
                    )
                } else {
                    // Leaf type (uint256, bool, address, etc.) or enum
                    let size = parse_num_bytes(&ty.number_of_bytes);
                    Ok(ResolvedSlot {
                        slot,
                        offset: byte_offset,
                        size,
                    })
                }
            }

            "mapping" => {
                let key_type_id = ty
                    .key
                    .as_ref()
                    .ok_or_else(|| ResolveError::TypeNotFound("mapping missing key type".into()))?;
                let value_type_id = ty
                    .value
                    .as_ref()
                    .ok_or_else(|| ResolveError::TypeNotFound("mapping missing value type".into()))?;

                // Decode one key from the keys buffer
                let sol_type = type_id_to_sol_type(key_type_id, &self.types)?;
                let key_bytes = consume_key(keys, key_cursor, &sol_type, &ty.label)?;

                // mapping slot = keccak256(abi.encode(key) ++ abi.encode(slot))
                let derived_slot = mapping_slot(&key_bytes, slot);

                self.resolve_inner(
                    derived_slot,
                    0,
                    value_type_id,
                    remaining_path,
                    keys,
                    key_cursor,
                )
            }

            "dynamic_array" => {
                let base_type_id = ty
                    .base
                    .as_ref()
                    .ok_or_else(|| ResolveError::TypeNotFound("array missing base type".into()))?;

                // Consume an index key (uint256)
                let sol_type = DynSolType::Uint(256);
                let index_bytes = consume_key(keys, key_cursor, &sol_type, &ty.label)?;
                let index = U256::from_be_slice(&index_bytes);

                // Element size in slots (ceil(numberOfBytes / 32))
                let base_ty = self
                    .types
                    .get(base_type_id.as_str())
                    .ok_or_else(|| ResolveError::TypeNotFound(base_type_id.clone()))?;
                let elem_bytes = parse_num_bytes(&base_ty.number_of_bytes);
                let elem_slots = (elem_bytes + 31) / 32;

                // Dynamic array data starts at keccak256(slot)
                let data_start = array_data_slot(slot);
                let elem_slot = data_start + U256::from(elem_slots) * index;

                self.resolve_inner(
                    elem_slot,
                    0,
                    base_type_id,
                    remaining_path,
                    keys,
                    key_cursor,
                )
            }

            "bytes" => {
                // string / bytes storage — just return the header slot
                let size = parse_num_bytes(&ty.number_of_bytes);
                Ok(ResolvedSlot {
                    slot,
                    offset: byte_offset,
                    size,
                })
            }

            other => Err(ResolveError::UnsupportedEncoding(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Slot computation helpers
// ---------------------------------------------------------------------------

/// Compute the storage slot for `mapping[key]`.
/// Solidity: `keccak256(abi.encode(key, slot))`
fn mapping_slot(key_abi_word: &[u8], base_slot: U256) -> U256 {
    let mut buf = Vec::with_capacity(key_abi_word.len() + 32);
    buf.extend_from_slice(key_abi_word);
    buf.extend_from_slice(&base_slot.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(&buf).0)
}

/// Compute the data-start slot for a dynamic array.
/// Solidity: `keccak256(abi.encode(slot))`
fn array_data_slot(base_slot: U256) -> U256 {
    U256::from_be_bytes(keccak256(&base_slot.to_be_bytes::<32>()).0)
}

// ---------------------------------------------------------------------------
// Key decoding
// ---------------------------------------------------------------------------

/// Consume one ABI-encoded key from the keys buffer at `cursor`.
/// Returns the raw 32-byte ABI word (left-padded for value types).
fn consume_key(
    keys: &[u8],
    cursor: &mut usize,
    _sol_type: &DynSolType,
    context_label: &str,
) -> Result<Vec<u8>, ResolveError> {
    // All value types in mappings are ABI-encoded as 32-byte words
    if *cursor + 32 > keys.len() {
        return Err(ResolveError::MissingKey(context_label.to_string()));
    }
    let word = keys[*cursor..*cursor + 32].to_vec();
    *cursor += 32;
    Ok(word)
}

// ---------------------------------------------------------------------------
// Type conversion
// ---------------------------------------------------------------------------

/// Convert a storageLayout type id (e.g. `"t_address"`, `"t_uint256"`) to a
/// `DynSolType` for ABI decoding keys.
fn type_id_to_sol_type(
    type_id: &str,
    types: &HashMap<String, StorageType>,
) -> Result<DynSolType, ResolveError> {
    // Leaf types
    if type_id == "t_address" {
        return Ok(DynSolType::Address);
    }
    if type_id == "t_bool" {
        return Ok(DynSolType::Bool);
    }
    if let Some(rest) = type_id.strip_prefix("t_uint") {
        let bits: usize = rest
            .parse()
            .map_err(|_| ResolveError::TypeNotFound(type_id.to_string()))?;
        return Ok(DynSolType::Uint(bits));
    }
    if let Some(rest) = type_id.strip_prefix("t_int") {
        let bits: usize = rest
            .parse()
            .map_err(|_| ResolveError::TypeNotFound(type_id.to_string()))?;
        return Ok(DynSolType::Int(bits));
    }
    if let Some(rest) = type_id.strip_prefix("t_bytes") {
        if rest == "_storage" {
            return Ok(DynSolType::Bytes);
        }
        let n: usize = rest
            .parse()
            .map_err(|_| ResolveError::TypeNotFound(type_id.to_string()))?;
        return Ok(DynSolType::FixedBytes(n));
    }
    if type_id == "t_string_storage" {
        return Ok(DynSolType::String);
    }

    // Try to look up in the types map and use the label
    if let Some(ty) = types.get(type_id) {
        // For enums, they're stored as uint8
        if type_id.starts_with("t_enum") {
            let n = parse_num_bytes(&ty.number_of_bytes);
            return Ok(DynSolType::Uint(n * 8));
        }
    }

    Err(ResolveError::TypeNotFound(type_id.to_string()))
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parse_slot(s: &str) -> U256 {
    U256::from_str_radix(s, 10).unwrap_or(U256::ZERO)
}

fn parse_num_bytes(s: &str) -> usize {
    s.parse().unwrap_or(32)
}

/// Extract a value from a raw storage word given byte offset and size.
/// Returns a right-aligned U256 (zero-padded on the left).
pub fn extract_packed(raw: U256, offset: usize, size: usize) -> U256 {
    if size >= 32 {
        return raw;
    }
    let shift = offset * 8;
    let mask = (U256::from(1) << (size * 8)) - U256::from(1);
    (raw >> shift) & mask
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_layout() -> StorageLayout {
        let json = r#"{
            "storage": [
                {"label": "flagA", "offset": 0, "slot": "0", "type": "t_bool"},
                {"label": "flagB", "offset": 1, "slot": "0", "type": "t_bool"},
                {"label": "owner", "offset": 2, "slot": "0", "type": "t_address"},
                {"label": "counter", "offset": 0, "slot": "2", "type": "t_uint256"},
                {"label": "balances", "offset": 0, "slot": "8", "type": "t_mapping(t_address,t_uint256)"},
                {"label": "allowances", "offset": 0, "slot": "9", "type": "t_mapping(t_address,t_mapping(t_address,t_uint256))"},
                {"label": "values", "offset": 0, "slot": "10", "type": "t_array(t_uint256)dyn_storage"},
                {"label": "position", "offset": 0, "slot": "11", "type": "t_struct(Position)52_storage"}
            ],
            "types": {
                "t_bool": {"encoding": "inplace", "label": "bool", "numberOfBytes": "1"},
                "t_address": {"encoding": "inplace", "label": "address", "numberOfBytes": "20"},
                "t_uint256": {"encoding": "inplace", "label": "uint256", "numberOfBytes": "32"},
                "t_uint128": {"encoding": "inplace", "label": "uint128", "numberOfBytes": "16"},
                "t_uint64": {"encoding": "inplace", "label": "uint64", "numberOfBytes": "8"},
                "t_uint32": {"encoding": "inplace", "label": "uint32", "numberOfBytes": "4"},
                "t_mapping(t_address,t_uint256)": {
                    "encoding": "mapping", "key": "t_address", "value": "t_uint256",
                    "label": "mapping(address => uint256)", "numberOfBytes": "32"
                },
                "t_mapping(t_address,t_mapping(t_address,t_uint256))": {
                    "encoding": "mapping", "key": "t_address",
                    "value": "t_mapping(t_address,t_uint256)",
                    "label": "mapping(address => mapping(address => uint256))",
                    "numberOfBytes": "32"
                },
                "t_array(t_uint256)dyn_storage": {
                    "encoding": "dynamic_array", "base": "t_uint256",
                    "label": "uint256[]", "numberOfBytes": "32"
                },
                "t_struct(Position)52_storage": {
                    "encoding": "inplace", "label": "struct Position", "numberOfBytes": "32",
                    "members": [
                        {"label": "amount", "offset": 0, "slot": "0", "type": "t_uint128"},
                        {"label": "timestamp", "offset": 16, "slot": "0", "type": "t_uint64"},
                        {"label": "nonce", "offset": 24, "slot": "0", "type": "t_uint32"},
                        {"label": "active", "offset": 28, "slot": "0", "type": "t_bool"}
                    ]
                }
            }
        }"#;
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn test_simple_var() {
        let layout = sample_layout();
        let r = layout.resolve("counter", &[]).unwrap();
        assert_eq!(r.slot, U256::from(2));
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 32);
    }

    #[test]
    fn test_packed_bool() {
        let layout = sample_layout();
        let r = layout.resolve("flagA", &[]).unwrap();
        assert_eq!(r.slot, U256::ZERO);
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 1);

        let r = layout.resolve("flagB", &[]).unwrap();
        assert_eq!(r.slot, U256::ZERO);
        assert_eq!(r.offset, 1);
        assert_eq!(r.size, 1);
    }

    #[test]
    fn test_packed_address() {
        let layout = sample_layout();
        let r = layout.resolve("owner", &[]).unwrap();
        assert_eq!(r.slot, U256::ZERO);
        assert_eq!(r.offset, 2);
        assert_eq!(r.size, 20);
    }

    #[test]
    fn test_struct_member() {
        let layout = sample_layout();
        let r = layout.resolve("position.amount", &[]).unwrap();
        assert_eq!(r.slot, U256::from(11));
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 16);

        let r = layout.resolve("position.timestamp", &[]).unwrap();
        assert_eq!(r.slot, U256::from(11));
        assert_eq!(r.offset, 16);
        assert_eq!(r.size, 8);

        let r = layout.resolve("position.active", &[]).unwrap();
        assert_eq!(r.slot, U256::from(11));
        assert_eq!(r.offset, 28);
        assert_eq!(r.size, 1);
    }

    #[test]
    fn test_mapping() {
        let layout = sample_layout();
        // balances[0x0000...0001]
        let mut key = [0u8; 32];
        key[31] = 1; // address(1) as 32-byte ABI word
        let r = layout.resolve("balances", &key).unwrap();
        // slot = keccak256(abi.encode(address(1), uint256(8)))
        let expected_slot = mapping_slot(&key, U256::from(8));
        assert_eq!(r.slot, expected_slot);
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 32);
    }

    #[test]
    fn test_nested_mapping() {
        let layout = sample_layout();
        // allowances[addr1][addr2]
        let mut keys = [0u8; 64];
        keys[31] = 1; // addr1
        keys[63] = 2; // addr2
        let r = layout.resolve("allowances", &keys).unwrap();
        let slot1 = mapping_slot(&keys[..32], U256::from(9));
        let expected_slot = mapping_slot(&keys[32..64], slot1);
        assert_eq!(r.slot, expected_slot);
    }

    #[test]
    fn test_dynamic_array() {
        let layout = sample_layout();
        // values[2]
        let mut key = [0u8; 32];
        key[31] = 2; // index 2
        let r = layout.resolve("values", &key).unwrap();
        let data_start = array_data_slot(U256::from(10));
        assert_eq!(r.slot, data_start + U256::from(2));
        assert_eq!(r.size, 32);
    }

    #[test]
    fn test_extract_packed() {
        // Slot: [... | address(20 bytes) | flagB(1 byte) | flagA(1 byte)]
        // flagA at offset 0, size 1 → value = 1
        // flagB at offset 1, size 1 → value = 0
        // owner at offset 2, size 20
        let mut raw = U256::ZERO;
        raw |= U256::from(1); // flagA = true at offset 0
        raw |= U256::from(0) << 8; // flagB = false at offset 1
        raw |= U256::from(0xDEAD_u64) << 16; // part of owner at offset 2

        assert_eq!(extract_packed(raw, 0, 1), U256::from(1));
        assert_eq!(extract_packed(raw, 1, 1), U256::ZERO);
    }

    #[test]
    fn test_missing_key_error() {
        let layout = sample_layout();
        let r = layout.resolve("balances", &[]);
        assert!(r.is_err());
    }

    #[test]
    fn test_variable_not_found() {
        let layout = sample_layout();
        let r = layout.resolve("nonexistent", &[]);
        assert!(matches!(r, Err(ResolveError::VariableNotFound(_))));
    }
}
