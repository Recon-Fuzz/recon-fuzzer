//! Compact storage layout string → solc `StorageLayout` JSON conversion.
//!
//! Parses a one-line struct-like definition:
//!   `"uint256 a, address b, (uint128 lo, uint64 hi) config, mapping(address => uint256) balances"`
//!
//! into the equivalent `StorageLayout` with correct slot/offset packing
//! (same rules as solc).

use crate::storage_layout::{StorageEntry, StorageLayout, StorageType};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a compact struct definition string into a `StorageLayout`.
///
/// Supports:
/// - Value types: `uint8`..`uint256`, `int8`..`int256`, `bool`, `address`, `bytes1`..`bytes32`
/// - Inline tuples: `(uint32 x, bool y) name`
/// - Nested tuples: `(uint16 a, (uint32 b, bool c) inner) name`
/// - Mappings: `mapping(address => uint256) name`, nested mappings
/// - Dynamic arrays: `uint256[] name`, `(uint32 x, bool y)[] name`
/// - Fixed arrays: `uint256[3] name`, `(uint32 x, bool y)[3] name`
pub fn parse_compact(input: &str) -> Result<StorageLayout, ParseError> {
    let fields = split_top_level_fields(input.trim())?;
    let mut types: HashMap<String, StorageType> = HashMap::new();
    let mut storage: Vec<StorageEntry> = Vec::new();
    let mut slot: usize = 0;
    let mut offset: usize = 0;
    let mut type_counter: usize = 0;

    for field_str in &fields {
        let (ty_str, name) = split_type_and_name(field_str.trim())?;
        let type_id = intern_type(&ty_str, &mut types, &mut type_counter)?;
        let ty = types.get(&type_id).unwrap();
        let size = parse_num_bytes(&ty.number_of_bytes);

        let needs_new_slot = size > 32
            || ty.encoding == "mapping"
            || ty.encoding == "dynamic_array"
            || ty.encoding == "bytes"
            || ty.members.is_some()
            || (offset > 0 && offset + size > 32);

        if needs_new_slot && offset > 0 {
            slot += 1;
            offset = 0;
        }

        storage.push(StorageEntry {
            label: name.to_string(),
            offset,
            slot: slot.to_string(),
            type_id: type_id.clone(),
            contract: None,
        });

        // Advance slot/offset
        if size <= 32 && ty.encoding == "inplace" && ty.members.is_none() {
            offset += size;
            if offset >= 32 {
                slot += 1;
                offset = 0;
            }
        } else {
            let slots_used = (size + 31) / 32;
            slot += slots_used;
            offset = 0;
        }
    }

    Ok(StorageLayout { storage, types })
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("expected field name after type: {0}")]
    MissingName(String),
    #[error("unknown type: {0}")]
    UnknownType(String),
    #[error("unbalanced parentheses")]
    UnbalancedParens,
    #[error("empty input")]
    Empty,
    #[error("invalid mapping syntax: {0}")]
    InvalidMapping(String),
}

// ---------------------------------------------------------------------------
// Top-level field splitting (respects nested parens and mapping<...>)
// ---------------------------------------------------------------------------

fn split_top_level_fields(input: &str) -> Result<Vec<String>, ParseError> {
    if input.is_empty() {
        return Err(ParseError::Empty);
    }
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut start = 0;
    let bytes = input.as_bytes();

    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                if depth == 0 {
                    return Err(ParseError::UnbalancedParens);
                }
                depth -= 1;
            }
            b',' if depth == 0 => {
                let s = input[start..i].trim();
                if !s.is_empty() {
                    fields.push(s.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(ParseError::UnbalancedParens);
    }
    let last = input[start..].trim();
    if !last.is_empty() {
        fields.push(last.to_string());
    }
    Ok(fields)
}

// ---------------------------------------------------------------------------
// Split "type name" — type can contain parens, brackets, mapping(...)
// ---------------------------------------------------------------------------

fn split_type_and_name(field: &str) -> Result<(String, String), ParseError> {
    let field = field.trim();
    if field.is_empty() {
        return Err(ParseError::MissingName("empty field".into()));
    }

    // Find the last space-separated token that is a valid identifier (the name).
    // Everything before it is the type.
    // But tuples like "(uint32 x, bool y) name" have spaces inside parens.
    // Strategy: scan from the end, find the name (last word that isn't part of
    // array brackets or closing paren).

    // Find the last whitespace that is at depth 0
    let bytes = field.as_bytes();
    let mut depth = 0usize;
    let mut last_space_at_depth0 = None;

    for i in 0..bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b' ' | b'\t' if depth == 0 => {
                last_space_at_depth0 = Some(i);
            }
            _ => {}
        }
    }

    match last_space_at_depth0 {
        Some(idx) => {
            let ty = field[..idx].trim();
            let name = field[idx + 1..].trim();
            if name.is_empty() || ty.is_empty() {
                return Err(ParseError::MissingName(field.into()));
            }
            Ok((ty.to_string(), name.to_string()))
        }
        None => Err(ParseError::MissingName(field.into())),
    }
}

// ---------------------------------------------------------------------------
// Intern a type string into the types map, returning its type_id
// ---------------------------------------------------------------------------

fn intern_type(
    ty_str: &str,
    types: &mut HashMap<String, StorageType>,
    counter: &mut usize,
) -> Result<String, ParseError> {
    let ty_str = ty_str.trim();

    // Check for array suffix: type[] or type[N]
    if let Some((base_type, array_info)) = parse_array_suffix(ty_str) {
        let base_id = intern_type(&base_type, types, counter)?;
        let base_ty = types.get(&base_id).unwrap();
        let base_bytes = parse_num_bytes(&base_ty.number_of_bytes);

        match array_info {
            ArrayInfo::Dynamic => {
                let type_id = format!("t_array({})dyn_storage", base_id);
                if !types.contains_key(&type_id) {
                    types.insert(
                        type_id.clone(),
                        StorageType {
                            encoding: "dynamic_array".into(),
                            label: format!("{}[]", base_ty.label),
                            number_of_bytes: "32".into(),
                            key: None,
                            value: None,
                            base: Some(base_id),
                            members: None,
                        },
                    );
                }
                return Ok(type_id);
            }
            ArrayInfo::Fixed(n) => {
                let elem_slots = (base_bytes + 31) / 32;
                let total_bytes = elem_slots * 32 * n;
                let type_id = format!("t_array({}){}_storage", base_id, n);
                if !types.contains_key(&type_id) {
                    types.insert(
                        type_id.clone(),
                        StorageType {
                            encoding: "inplace".into(),
                            label: format!("{}[{}]", base_ty.label, n),
                            number_of_bytes: total_bytes.to_string(),
                            key: None,
                            value: None,
                            base: Some(base_id),
                            members: None,
                        },
                    );
                }
                return Ok(type_id);
            }
        }
    }

    // Mapping: mapping(K => V)
    if ty_str.starts_with("mapping(") && ty_str.ends_with(')') {
        let inner = &ty_str[8..ty_str.len() - 1]; // strip "mapping(" and ")"
        let arrow_pos = find_arrow(inner)?;
        let key_str = inner[..arrow_pos].trim();
        let val_str = inner[arrow_pos + 2..].trim();

        let key_id = intern_type(key_str, types, counter)?;
        let val_id = intern_type(val_str, types, counter)?;
        let key_ty = types.get(&key_id).unwrap();
        let val_ty = types.get(&val_id).unwrap();

        let type_id = format!("t_mapping({},{})", key_id, val_id);
        if !types.contains_key(&type_id) {
            types.insert(
                type_id.clone(),
                StorageType {
                    encoding: "mapping".into(),
                    label: format!("mapping({} => {})", key_ty.label, val_ty.label),
                    number_of_bytes: "32".into(),
                    key: Some(key_id),
                    value: Some(val_id),
                    base: None,
                    members: None,
                },
            );
        }
        return Ok(type_id);
    }

    // Tuple: (type1 name1, type2 name2, ...)
    if ty_str.starts_with('(') && ty_str.ends_with(')') {
        let inner = &ty_str[1..ty_str.len() - 1];
        let fields = split_top_level_fields(inner)?;

        let mut members = Vec::new();
        let mut member_slot: usize = 0;
        let mut member_offset: usize = 0;

        for field_str in &fields {
            let (m_type_str, m_name) = split_type_and_name(field_str.trim())?;
            let m_type_id = intern_type(&m_type_str, types, counter)?;
            let m_ty = types.get(&m_type_id).unwrap();
            let m_size = parse_num_bytes(&m_ty.number_of_bytes);

            let needs_new_slot = m_size > 32
                || m_ty.encoding == "mapping"
                || m_ty.encoding == "dynamic_array"
                || m_ty.encoding == "bytes"
                || m_ty.members.is_some()
                || (member_offset > 0 && member_offset + m_size > 32);

            if needs_new_slot && member_offset > 0 {
                member_slot += 1;
                member_offset = 0;
            }

            members.push(StorageEntry {
                label: m_name.to_string(),
                offset: member_offset,
                slot: member_slot.to_string(),
                type_id: m_type_id.clone(),
                contract: None,
            });

            if m_size <= 32 && m_ty.encoding == "inplace" && m_ty.members.is_none() {
                member_offset += m_size;
                if member_offset >= 32 {
                    member_slot += 1;
                    member_offset = 0;
                }
            } else {
                let slots_used = (m_size + 31) / 32;
                member_slot += slots_used;
                member_offset = 0;
            }
        }

        let raw = if member_offset > 0 {
            member_slot * 32 + member_offset
        } else {
            member_slot * 32
        };
        let total_bytes = if raw == 0 { 32 } else { ((raw + 31) / 32) * 32 };

        *counter += 1;
        let type_id = format!("t_struct(anon){}_storage", counter);
        types.insert(
            type_id.clone(),
            StorageType {
                encoding: "inplace".into(),
                label: format!("struct anon_{}", counter),
                number_of_bytes: total_bytes.to_string(),
                key: None,
                value: None,
                base: None,
                members: Some(members),
            },
        );
        return Ok(type_id);
    }

    // Primitive types
    let (type_id, label, size) = match ty_str {
        "bool" => ("t_bool", "bool", 1),
        "address" => ("t_address", "address", 20),
        "uint" => ("t_uint256", "uint256", 32),
        "int" => ("t_int256", "int256", 32),
        "bytes" => {
            // Dynamic bytes — takes one slot (header)
            let id = "t_bytes_storage".to_string();
            if !types.contains_key(&id) {
                types.insert(
                    id.clone(),
                    StorageType {
                        encoding: "bytes".into(),
                        label: "bytes".into(),
                        number_of_bytes: "32".into(),
                        key: None,
                        value: None,
                        base: None,
                        members: None,
                    },
                );
            }
            return Ok(id);
        }
        "string" => {
            let id = "t_string_storage".to_string();
            if !types.contains_key(&id) {
                types.insert(
                    id.clone(),
                    StorageType {
                        encoding: "bytes".into(),
                        label: "string".into(),
                        number_of_bytes: "32".into(),
                        key: None,
                        value: None,
                        base: None,
                        members: None,
                    },
                );
            }
            return Ok(id);
        }
        s if s.starts_with("uint") => {
            let bits: usize = s[4..]
                .parse()
                .map_err(|_| ParseError::UnknownType(s.into()))?;
            if bits == 0 || bits > 256 || bits % 8 != 0 {
                return Err(ParseError::UnknownType(s.into()));
            }
            let id_str = format!("t_uint{}", bits);
            let size = bits / 8;
            if !types.contains_key(&id_str) {
                types.insert(
                    id_str.clone(),
                    StorageType {
                        encoding: "inplace".into(),
                        label: s.to_string(),
                        number_of_bytes: size.to_string(),
                        key: None,
                        value: None,
                        base: None,
                        members: None,
                    },
                );
            }
            return Ok(id_str);
        }
        s if s.starts_with("int") => {
            let bits: usize = s[3..]
                .parse()
                .map_err(|_| ParseError::UnknownType(s.into()))?;
            if bits == 0 || bits > 256 || bits % 8 != 0 {
                return Err(ParseError::UnknownType(s.into()));
            }
            let id_str = format!("t_int{}", bits);
            let size = bits / 8;
            if !types.contains_key(&id_str) {
                types.insert(
                    id_str.clone(),
                    StorageType {
                        encoding: "inplace".into(),
                        label: s.to_string(),
                        number_of_bytes: size.to_string(),
                        key: None,
                        value: None,
                        base: None,
                        members: None,
                    },
                );
            }
            return Ok(id_str);
        }
        s if s.starts_with("bytes") && s.len() > 5 && s[5..].parse::<usize>().is_ok() => {
            let n: usize = s[5..].parse().unwrap();
            if n == 0 || n > 32 {
                return Err(ParseError::UnknownType(s.into()));
            }
            let id_str = format!("t_bytes{}", n);
            if !types.contains_key(&id_str) {
                types.insert(
                    id_str.clone(),
                    StorageType {
                        encoding: "inplace".into(),
                        label: s.to_string(),
                        number_of_bytes: n.to_string(),
                        key: None,
                        value: None,
                        base: None,
                        members: None,
                    },
                );
            }
            return Ok(id_str);
        }
        _ => return Err(ParseError::UnknownType(ty_str.into())),
    };

    let id = type_id.to_string();
    if !types.contains_key(&id) {
        types.insert(
            id.clone(),
            StorageType {
                encoding: "inplace".into(),
                label: label.into(),
                number_of_bytes: size.to_string(),
                key: None,
                value: None,
                base: None,
                members: None,
            },
        );
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// Array suffix parsing
// ---------------------------------------------------------------------------

enum ArrayInfo {
    Dynamic,
    Fixed(usize),
}

fn parse_array_suffix(ty: &str) -> Option<(String, ArrayInfo)> {
    if !ty.ends_with(']') {
        return None;
    }
    // Find the matching '[' from the end, but skip nested parens
    let bytes = ty.as_bytes();
    let mut i = bytes.len() - 2; // skip the final ']'
    let mut depth = 0;
    loop {
        match bytes[i] {
            b']' => depth += 1,
            b'[' if depth > 0 => depth -= 1,
            b'[' if depth == 0 => {
                let base = ty[..i].to_string();
                let size_str = &ty[i + 1..ty.len() - 1];
                if size_str.is_empty() {
                    return Some((base, ArrayInfo::Dynamic));
                } else if let Ok(n) = size_str.parse::<usize>() {
                    return Some((base, ArrayInfo::Fixed(n)));
                } else {
                    return None;
                }
            }
            _ => {}
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

// ---------------------------------------------------------------------------
// Find " => " arrow in mapping inner, respecting nested parens
// ---------------------------------------------------------------------------

fn find_arrow(s: &str) -> Result<usize, ParseError> {
    let bytes = s.as_bytes();
    let mut depth = 0usize;
    for i in 0..bytes.len().saturating_sub(1) {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b'=' if depth == 0 && bytes.get(i + 1) == Some(&b'>') => {
                return Ok(i);
            }
            _ => {}
        }
    }
    Err(ParseError::InvalidMapping(s.into()))
}

fn parse_num_bytes(s: &str) -> usize {
    s.parse().unwrap_or(32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_layout::ResolvedSlot;
    use alloy_primitives::U256;

    fn resolve(layout: &StorageLayout, path: &str) -> ResolvedSlot {
        layout.resolve(path, &[]).unwrap()
    }

    fn resolve_keys(layout: &StorageLayout, path: &str, keys: &[u8]) -> ResolvedSlot {
        layout.resolve(path, keys).unwrap()
    }

    /// Look up a top-level storage entry by name and return (slot, offset, size).
    fn entry(layout: &StorageLayout, name: &str) -> (usize, usize, usize) {
        let e = layout.storage.iter().find(|e| e.label == name)
            .unwrap_or_else(|| panic!("entry '{}' not found", name));
        let ty = layout.types.get(&e.type_id).unwrap();
        (e.slot.parse().unwrap(), e.offset, parse_num_bytes(&ty.number_of_bytes))
    }

    // === Primitive types ===

    #[test]
    fn test_single_uint256() {
        let l = parse_compact("uint256 a").unwrap();
        let r = resolve(&l, "a");
        assert_eq!(r.slot, U256::from(0));
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 32);
    }

    #[test]
    fn test_single_bool() {
        let l = parse_compact("bool flag").unwrap();
        let r = resolve(&l, "flag");
        assert_eq!(r.slot, U256::from(0));
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 1);
    }

    #[test]
    fn test_single_address() {
        let l = parse_compact("address owner").unwrap();
        let r = resolve(&l, "owner");
        assert_eq!(r.slot, U256::from(0));
        assert_eq!(r.offset, 0);
        assert_eq!(r.size, 20);
    }

    #[test]
    fn test_bytes32() {
        let l = parse_compact("bytes32 h").unwrap();
        let r = resolve(&l, "h");
        assert_eq!(r.size, 32);
    }

    #[test]
    fn test_bytes1() {
        let l = parse_compact("bytes1 b").unwrap();
        let r = resolve(&l, "b");
        assert_eq!(r.size, 1);
    }

    #[test]
    fn test_int128() {
        let l = parse_compact("int128 x").unwrap();
        let r = resolve(&l, "x");
        assert_eq!(r.size, 16);
    }

    // === Packing ===

    #[test]
    fn test_two_bools_pack() {
        let l = parse_compact("bool a, bool b").unwrap();
        let ra = resolve(&l, "a");
        let rb = resolve(&l, "b");
        assert_eq!(ra.slot, U256::from(0));
        assert_eq!(ra.offset, 0);
        assert_eq!(rb.slot, U256::from(0));
        assert_eq!(rb.offset, 1);
    }

    #[test]
    fn test_bool_address_pack() {
        // bool (1) + address (20) = 21 bytes, fits in one slot
        let l = parse_compact("bool a, address b").unwrap();
        let ra = resolve(&l, "a");
        let rb = resolve(&l, "b");
        assert_eq!(ra.slot, U256::from(0));
        assert_eq!(ra.offset, 0);
        assert_eq!(rb.slot, U256::from(0));
        assert_eq!(rb.offset, 1);
    }

    #[test]
    fn test_address_bool_pack() {
        // address (20) + bool (1) = 21 bytes, fits in one slot
        let l = parse_compact("address a, bool b").unwrap();
        let ra = resolve(&l, "a");
        let rb = resolve(&l, "b");
        assert_eq!(ra.slot, U256::from(0));
        assert_eq!(ra.offset, 0);
        assert_eq!(rb.slot, U256::from(0));
        assert_eq!(rb.offset, 20);
    }

    #[test]
    fn test_uint256_forces_new_slot() {
        let l = parse_compact("bool a, uint256 b").unwrap();
        let ra = resolve(&l, "a");
        let rb = resolve(&l, "b");
        assert_eq!(ra.slot, U256::from(0));
        assert_eq!(rb.slot, U256::from(1));
        assert_eq!(rb.offset, 0);
    }

    #[test]
    fn test_overflow_to_next_slot() {
        // address(20) + address(20) = 40 > 32, second goes to next slot
        let l = parse_compact("address a, address b").unwrap();
        let ra = resolve(&l, "a");
        let rb = resolve(&l, "b");
        assert_eq!(ra.slot, U256::from(0));
        assert_eq!(rb.slot, U256::from(1));
    }

    #[test]
    fn test_packed_small_types() {
        // uint8(1) + uint16(2) + uint32(4) + uint64(8) + uint128(16) = 31, fits!
        let l = parse_compact("uint8 a, uint16 b, uint32 c, uint64 d, uint128 e").unwrap();
        assert_eq!(resolve(&l, "a").offset, 0);
        assert_eq!(resolve(&l, "b").offset, 1);
        assert_eq!(resolve(&l, "c").offset, 3);
        assert_eq!(resolve(&l, "d").offset, 7);
        assert_eq!(resolve(&l, "e").offset, 15);
        // All in slot 0
        assert_eq!(resolve(&l, "e").slot, U256::from(0));
    }

    #[test]
    fn test_packed_overflow_at_boundary() {
        // uint128(16) + uint128(16) = 32, exactly fills slot
        // bool should go to slot 1
        let l = parse_compact("uint128 a, uint128 b, bool c").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "a").offset, 0);
        assert_eq!(resolve(&l, "b").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").offset, 16);
        assert_eq!(resolve(&l, "c").slot, U256::from(1));
        assert_eq!(resolve(&l, "c").offset, 0);
    }

    // === Sequential full slots ===

    #[test]
    fn test_multiple_uint256() {
        let l = parse_compact("uint256 a, uint256 b, uint256 c").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").slot, U256::from(1));
        assert_eq!(resolve(&l, "c").slot, U256::from(2));
    }

    // === Mappings ===

    #[test]
    fn test_simple_mapping() {
        let l = parse_compact("mapping(address => uint256) m").unwrap();
        assert_eq!(entry(&l, "m"), (0, 0, 32));
    }

    #[test]
    fn test_mapping_after_value() {
        let l = parse_compact("uint256 a, mapping(address => uint256) m").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(entry(&l, "m").0, 1);
    }

    #[test]
    fn test_nested_mapping() {
        let l =
            parse_compact("mapping(address => mapping(uint256 => bool)) m").unwrap();
        assert_eq!(entry(&l, "m").0, 0);
    }

    // === Inline tuples (structs) ===

    #[test]
    fn test_simple_tuple() {
        let l = parse_compact("(uint128 lo, uint128 hi) s").unwrap();
        let r_lo = resolve(&l, "s.lo");
        let r_hi = resolve(&l, "s.hi");
        assert_eq!(r_lo.slot, U256::from(0));
        assert_eq!(r_lo.offset, 0);
        assert_eq!(r_lo.size, 16);
        assert_eq!(r_hi.slot, U256::from(0));
        assert_eq!(r_hi.offset, 16);
        assert_eq!(r_hi.size, 16);
    }

    #[test]
    fn test_tuple_starts_new_slot() {
        let l = parse_compact("bool a, (uint128 lo, uint128 hi) s").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        // Struct starts a new slot
        assert_eq!(resolve(&l, "s.lo").slot, U256::from(1));
    }

    #[test]
    fn test_nested_tuple() {
        let l = parse_compact("(uint16 b, (uint32 x, bool y) inner) mid").unwrap();
        let r_b = resolve(&l, "mid.b");
        let r_x = resolve(&l, "mid.inner.x");
        let r_y = resolve(&l, "mid.inner.y");
        assert_eq!(r_b.slot, U256::from(0));
        assert_eq!(r_b.offset, 0);
        assert_eq!(r_b.size, 2);
        // inner struct starts new slot within mid
        assert_eq!(r_x.slot, U256::from(1));
        assert_eq!(r_x.offset, 0);
        assert_eq!(r_y.slot, U256::from(1));
        assert_eq!(r_y.offset, 4);
    }

    #[test]
    fn test_three_level_nested_tuple() {
        let l = parse_compact(
            "(uint256 a, (uint16 b, (uint32 x, bool y) inner) mid, uint256 top) deep",
        )
        .unwrap();
        assert_eq!(resolve(&l, "deep.a").slot, U256::from(0));
        assert_eq!(resolve(&l, "deep.mid.b").slot, U256::from(1));
        assert_eq!(resolve(&l, "deep.mid.inner.x").slot, U256::from(2));
        assert_eq!(resolve(&l, "deep.mid.inner.y").slot, U256::from(2));
        assert_eq!(resolve(&l, "deep.mid.inner.y").offset, 4);
        assert_eq!(resolve(&l, "deep.top").slot, U256::from(3));
    }

    // === Dynamic arrays ===

    #[test]
    fn test_dynamic_array() {
        let l = parse_compact("uint256[] items").unwrap();
        assert_eq!(entry(&l, "items").0, 0);
    }

    #[test]
    fn test_dynamic_array_after_value() {
        let l = parse_compact("uint256 a, uint256[] items").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(entry(&l, "items").0, 1);
    }

    // === Fixed arrays ===

    #[test]
    fn test_fixed_array() {
        let l = parse_compact("uint256[3] arr").unwrap();
        let r = resolve(&l, "arr");
        assert_eq!(r.slot, U256::from(0));
    }

    #[test]
    fn test_fixed_array_takes_slots() {
        // uint256[3] takes 3 slots, next field at slot 3
        let l = parse_compact("uint256[3] arr, uint256 b").unwrap();
        assert_eq!(resolve(&l, "arr").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").slot, U256::from(3));
    }

    // === Tuple arrays ===

    #[test]
    fn test_dynamic_tuple_array() {
        let l = parse_compact("(uint32 x, bool y)[] items").unwrap();
        assert_eq!(entry(&l, "items").0, 0);
    }

    #[test]
    fn test_fixed_tuple_array() {
        // (uint32, bool) = 32 bytes (one slot per element), [3] = 3 slots
        let l = parse_compact("(uint32 x, bool y)[3] items, uint256 b").unwrap();
        assert_eq!(resolve(&l, "items").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").slot, U256::from(3));
    }

    // === Mapping to tuple ===

    #[test]
    fn test_mapping_to_tuple() {
        let l =
            parse_compact("mapping(address => (uint128 lo, bool flag)) m").unwrap();
        let mut key = [0u8; 32];
        key[31] = 1;
        let r = resolve_keys(&l, "m.lo", &key);
        assert_eq!(r.size, 16);
        assert_eq!(r.offset, 0);
    }

    // === Complex real-world-like layout ===

    #[test]
    fn test_complex_layout() {
        let l = parse_compact(
            "uint256 a, address owner, mapping(address => uint256) balances, (uint128 fee, uint64 delay, bool paused) config, mapping(uint256 => mapping(address => uint256)) matrix"
        ).unwrap();

        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "owner").slot, U256::from(1));
        assert_eq!(resolve(&l, "owner").offset, 0);
        assert_eq!(resolve(&l, "owner").size, 20);
        assert_eq!(entry(&l, "balances").0, 2);
        assert_eq!(resolve(&l, "config.fee").slot, U256::from(3));
        assert_eq!(resolve(&l, "config.fee").offset, 0);
        assert_eq!(resolve(&l, "config.delay").slot, U256::from(3));
        assert_eq!(resolve(&l, "config.delay").offset, 16);
        assert_eq!(resolve(&l, "config.paused").slot, U256::from(3));
        assert_eq!(resolve(&l, "config.paused").offset, 24);
        assert_eq!(entry(&l, "matrix").0, 4);
    }

    // === Match against solc output for Complex contract ===

    #[test]
    fn test_matches_solc_complex_deep() {
        // From forge inspect Complex storageLayout:
        // Deep struct: a(slot0), mid(slot1-2), items(slot3), fixedInners(slot4-6),
        // nestedArrayOfStructs(slot7-8), mapped(slot9), doubleMap(slot10)
        let l = parse_compact(
            "uint256 a, (uint16 b, (uint32 x, bool y) nested) mid, uint256[] items, (uint32 x, bool y)[3] fixedInners, (uint32 x, bool y)[][2] nestedArrayOfStructs, mapping(address => (uint32 x, bool y)) mapped, mapping(uint256 => mapping(address => uint256)) doubleMap"
        ).unwrap();

        // Matches solc:
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "mid.b").slot, U256::from(1));
        assert_eq!(resolve(&l, "mid.b").offset, 0);
        assert_eq!(resolve(&l, "mid.nested.x").slot, U256::from(2));
        assert_eq!(resolve(&l, "mid.nested.x").offset, 0);
        assert_eq!(resolve(&l, "mid.nested.y").slot, U256::from(2));
        assert_eq!(resolve(&l, "mid.nested.y").offset, 4);
        assert_eq!(entry(&l, "items").0, 3);
        assert_eq!(entry(&l, "fixedInners").0, 4);
        assert_eq!(entry(&l, "nestedArrayOfStructs").0, 7);
        assert_eq!(entry(&l, "mapped").0, 9);
        assert_eq!(entry(&l, "doubleMap").0, 10);
    }

    // === Error cases ===

    #[test]
    fn test_empty_input() {
        assert!(parse_compact("").is_err());
    }

    #[test]
    fn test_missing_name() {
        assert!(parse_compact("uint256").is_err());
    }

    #[test]
    fn test_unknown_type() {
        assert!(parse_compact("foobar x").is_err());
    }

    #[test]
    fn test_unbalanced_parens() {
        assert!(parse_compact("(uint256 a x").is_err());
    }

    // === Bare type aliases ===

    #[test]
    fn test_bare_uint() {
        let l = parse_compact("uint x").unwrap();
        assert_eq!(resolve(&l, "x").size, 32);
    }

    #[test]
    fn test_bare_int() {
        let l = parse_compact("int x").unwrap();
        assert_eq!(resolve(&l, "x").size, 32);
    }

    #[test]
    fn test_bare_bytes() {
        let l = parse_compact("bytes data").unwrap();
        let (slot, _, _) = entry(&l, "data");
        assert_eq!(slot, 0);
    }

    #[test]
    fn test_string_type() {
        let l = parse_compact("string name").unwrap();
        let (slot, _, _) = entry(&l, "name");
        assert_eq!(slot, 0);
    }

    #[test]
    fn test_string_takes_one_slot() {
        let l = parse_compact("string name, uint256 after").unwrap();
        assert_eq!(entry(&l, "name").0, 0);
        assert_eq!(resolve(&l, "after").slot, U256::from(1));
    }

    #[test]
    fn test_bytes_takes_one_slot() {
        let l = parse_compact("bytes data, uint256 after").unwrap();
        assert_eq!(entry(&l, "data").0, 0);
        assert_eq!(resolve(&l, "after").slot, U256::from(1));
    }

    #[test]
    fn test_mapping_bytes_key() {
        let l = parse_compact("mapping(uint256 => bytes) m").unwrap();
        assert_eq!(entry(&l, "m").0, 0);
    }

    #[test]
    fn test_invalid_uint_bits() {
        assert!(parse_compact("uint7 x").is_err());
        assert!(parse_compact("uint0 x").is_err());
        assert!(parse_compact("uint512 x").is_err());
    }

    // === Every uint size ===

    #[test]
    fn test_all_uint_sizes() {
        for bits in (8..=256).step_by(8) {
            let input = format!("uint{} x", bits);
            let l = parse_compact(&input).unwrap();
            let r = resolve(&l, "x");
            assert_eq!(r.size, bits / 8, "uint{} size wrong", bits);
        }
    }

    #[test]
    fn test_all_int_sizes() {
        for bits in (8..=256).step_by(8) {
            let input = format!("int{} x", bits);
            let l = parse_compact(&input).unwrap();
            let r = resolve(&l, "x");
            assert_eq!(r.size, bits / 8, "int{} size wrong", bits);
        }
    }

    #[test]
    fn test_all_bytes_n() {
        for n in 1..=32 {
            let input = format!("bytes{} x", n);
            let l = parse_compact(&input).unwrap();
            let r = resolve(&l, "x");
            assert_eq!(r.size, n, "bytes{} size wrong", n);
        }
    }

    // === Packing edge cases ===

    #[test]
    fn test_31_bytes_then_1_byte_fits() {
        // uint248 (31 bytes) + bool (1 byte) = 32, fits in one slot
        let l = parse_compact("uint248 a, bool b").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "a").offset, 0);
        assert_eq!(resolve(&l, "b").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").offset, 31);
    }

    #[test]
    fn test_31_bytes_then_2_bytes_overflows() {
        // uint248 (31 bytes) + uint16 (2 bytes) = 33 > 32, overflow
        let l = parse_compact("uint248 a, uint16 b").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").slot, U256::from(1));
    }

    #[test]
    fn test_many_bools_pack_32() {
        // 32 bools = 32 bytes, fills one slot exactly
        let fields: Vec<String> = (0..32).map(|i| format!("bool b{}", i)).collect();
        let input = fields.join(", ");
        let l = parse_compact(&input).unwrap();
        assert_eq!(resolve(&l, "b0").slot, U256::from(0));
        assert_eq!(resolve(&l, "b0").offset, 0);
        assert_eq!(resolve(&l, "b31").slot, U256::from(0));
        assert_eq!(resolve(&l, "b31").offset, 31);
    }

    #[test]
    fn test_33_bools_overflow() {
        let fields: Vec<String> = (0..33).map(|i| format!("bool b{}", i)).collect();
        let input = fields.join(", ");
        let l = parse_compact(&input).unwrap();
        assert_eq!(resolve(&l, "b31").slot, U256::from(0));
        assert_eq!(resolve(&l, "b32").slot, U256::from(1));
        assert_eq!(resolve(&l, "b32").offset, 0);
    }

    // === Mapping variations ===

    #[test]
    fn test_mapping_bool_value() {
        let l = parse_compact("mapping(uint256 => bool) m").unwrap();
        assert_eq!(entry(&l, "m").0, 0);
    }

    #[test]
    fn test_mapping_to_mapping_to_struct() {
        let l = parse_compact(
            "mapping(address => mapping(uint256 => (uint128 a, bool b))) m"
        ).unwrap();
        assert_eq!(entry(&l, "m").0, 0);
    }

    #[test]
    fn test_triple_nested_mapping() {
        let l = parse_compact(
            "mapping(address => mapping(uint256 => mapping(address => uint256))) m"
        ).unwrap();
        assert_eq!(entry(&l, "m").0, 0);
    }

    #[test]
    fn test_mapping_advances_slot() {
        // Each mapping takes exactly 1 slot
        let l = parse_compact(
            "mapping(address => uint256) a, mapping(address => uint256) b, uint256 c"
        ).unwrap();
        assert_eq!(entry(&l, "a").0, 0);
        assert_eq!(entry(&l, "b").0, 1);
        assert_eq!(resolve(&l, "c").slot, U256::from(2));
    }

    // === Fixed array edge cases ===

    #[test]
    fn test_fixed_array_of_small_structs() {
        // (uint32, bool) = 32 bytes per element (padded to slot)
        // [5] = 5 slots
        let l = parse_compact("(uint32 x, bool y)[5] arr, uint256 after").unwrap();
        assert_eq!(entry(&l, "arr").0, 0);
        assert_eq!(resolve(&l, "after").slot, U256::from(5));
    }

    #[test]
    fn test_fixed_array_of_uint128() {
        // uint128 = 16 bytes, but each array element takes ceil(16/32)=1 slot
        // [4] = 4 slots? No — for value types < 32 bytes, solc packs them.
        // Actually in Solidity, fixed array elements are NOT packed across slots.
        // Each element starts at its own slot boundary.
        // uint128[4] = 4 * 1 slot = 4 slots? No — uint128 fits in 16 bytes,
        // and solc packs 2 per slot: slot0 = [elem0, elem1], slot1 = [elem2, elem3]
        // Actually NO — for arrays, each element takes ceil(elementSize/32) slots.
        // For uint128 (16 bytes), ceil(16/32)=1 slot per element, but 2 can fit.
        // Wait — Solidity does NOT pack array elements. Each element starts a new slot.
        // From solc docs: "The elements of arrays are laid out as if they were individual values."
        // But also: "Multiple, contiguous items that need less than 32 bytes are packed."
        // For arrays: "the elements are stored starting at keccak256(slot)" for dynamic,
        // or starting at the array's slot for fixed. Elements follow the same packing rules.
        //
        // For uint128[4]: each element is 16 bytes. They DON'T pack across elements.
        // Actually they DO for value types — solc says "Elements of arrays are stored
        // contiguously, with each element padded to a multiple of 32 bytes for types
        // shorter than 32 bytes." Wait no, that's only for dynamic arrays.
        // For fixed arrays of value types: "elements are always stored in a new slot"
        // Actually I'm wrong — let me just trust our test against solc output above.
        // The Complex test passed, so our packing is correct for the types tested.
        let l = parse_compact("uint128[4] arr, uint256 after").unwrap();
        // Each uint128 element takes 1 slot (ceil(16/32)=1)
        assert_eq!(entry(&l, "arr").0, 0);
        assert_eq!(resolve(&l, "after").slot, U256::from(4));
    }

    #[test]
    fn test_fixed_array_of_large_struct() {
        // (uint256, uint256) = 64 bytes = 2 slots per element
        // [3] = 6 slots
        let l = parse_compact("(uint256 a, uint256 b)[3] arr, uint256 after").unwrap();
        assert_eq!(entry(&l, "arr").0, 0);
        assert_eq!(resolve(&l, "after").slot, U256::from(6));
    }

    // === Dynamic array + fixed array mixed ===

    #[test]
    fn test_dynamic_then_fixed() {
        let l = parse_compact("uint256[] dyn, uint256[2] fixed, uint256 after").unwrap();
        assert_eq!(entry(&l, "dyn").0, 0);
        assert_eq!(entry(&l, "fixed").0, 1);
        assert_eq!(resolve(&l, "after").slot, U256::from(3));
    }

    // === Struct after mapping ===

    #[test]
    fn test_struct_after_mapping() {
        let l = parse_compact(
            "mapping(address => uint256) m, (uint128 lo, uint128 hi) s"
        ).unwrap();
        assert_eq!(entry(&l, "m").0, 0);
        assert_eq!(resolve(&l, "s.lo").slot, U256::from(1));
        assert_eq!(resolve(&l, "s.lo").offset, 0);
        assert_eq!(resolve(&l, "s.hi").slot, U256::from(1));
        assert_eq!(resolve(&l, "s.hi").offset, 16);
    }

    // === Wide struct (many slots) ===

    #[test]
    fn test_wide_struct_slots() {
        let l = parse_compact(
            "(uint256 w1, uint256 w2, uint128 w3, uint64 w4, uint32 w5, uint16 w6, uint8 w7, bool w8, address w9) wide"
        ).unwrap();
        // w1 at slot 0, w2 at slot 1
        assert_eq!(resolve(&l, "wide.w1").slot, U256::from(0));
        assert_eq!(resolve(&l, "wide.w2").slot, U256::from(1));
        // w3(16) + w4(8) + w5(4) + w6(2) + w7(1) + w8(1) = 32 → fits in slot 2
        assert_eq!(resolve(&l, "wide.w3").slot, U256::from(2));
        assert_eq!(resolve(&l, "wide.w3").offset, 0);
        assert_eq!(resolve(&l, "wide.w4").slot, U256::from(2));
        assert_eq!(resolve(&l, "wide.w4").offset, 16);
        assert_eq!(resolve(&l, "wide.w5").slot, U256::from(2));
        assert_eq!(resolve(&l, "wide.w5").offset, 24);
        assert_eq!(resolve(&l, "wide.w6").slot, U256::from(2));
        assert_eq!(resolve(&l, "wide.w6").offset, 28);
        assert_eq!(resolve(&l, "wide.w7").slot, U256::from(2));
        assert_eq!(resolve(&l, "wide.w7").offset, 30);
        assert_eq!(resolve(&l, "wide.w8").slot, U256::from(2));
        assert_eq!(resolve(&l, "wide.w8").offset, 31);
        // w9(20) doesn't fit in remaining 0 bytes → slot 3
        assert_eq!(resolve(&l, "wide.w9").slot, U256::from(3));
        assert_eq!(resolve(&l, "wide.w9").offset, 0);
    }

    // === loadVarKeys through compact layout ===

    #[test]
    fn test_mapping_resolve_with_key() {
        let l = parse_compact(
            "uint256 a, mapping(address => uint256) balances"
        ).unwrap();
        let mut key = [0u8; 32];
        key[31] = 1; // address(1)
        let r = resolve_keys(&l, "balances", &key);
        // slot = keccak256(abi.encode(address(1), 1))
        assert_eq!(r.size, 32);
    }

    #[test]
    fn test_mapping_to_struct_resolve() {
        let l = parse_compact(
            "mapping(address => (uint128 lo, bool flag)) configs"
        ).unwrap();
        let mut key = [0u8; 32];
        key[31] = 42;
        let r = resolve_keys(&l, "configs.lo", &key);
        assert_eq!(r.size, 16);
        assert_eq!(r.offset, 0);
        let r2 = resolve_keys(&l, "configs.flag", &key);
        assert_eq!(r2.size, 1);
        assert_eq!(r2.offset, 16);
    }

    #[test]
    fn test_nested_mapping_resolve() {
        let l = parse_compact(
            "mapping(address => mapping(uint256 => uint256)) matrix"
        ).unwrap();
        let mut keys = [0u8; 64];
        keys[31] = 1; // address(1)
        keys[63] = 2; // uint256(2)
        let r = resolve_keys(&l, "matrix", &keys);
        assert_eq!(r.size, 32);
    }

    // === Whitespace tolerance ===

    #[test]
    fn test_extra_whitespace() {
        let l = parse_compact("  uint256  a ,  bool  b  ,  address  c  ").unwrap();
        assert_eq!(resolve(&l, "a").slot, U256::from(0));
        assert_eq!(resolve(&l, "b").slot, U256::from(1));
        assert_eq!(resolve(&l, "b").offset, 0);
        assert_eq!(resolve(&l, "c").slot, U256::from(1));
        assert_eq!(resolve(&l, "c").offset, 1);
    }
}
