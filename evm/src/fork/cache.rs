//! RPC cache types for fork persistence.
//!
//! The on-disk format mirrors the one hevm/echidna write to corpus directories
//! so the same `rpc-cache-<block>.json` file is interchangeable between the
//! two tools (and so users can check it in to share fixed-block forks).

use alloy_primitives::{Address, Bytes, B256, U256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::HashMap;

/// Cached contract data — matches hevm's `RPCContract`.
///
/// Serialisation is byte-for-byte compatible with echidna/hevm:
/// - `code`: lowercase hex with `0x` prefix
/// - `nonce` (W64): short hex `"0x..."` (no zero padding)
/// - `balance` (W256): 64-char zero-padded hex `"0x000...0"`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAccount {
    pub code: HexBytes,
    #[serde(with = "u256_short_hex")]
    pub nonce: U256,
    #[serde(with = "u256_padded_hex")]
    pub balance: U256,
}

/// Echidna/hevm storage entry: a JSON pair `["(addr,slot)", value]`.
/// Stored as a `Vec` so order in the file is stable and lookups go through a
/// `HashMap` we build on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedSlot {
    pub address: Address,
    pub slot: U256,
    pub value: U256,
}

/// Echidna-compatible RPC cache: `{ contracts, slots, blocks }`.
///
/// `contracts` is `[[addr, {code, nonce, balance}], ...]`,
/// `slots` is `[["(addr,slot)", value], ...]` (stringified key, hex value).
/// `blocks` is unused for our purposes today and kept as an empty object.
///
/// Output is byte-for-byte compatible with echidna's `rpc-cache-<block>.json`
/// (EIP-55 checksum addresses, padded W256 balances/values, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RpcCacheData {
    #[serde(serialize_with = "ser_contracts", deserialize_with = "de_contracts")]
    pub contracts: HashMap<Address, CachedAccount>,
    #[serde(serialize_with = "ser_slots", deserialize_with = "de_slots")]
    pub slots: Vec<CachedSlot>,
    #[serde(default)]
    pub blocks: serde_json::Map<String, serde_json::Value>,
}

impl RpcCacheData {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Hex-string newtype that round-trips to `0x..`-prefixed JSON, matching
/// the encoding hevm uses for `code` fields.
#[derive(Debug, Clone)]
pub struct HexBytes(pub Bytes);

impl From<Bytes> for HexBytes {
    fn from(b: Bytes) -> Self {
        Self(b)
    }
}

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(&self.0)))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        Ok(HexBytes(Bytes::from(bytes)))
    }
}

/// Format an address with EIP-55 mixed-case checksum (matches echidna).
fn checksum_addr(addr: &Address) -> String {
    addr.to_checksum(None)
}

fn ser_contracts<S: Serializer>(
    map: &HashMap<Address, CachedAccount>,
    s: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    // Stable order so on-disk diffs are sane between runs.
    let mut entries: Vec<(&Address, &CachedAccount)> = map.iter().collect();
    entries.sort_by_key(|(a, _)| **a);
    let mut seq = s.serialize_seq(Some(entries.len()))?;
    for (addr, info) in entries {
        // Echidna writes addresses with EIP-55 checksum casing.
        seq.serialize_element(&(checksum_addr(addr), info))?;
    }
    seq.end()
}

fn de_contracts<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<HashMap<Address, CachedAccount>, D::Error> {
    let v: Vec<(Address, CachedAccount)> = Vec::deserialize(d)?;
    Ok(v.into_iter().collect())
}

fn ser_slots<S: Serializer>(slots: &[CachedSlot], s: S) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeSeq;
    let mut seq = s.serialize_seq(Some(slots.len()))?;
    for sl in slots {
        // Echidna key: "(0xCHECKSUM_ADDR,0x<short-hex-slot>)", value: padded W256.
        let key = format!("({},{:#x})", checksum_addr(&sl.address), sl.slot);
        let value = format!("{:#066x}", sl.value);
        seq.serialize_element(&(key, value))?;
    }
    seq.end()
}

fn de_slots<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<CachedSlot>, D::Error> {
    let raw: Vec<(String, String)> = Vec::deserialize(d)?;
    let mut out = Vec::with_capacity(raw.len());
    for (k, v) in raw {
        let inside = k
            .trim()
            .trim_start_matches('(')
            .trim_end_matches(')');
        let (addr_str, slot_str) = inside
            .split_once(',')
            .ok_or_else(|| serde::de::Error::custom(format!("bad slot key {:?}", k)))?;
        let addr_str = addr_str.trim();
        let slot_str = slot_str.trim();
        let address: Address = addr_str
            .parse()
            .map_err(|e| serde::de::Error::custom(format!("addr {:?}: {}", addr_str, e)))?;
        let slot = parse_u256_hex(slot_str)
            .map_err(|e| serde::de::Error::custom(format!("slot {:?}: {}", slot_str, e)))?;
        let value = parse_u256_hex(&v)
            .map_err(|e| serde::de::Error::custom(format!("value {:?}: {}", v, e)))?;
        out.push(CachedSlot { address, slot, value });
    }
    Ok(out)
}

fn parse_u256_hex(s: &str) -> Result<U256, String> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    U256::from_str_radix(t, 16).map_err(|e| e.to_string())
}

/// Filename hevm/echidna use for a per-block cache.
pub fn cache_file_name(block: u64) -> String {
    format!("rpc-cache-{}.json", block)
}

/// 32-byte zero-padded hex (`"0x" + 64 chars`), matching hevm's `ToJSON W256`.
pub mod u256_padded_hex {
    use alloy_primitives::U256;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:#066x}", v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let s = String::deserialize(d)?;
        let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        U256::from_str_radix(t, 16).map_err(serde::de::Error::custom)
    }
}

/// Short hex (`"0x..."` no zero padding), matching hevm's `ToJSON W64` /
/// `Show W256`.
pub mod u256_short_hex {
    use alloy_primitives::U256;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("{:#x}", v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let s = String::deserialize(d)?;
        let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
        U256::from_str_radix(t, 16).map_err(serde::de::Error::custom)
    }
}

/// `Bytes` is referenced from re-exports.
#[allow(dead_code)]
fn _ensure_bytes_used(_: B256) {}
