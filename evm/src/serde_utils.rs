use alloy::dyn_abi::DynSolValue;
use alloy_primitives::{Address, FixedBytes, I256, U256};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum SerializableDynSolValue {
    Bool(bool),
    Int(I256, usize),
    Uint(U256, usize),
    FixedBytes(FixedBytes<32>, usize),
    Address(Address),
    Function(i32),
    Bytes(Vec<u8>), // Changed to Vec<u8> to match DynSolValue payload
    String(String),
    Array(Vec<SerializableDynSolValue>),
    FixedArray(Vec<SerializableDynSolValue>),
    Tuple(Vec<SerializableDynSolValue>),
}

impl From<&DynSolValue> for SerializableDynSolValue {
    fn from(value: &DynSolValue) -> Self {
        match value {
            DynSolValue::Bool(b) => SerializableDynSolValue::Bool(*b),
            DynSolValue::Int(i, size) => SerializableDynSolValue::Int(*i, *size),
            DynSolValue::Uint(u, size) => SerializableDynSolValue::Uint(*u, *size),
            DynSolValue::FixedBytes(w, size) => SerializableDynSolValue::FixedBytes(*w, *size),
            DynSolValue::Address(a) => SerializableDynSolValue::Address(*a),
            DynSolValue::Bytes(b) => SerializableDynSolValue::Bytes(b.clone()),
            DynSolValue::String(s) => SerializableDynSolValue::String(s.clone()),
            DynSolValue::Array(arr) => {
                SerializableDynSolValue::Array(arr.iter().map(|e| e.into()).collect())
            }
            DynSolValue::FixedArray(arr) => {
                SerializableDynSolValue::FixedArray(arr.iter().map(|e| e.into()).collect())
            }
            DynSolValue::Tuple(arr) => {
                SerializableDynSolValue::Tuple(arr.iter().map(|e| e.into()).collect())
            }
            _ => SerializableDynSolValue::Bool(false),
        }
    }
}

impl From<SerializableDynSolValue> for DynSolValue {
    fn from(value: SerializableDynSolValue) -> Self {
        match value {
            SerializableDynSolValue::Bool(b) => DynSolValue::Bool(b),
            SerializableDynSolValue::Int(i, size) => DynSolValue::Int(i, size),
            SerializableDynSolValue::Uint(u, size) => DynSolValue::Uint(u, size),
            SerializableDynSolValue::FixedBytes(w, size) => DynSolValue::FixedBytes(w, size),
            SerializableDynSolValue::Address(a) => DynSolValue::Address(a),
            SerializableDynSolValue::Bytes(b) => DynSolValue::Bytes(b),
            SerializableDynSolValue::String(s) => DynSolValue::String(s),
            SerializableDynSolValue::Array(arr) => {
                DynSolValue::Array(arr.into_iter().map(|e| e.into()).collect())
            }
            SerializableDynSolValue::FixedArray(arr) => {
                DynSolValue::FixedArray(arr.into_iter().map(|e| e.into()).collect())
            }
            SerializableDynSolValue::Tuple(arr) => {
                DynSolValue::Tuple(arr.into_iter().map(|e| e.into()).collect())
            }
            _ => DynSolValue::Bool(false),
        }
    }
}

pub mod vec_dyn_sol_value {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &Vec<DynSolValue>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable: Vec<SerializableDynSolValue> = value.iter().map(|e| e.into()).collect();
        serializable.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<DynSolValue>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let serializable: Vec<SerializableDynSolValue> = Vec::deserialize(deserializer)?;
        Ok(serializable.into_iter().map(|e| e.into()).collect())
    }
}
