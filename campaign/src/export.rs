//! Export corpus to Echidna-compatible JSON format
//!
//! Converts Recon's native corpus format to Echidna's JSON format.
//! Key differences:
//! - Enum tagging: Rust `{"SolCall": {...}}` → Echidna `{"tag": "SolCall", "contents": [...]}`
//! - Delay encoding: Rust `[u64, u64]` → Echidna `["0x{64-char hex}", "0x{64-char hex}"]`
//! - ABI values: Rust `{"Uint": [val, bits]}` → Echidna `{"tag": "AbiUInt", "contents": [bits, "decimal"]}`

use std::path::Path;

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::I256;
use evm::types::Tx;
use serde_json::{json, Value};
use tracing::{info, warn};

/// Export a corpus directory to Echidna-compatible format.
///
/// Copies the directory structure, loads each `.txt`/`.json` file as `Vec<Tx>`,
/// converts to Echidna JSON format, and writes to the export directory.
pub fn export_corpus_to_echidna(corpus_dir: &Path, export_dir: &Path) -> anyhow::Result<usize> {
    let mut file_count = 0;

    // Walk subdirectories: coverage/, reproducers/, reproducers-unshrunk/
    for subdir_name in &["coverage", "reproducers", "reproducers-unshrunk"] {
        let src_dir = corpus_dir.join(subdir_name);
        if !src_dir.exists() {
            continue;
        }

        let dst_dir = export_dir.join(subdir_name);
        std::fs::create_dir_all(&dst_dir)?;

        for entry in std::fs::read_dir(&src_dir)? {
            let entry = entry?;
            let path = entry.path();

            let is_corpus_file = path
                .extension()
                .map_or(false, |ext| ext == "txt" || ext == "json");

            if !is_corpus_file {
                continue;
            }

            let content = std::fs::read_to_string(&path)?;
            match serde_json::from_str::<Vec<Tx>>(&content) {
                Ok(txs) => {
                    let echidna_json: Vec<Value> =
                        txs.iter().map(tx_to_echidna_json).collect();
                    let output = serde_json::to_string(&echidna_json)?;

                    let filename = path.file_name().unwrap();
                    std::fs::write(dst_dir.join(filename), output)?;
                    file_count += 1;
                }
                Err(e) => {
                    warn!("Failed to parse corpus file {:?}: {}", path, e);
                }
            }
        }
    }

    // Also handle files directly in the corpus_dir (not in subdirectories)
    for entry in std::fs::read_dir(corpus_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        let is_corpus_file = path
            .extension()
            .map_or(false, |ext| ext == "txt" || ext == "json");

        if !is_corpus_file {
            continue;
        }

        let content = std::fs::read_to_string(&path)?;
        match serde_json::from_str::<Vec<Tx>>(&content) {
            Ok(txs) => {
                let echidna_json: Vec<Value> =
                    txs.iter().map(tx_to_echidna_json).collect();
                let output = serde_json::to_string(&echidna_json)?;

                let filename = path.file_name().unwrap();
                std::fs::write(export_dir.join(filename), output)?;
                file_count += 1;
            }
            Err(e) => {
                warn!("Failed to parse corpus file {:?}: {}", path, e);
            }
        }
    }

    info!("Exported {} corpus files to {:?}", file_count, export_dir);
    Ok(file_count)
}

/// Convert a single Tx to Echidna's JSON format.
fn tx_to_echidna_json(tx: &Tx) -> Value {
    let call = match &tx.call {
        evm::types::TxCall::SolCall { name, args } => {
            let echidna_args: Vec<Value> = args.iter().map(dyn_sol_value_to_echidna).collect();
            json!({
                "tag": "SolCall",
                "contents": [name, echidna_args]
            })
        }
        evm::types::TxCall::SolCreate(bytecode) => {
            json!({
                "tag": "SolCreate",
                "contents": format!("0x{}", hex::encode(bytecode.as_ref()))
            })
        }
        evm::types::TxCall::SolCalldata(data) => {
            json!({
                "tag": "SolCalldata",
                "contents": format!("0x{}", hex::encode(data.as_ref()))
            })
        }
        evm::types::TxCall::NoCall => {
            json!({
                "tag": "NoCall",
                "contents": []
            })
        }
    };

    // Delays: 256-bit zero-padded hex strings
    let delay_time = format!("0x{:064x}", tx.delay.0);
    let delay_block = format!("0x{:064x}", tx.delay.1);

    // Value and gasprice: 256-bit zero-padded hex strings
    let value = format!("0x{:0>64}", format!("{:x}", tx.value));
    let gasprice = format!("0x{:0>64}", format!("{:x}", tx.gasprice));

    json!({
        "call": call,
        "src": format!("{}", tx.src),
        "dst": format!("{}", tx.dst),
        "gas": tx.gas,
        "gasprice": gasprice,
        "value": value,
        "delay": [delay_time, delay_block]
    })
}

/// Convert a DynSolValue to Echidna's ABI JSON format.
fn dyn_sol_value_to_echidna(val: &DynSolValue) -> Value {
    match val {
        DynSolValue::Uint(v, bits) => {
            json!({
                "tag": "AbiUInt",
                "contents": [bits, v.to_string()]
            })
        }
        DynSolValue::Int(v, bits) => {
            // Convert I256 to signed decimal string
            let decimal = i256_to_decimal_string(*v);
            json!({
                "tag": "AbiInt",
                "contents": [bits, decimal]
            })
        }
        DynSolValue::Address(addr) => {
            json!({
                "tag": "AbiAddress",
                "contents": format!("{}", addr)
            })
        }
        DynSolValue::Bool(b) => {
            json!({
                "tag": "AbiBool",
                "contents": b
            })
        }
        DynSolValue::Bytes(b) => {
            json!({
                "tag": "AbiBytesDynamic",
                "contents": bytes_to_haskell_show(b)
            })
        }
        DynSolValue::FixedBytes(word, size) => {
            let bytes = &word.as_slice()[..*size];
            json!({
                "tag": "AbiBytes",
                "contents": [size, bytes_to_haskell_show(bytes)]
            })
        }
        DynSolValue::String(s) => {
            json!({
                "tag": "AbiString",
                "contents": s
            })
        }
        DynSolValue::Tuple(arr) => {
            let contents: Vec<Value> = arr.iter().map(dyn_sol_value_to_echidna).collect();
            json!({
                "tag": "AbiTuple",
                "contents": contents
            })
        }
        DynSolValue::Array(arr) => {
            let contents: Vec<Value> = arr.iter().map(dyn_sol_value_to_echidna).collect();
            json!({
                "tag": "AbiArrayDynamic",
                "contents": contents
            })
        }
        DynSolValue::FixedArray(arr) => {
            let contents: Vec<Value> = arr.iter().map(dyn_sol_value_to_echidna).collect();
            // Echidna FixedArray: {"tag": "AbiArray", "contents": [size, type_tag, [items...]]}
            // We approximate the type tag from the first element
            let size = arr.len();
            let type_tag = if let Some(first) = arr.first() {
                abi_type_tag(first)
            } else {
                json!("AbiUInt")
            };
            json!({
                "tag": "AbiArray",
                "contents": [size, type_tag, contents]
            })
        }
        // Fallback for any unhandled types
        _ => {
            json!({
                "tag": "AbiBool",
                "contents": false
            })
        }
    }
}

/// Get a type tag string for Echidna's AbiArray encoding.
fn abi_type_tag(val: &DynSolValue) -> Value {
    match val {
        DynSolValue::Uint(_, _) => json!("AbiUInt"),
        DynSolValue::Int(_, _) => json!("AbiInt"),
        DynSolValue::Address(_) => json!("AbiAddress"),
        DynSolValue::Bool(_) => json!("AbiBool"),
        DynSolValue::Bytes(_) => json!("AbiBytesDynamic"),
        DynSolValue::FixedBytes(_, _) => json!("AbiBytes"),
        DynSolValue::String(_) => json!("AbiString"),
        DynSolValue::Tuple(_) => json!("AbiTuple"),
        _ => json!("AbiBool"),
    }
}

/// Convert I256 to a signed decimal string.
fn i256_to_decimal_string(v: I256) -> String {
    if v.is_negative() {
        // I256 doesn't implement Display with sign in alloy, so handle manually
        let abs = v.wrapping_neg();
        format!("-{}", abs)
    } else {
        format!("{}", v)
    }
}

/// Encode bytes in Haskell's `show` format for ByteString.
///
/// Echidna uses Haskell's `show` for ByteString which produces escaped ASCII
/// control character mnemonics like `\NUL`, `\SOH`, `\STX`, `\ETB`, etc.
/// The result is wrapped in quotes: `"\"...\""`
fn bytes_to_haskell_show(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 4 + 2);
    result.push('"');

    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            // Printable ASCII (except backslash and double-quote)
            0x20..=0x7E if byte != b'\\' && byte != b'"' => {
                // If the previous character was a numeric escape and this is a digit,
                // we need to insert \& to break the escape sequence
                let needs_break = i > 0 && byte.is_ascii_digit() && needs_escape_break(&result);
                if needs_break {
                    result.push_str("\\&");
                }
                result.push(byte as char);
            }
            // Special escape sequences that Haskell uses
            0x00 => result.push_str("\\NUL"),
            0x01 => result.push_str("\\SOH"),
            0x02 => result.push_str("\\STX"),
            0x03 => result.push_str("\\ETX"),
            0x04 => result.push_str("\\EOT"),
            0x05 => result.push_str("\\ENQ"),
            0x06 => result.push_str("\\ACK"),
            0x07 => result.push_str("\\a"),
            0x08 => result.push_str("\\b"),
            0x09 => result.push_str("\\t"),
            0x0A => result.push_str("\\n"),
            0x0B => result.push_str("\\v"),
            0x0C => result.push_str("\\f"),
            0x0D => result.push_str("\\r"),
            0x0E => result.push_str("\\SO"),
            0x0F => result.push_str("\\SI"),
            0x10 => result.push_str("\\DLE"),
            0x11 => result.push_str("\\DC1"),
            0x12 => result.push_str("\\DC2"),
            0x13 => result.push_str("\\DC3"),
            0x14 => result.push_str("\\DC4"),
            0x15 => result.push_str("\\NAK"),
            0x16 => result.push_str("\\SYN"),
            0x17 => result.push_str("\\ETB"),
            0x18 => result.push_str("\\CAN"),
            0x19 => result.push_str("\\EM"),
            0x1A => result.push_str("\\SUB"),
            0x1B => result.push_str("\\ESC"),
            0x1C => result.push_str("\\FS"),
            0x1D => result.push_str("\\GS"),
            0x1E => result.push_str("\\RS"),
            0x1F => result.push_str("\\US"),
            0x5C => result.push_str("\\\\"), // backslash
            0x22 => result.push_str("\\\""), // double-quote
            0x7F => result.push_str("\\DEL"),
            // High bytes (128-255): use decimal escape
            _ => {
                result.push('\\');
                result.push_str(&byte.to_string());
            }
        }
    }

    result.push('"');
    result
}

/// Check if the current result string ends with a numeric escape sequence,
/// meaning we need to insert `\&` before appending a digit.
fn needs_escape_break(s: &str) -> bool {
    // Check if the string ends with a decimal escape like \123
    if let Some(pos) = s.rfind('\\') {
        let after = &s[pos + 1..];
        // It's a numeric escape if all chars after \ are digits
        !after.is_empty() && after.chars().all(|c| c.is_ascii_digit())
    } else {
        false
    }
}
