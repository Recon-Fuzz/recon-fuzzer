//! Transaction generation
//!

use abi::r#gen::{gen_abi_call_m, gen_abi_value_with_dict};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_json_abi::Function;
use alloy_primitives::{Address, U256};
use config::transaction::TxConf;
use parking_lot::RwLock;
use rand::prelude::*;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::world::World;
use abi::types::GenDict;
use analysis::slither::ResolvedRelations;
use evm::{foundry::CompiledContract, types::{Tx, TxCall}};

/// Type alias for argument clamps: (function_name, param_idx) -> clamped_value_string
pub type ArgClamps = Arc<RwLock<HashMap<(String, usize), String>>>;

/// Type alias for fuzz templates storage
pub type FuzzTemplates = Arc<RwLock<Vec<FuzzSequenceTemplate>>>;

/// A single argument in a fuzz template - either concrete or wildcard
#[derive(Debug, Clone)]
pub enum TemplateArg {
    /// Wildcard `?` - will be fuzzed
    Wildcard,
    /// Concrete value as string (will be parsed based on type)
    Concrete(String),
}

/// A single transaction template in a fuzz sequence
#[derive(Debug, Clone)]
pub struct TxTemplate {
    /// Function name (without params)
    pub function: String,
    /// Arguments - mix of wildcards and concrete values
    pub args: Vec<TemplateArg>,
    /// Optional sender address
    pub sender: Option<String>,
    /// Optional ETH value
    pub value: Option<String>,
}

/// A sequence of transaction templates to prioritize
#[derive(Debug, Clone)]
pub struct FuzzSequenceTemplate {
    /// Transaction templates in order
    pub transactions: Vec<TxTemplate>,
    /// Priority weight (higher = more likely to be selected)
    pub priority: usize,
}

/// Parse a fuzz template string like "f(1,?,?) ; g(?,2,5)"
/// Returns a list of transaction templates
pub fn parse_fuzz_template(input: &str) -> Result<Vec<TxTemplate>, String> {
    let mut templates = Vec::new();

    // Split by ; to get individual calls
    for part in input.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        let template = parse_single_template(part)?;
        templates.push(template);
    }

    if templates.is_empty() {
        return Err("No valid templates found".to_string());
    }

    Ok(templates)
}

/// Parse a single template like "f(1,?,?)" or "f(1, ?, ?)"
fn parse_single_template(input: &str) -> Result<TxTemplate, String> {
    let input = input.trim();

    // Find the function name and args
    let open_paren = input
        .find('(')
        .ok_or_else(|| format!("Missing '(' in template: {}", input))?;
    let close_paren = input
        .rfind(')')
        .ok_or_else(|| format!("Missing ')' in template: {}", input))?;

    if close_paren <= open_paren {
        return Err(format!("Invalid parentheses in template: {}", input));
    }

    let function = input[..open_paren].trim().to_string();
    if function.is_empty() {
        return Err("Empty function name".to_string());
    }

    let args_str = &input[open_paren + 1..close_paren];
    let args = parse_template_args(args_str)?;

    Ok(TxTemplate {
        function,
        args,
        sender: None,
        value: None,
    })
}

/// Parse template arguments, handling nested structures
fn parse_template_args(input: &str) -> Result<Vec<TemplateArg>, String> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0; // Track nested brackets/parens
    let mut in_string = false;
    let mut escape_next = false;

    for ch in input.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' => {
                escape_next = true;
                current.push(ch);
            }
            '"' | '\'' => {
                in_string = !in_string;
                current.push(ch);
            }
            '[' | '(' | '{' if !in_string => {
                depth += 1;
                current.push(ch);
            }
            ']' | ')' | '}' if !in_string => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 && !in_string => {
                // End of argument
                let arg = parse_single_arg(current.trim())?;
                args.push(arg);
                current = String::new();
            }
            _ => {
                current.push(ch);
            }
        }
    }

    // Don't forget the last argument
    if !current.trim().is_empty() {
        let arg = parse_single_arg(current.trim())?;
        args.push(arg);
    }

    Ok(args)
}

/// Parse a single argument - either "?" for wildcard or a concrete value
fn parse_single_arg(input: &str) -> Result<TemplateArg, String> {
    let input = input.trim();
    if input == "?" {
        Ok(TemplateArg::Wildcard)
    } else {
        Ok(TemplateArg::Concrete(input.to_string()))
    }
}

/// Generate a transaction from a template, filling wildcards with fuzzed values
pub fn gen_tx_from_template<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    template: &TxTemplate,
) -> Option<Tx> {
    // Find the function in the contract ABI
    let func = contract
        .abi
        .functions()
        .find(|f| f.name == template.function)?;

    let selector = func.selector();
    let param_types = contract.get_param_types(&selector);

    // Check argument count matches
    if template.args.len() != param_types.len() {
        tracing::warn!(
            "Template arg count mismatch for {}: expected {}, got {}",
            template.function,
            param_types.len(),
            template.args.len()
        );
        return None;
    }

    // Generate arguments - fuzz wildcards, parse concrete values
    let mut args = Vec::with_capacity(template.args.len());
    for (idx, (template_arg, param_type)) in
        template.args.iter().zip(param_types.iter()).enumerate()
    {
        let arg = match template_arg {
            TemplateArg::Wildcard => {
                // Generate a fuzzed value using the dictionary
                gen_abi_value_with_dict(rng, dict, param_type, &template.function)
            }
            TemplateArg::Concrete(value) => {
                // Parse the concrete value
                match parse_clamped_value(value, param_type) {
                    Some(v) => v,
                    None => {
                        tracing::warn!(
                            "Failed to parse template arg {} for {}[{}]: '{}'",
                            idx,
                            template.function,
                            idx,
                            value
                        );
                        // Fall back to fuzzed value
                        gen_abi_value_with_dict(rng, dict, param_type, &template.function)
                    }
                }
            }
        };
        args.push(arg);
    }

    // Determine sender
    let sender = if let Some(ref sender_str) = template.sender {
        sender_str.parse().unwrap_or_else(|_| {
            world
                .random_sender(rng)
                .unwrap_or_else(|| Address::from_word(U256::from(0x10000u64).into()))
        })
    } else {
        world
            .random_sender(rng)
            .unwrap_or_else(|| Address::from_word(U256::from(0x10000u64).into()))
    };

    // Determine value
    let value = if let Some(ref value_str) = template.value {
        if value_str.starts_with("0x") {
            U256::from_str_radix(&value_str[2..], 16).unwrap_or(U256::ZERO)
        } else {
            U256::from_str_radix(value_str, 10).unwrap_or(U256::ZERO)
        }
    } else {
        // Generate value for payable functions
        gen_value(
            rng,
            tx_conf.max_value,
            &mut dict.dict_values,
            &world.payable_sigs,
            &selector,
        )
    };

    // Generate delay
    let delay = gen_delay(
        rng,
        tx_conf.max_time_delay,
        tx_conf.max_block_delay,
        &mut dict.dict_values,
    );

    Some(Tx {
        call: TxCall::SolCall {
            name: template.function.clone(),
            args,
        },
        src: sender,
        dst: contract_addr,
        gas: tx_conf.tx_gas,
        gasprice: tx_conf.max_gasprice,
        value,
        delay,
    })
}

/// Generate a full sequence from a template sequence
pub fn gen_sequence_from_template<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    template: &FuzzSequenceTemplate,
) -> Vec<Tx> {
    template
        .transactions
        .iter()
        .filter_map(|tx_template| {
            gen_tx_from_template(
                rng,
                dict,
                world,
                tx_conf,
                contract,
                contract_addr,
                tx_template,
            )
        })
        .collect()
}

/// Apply argument clamps to a transaction
/// If any clamps exist for the function's arguments, replace them with the clamped values
pub fn apply_clamps(tx: &mut Tx, clamps: &ArgClamps, param_types: &[DynSolType]) {
    if let TxCall::SolCall {
        ref name,
        ref mut args,
    } = tx.call
    {
        let clamps_read = clamps.read();
        if clamps_read.is_empty() {
            return;
        }

        for (idx, arg) in args.iter_mut().enumerate() {
            if let Some(clamped_value) = clamps_read.get(&(name.clone(), idx)) {
                // Try to parse the clamped value according to the parameter type
                if let Some(param_type) = param_types.get(idx) {
                    if let Some(parsed) = parse_clamped_value(clamped_value, param_type) {
                        tracing::debug!(
                            "Applied clamp for {}[{}]: {} -> {:?}",
                            name,
                            idx,
                            clamped_value,
                            parsed
                        );
                        *arg = parsed;
                    } else {
                        tracing::warn!(
                            "Failed to parse clamped value '{}' for {}[{}] as {:?}",
                            clamped_value,
                            name,
                            idx,
                            param_type
                        );
                    }
                }
            }
        }
    }
}

/// Parse a clamped value string into a DynSolValue
fn parse_clamped_value(value: &str, ty: &DynSolType) -> Option<DynSolValue> {
    match ty {
        DynSolType::Uint(bits) => {
            let n = if value.starts_with("0x") {
                U256::from_str_radix(&value[2..], 16).ok()?
            } else {
                U256::from_str_radix(value, 10).ok()?
            };
            Some(DynSolValue::Uint(n, *bits))
        }
        DynSolType::Int(bits) => {
            let n = alloy_primitives::I256::from_dec_str(value).ok()?;
            Some(DynSolValue::Int(n, *bits))
        }
        DynSolType::Address => {
            let addr: Address = value.parse().ok()?;
            Some(DynSolValue::Address(addr))
        }
        DynSolType::Bool => {
            let b = match value.to_lowercase().as_str() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return None,
            };
            Some(DynSolValue::Bool(b))
        }
        DynSolType::Bytes => {
            let bytes = hex::decode(value.trim_start_matches("0x")).ok()?;
            Some(DynSolValue::Bytes(bytes.into()))
        }
        DynSolType::String => Some(DynSolValue::String(value.to_string())),
        DynSolType::FixedBytes(len) => {
            let bytes = hex::decode(value.trim_start_matches("0x")).ok()?;
            if bytes.len() != *len {
                return None;
            }
            let mut padded = [0u8; 32];
            padded[..bytes.len()].copy_from_slice(&bytes);
            Some(DynSolValue::FixedBytes(
                alloy_primitives::FixedBytes::<32>::from(padded),
                *len,
            ))
        }
        // For complex types (arrays, tuples), try JSON parsing
        DynSolType::Array(_) | DynSolType::FixedArray(_, _) | DynSolType::Tuple(_) => {
            // Attempt to parse as JSON and decode
            let json_val: serde_json::Value = serde_json::from_str(value).ok()?;
            parse_json_to_sol_value(&json_val, ty)
        }
        // Function type not commonly clamped
        DynSolType::Function => None,
    }
}

/// Parse a JSON value into a DynSolValue (for complex types)
fn parse_json_to_sol_value(json: &serde_json::Value, ty: &DynSolType) -> Option<DynSolValue> {
    match ty {
        DynSolType::Array(inner) => {
            let arr = json.as_array()?;
            let values: Option<Vec<_>> = arr
                .iter()
                .map(|v| parse_json_to_sol_value(v, inner))
                .collect();
            Some(DynSolValue::Array(values?))
        }
        DynSolType::FixedArray(inner, len) => {
            let arr = json.as_array()?;
            if arr.len() != *len {
                return None;
            }
            let values: Option<Vec<_>> = arr
                .iter()
                .map(|v| parse_json_to_sol_value(v, inner))
                .collect();
            Some(DynSolValue::FixedArray(values?))
        }
        DynSolType::Tuple(types) => {
            let arr = json.as_array()?;
            if arr.len() != types.len() {
                return None;
            }
            let values: Option<Vec<_>> = arr
                .iter()
                .zip(types.iter())
                .map(|(v, t)| parse_json_to_sol_value(v, t))
                .collect();
            Some(DynSolValue::Tuple(values?))
        }
        DynSolType::Uint(bits) => {
            let n = if let Some(s) = json.as_str() {
                if s.starts_with("0x") {
                    U256::from_str_radix(&s[2..], 16).ok()?
                } else {
                    U256::from_str_radix(s, 10).ok()?
                }
            } else if let Some(n) = json.as_u64() {
                U256::from(n)
            } else {
                return None;
            };
            Some(DynSolValue::Uint(n, *bits))
        }
        DynSolType::Int(bits) => {
            let n = if let Some(s) = json.as_str() {
                alloy_primitives::I256::from_dec_str(s).ok()?
            } else if let Some(n) = json.as_i64() {
                alloy_primitives::I256::try_from(n).ok()?
            } else {
                return None;
            };
            Some(DynSolValue::Int(n, *bits))
        }
        DynSolType::Address => {
            let s = json.as_str()?;
            let addr: Address = s.parse().ok()?;
            Some(DynSolValue::Address(addr))
        }
        DynSolType::Bool => Some(DynSolValue::Bool(json.as_bool()?)),
        DynSolType::String => Some(DynSolValue::String(json.as_str()?.to_string())),
        _ => None,
    }
}

/// Generate a random transaction with smart filtering
///
/// This is the preferred method when slither info is available.
/// For view/pure functions, only includes them if they have assertions.
/// This avoids wasting fuzzing effort on view functions that can't fail.
pub fn gen_tx_smart<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    mutable_only: bool,
    assert_functions: &HashSet<String>,
) -> Option<Tx> {
    let fuzzable = contract.fuzzable_functions_smart(mutable_only, assert_functions);
    if fuzzable.is_empty() {
        return None;
    }

    let sender = world
        .random_sender(rng)
        .unwrap_or_else(|| Address::from_word(U256::from(0x10000u64).into()));

    let func = fuzzable[rng.gen_range(0..fuzzable.len())];

    let selector = func.selector();
    let param_types = contract.get_param_types(&selector);

    let (name, args) = gen_abi_call_m(rng, dict, &func.name, param_types);

    let value = gen_value(
        rng,
        tx_conf.max_value,
        &mut dict.dict_values,
        &world.payable_sigs,
        &selector,
    );

    let delay = gen_delay(
        rng,
        tx_conf.max_time_delay,
        tx_conf.max_block_delay,
        &mut dict.dict_values,
    );

    Some(Tx {
        call: TxCall::SolCall { name, args },
        src: sender,
        dst: contract_addr,
        gas: tx_conf.tx_gas,
        gasprice: tx_conf.max_gasprice,
        value,
        delay,
    })
}

/// Generate a random transaction
///
/// Key for multi-step bug finding: uses gen_abi_call_m which checks
/// the wholeCalls dictionary first. This allows the fuzzer to replay
/// successful calls like initSequence(42) with high probability.
pub fn gen_tx<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    mutable_only: bool,
) -> Option<Tx> {
    let fuzzable = contract.fuzzable_functions(mutable_only);
    if fuzzable.is_empty() {
        return None;
    }

    let sender = world
        .random_sender(rng)
        .unwrap_or_else(|| Address::from_word(U256::from(0x10000u64).into()));

    let func = fuzzable[rng.gen_range(0..fuzzable.len())];

    let selector = func.selector();
    let param_types = contract.get_param_types(&selector);

    let (name, args) = gen_abi_call_m(rng, dict, &func.name, param_types);

    // Generate value for payable functions
    let value = gen_value(
        rng,
        tx_conf.max_value,
        &mut dict.dict_values,
        &world.payable_sigs,
        &selector,
    );

    // Generate delay using dictionary values
    let delay = gen_delay(
        rng,
        tx_conf.max_time_delay,
        tx_conf.max_block_delay,
        &mut dict.dict_values,
    );

    Some(Tx {
        call: TxCall::SolCall {
            name, // Use the name from gen_abi_call_m (might have come from wholeCalls)
            args,
        },
        src: sender,
        dst: contract_addr,
        gas: tx_conf.tx_gas,
        gasprice: tx_conf.max_gasprice,
        value,
        delay,
    })
}

/// PERF OPTIMIZED: Generate a transaction using pre-cached fuzzable functions and relations
/// Avoids recomputing fuzzable_functions_smart and resolve_wrapper_relations on every call
pub fn gen_tx_with_cached_fuzzable<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    cached_fuzzable: &[Function],
    _cached_assert_functions: &HashSet<String>,
    relations: &HashMap<String, ResolvedRelations>,
    prev_call: Option<&str>,
) -> Option<Tx> {
    if cached_fuzzable.is_empty() {
        return None;
    }

    // relations disabled to match Echidna exactly
    let _ = (relations, prev_call); // Suppress unused warnings

    // Pick sender FIRST (matches Echidna's genTx order)
    let sender = world
        .random_sender(rng)
        .unwrap_or_else(|| Address::from_word(U256::from(0x10000u64).into()));

    // Contract selection
    // Echidna's rElem' uses getRandomR (0, size-1). For single contract, this is
    // getRandomR (0, 0) which returns 0 WITHOUT consuming RNG in most Haskell implementations.
    // We should NOT consume RNG here for single-contract case to match Echidna.
    // (If you have multiple contracts, add rng.gen_range(0..num_contracts) here)

    // Pick function (Echidna's genInteractionsM -> rElem on signatures)
    let func = &cached_fuzzable[rng.gen_range(0..cached_fuzzable.len())];

    let selector = func.selector();
    let param_types = contract.get_param_types(&selector);
    let (name, args) = gen_abi_call_m(rng, dict, &func.name, param_types);

    let value = gen_value(
        rng,
        tx_conf.max_value,
        &mut dict.dict_values,
        &world.payable_sigs,
        &selector,
    );
    let delay = gen_delay(
        rng,
        tx_conf.max_time_delay,
        tx_conf.max_block_delay,
        &mut dict.dict_values,
    );

    Some(Tx {
        call: TxCall::SolCall { name, args },
        src: sender,
        dst: contract_addr,
        gas: tx_conf.tx_gas,
        gasprice: tx_conf.max_gasprice,
        value,
        delay,
    })
}

/// PERF OPTIMIZED: Simple version for when we don't have relations
pub fn gen_tx_with_cached_fuzzable_simple<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    cached_fuzzable: &[Function],
) -> Option<Tx> {
    if cached_fuzzable.is_empty() {
        return None;
    }

    // Pick sender FIRST (matches Echidna's genTx order)
    let sender = world
        .random_sender(rng)
        .unwrap_or_else(|| Address::from_word(U256::from(0x10000u64).into()));

    // Contract selection
    // Echidna's rElem' uses getRandomR (0, size-1). For single contract, this is
    // getRandomR (0, 0) which returns 0 WITHOUT consuming RNG in most Haskell implementations.
    // We should NOT consume RNG here for single-contract case to match Echidna.
    // (If you have multiple contracts, add rng.gen_range(0..num_contracts) here)

    // Pick function (Echidna's genInteractionsM -> rElem on signatures)
    let func = &cached_fuzzable[rng.gen_range(0..cached_fuzzable.len())];

    let selector = func.selector();
    let param_types = contract.get_param_types(&selector);
    let (name, args) = gen_abi_call_m(rng, dict, &func.name, param_types);

    let value = gen_value(
        rng,
        tx_conf.max_value,
        &mut dict.dict_values,
        &world.payable_sigs,
        &selector,
    );
    let delay = gen_delay(
        rng,
        tx_conf.max_time_delay,
        tx_conf.max_block_delay,
        &mut dict.dict_values,
    );

    Some(Tx {
        call: TxCall::SolCall { name, args },
        src: sender,
        dst: contract_addr,
        gas: tx_conf.tx_gas,
        gasprice: tx_conf.max_gasprice,
        value,
        delay,
    })
}

/// Generate a value for a transaction
/// For payable: oftenUsually picks from dict (91%), else random (9%)
/// For non-payable: usuallyVeryRarely returns 0 (99.9%), else random (0.1%)
fn gen_value<R: Rng>(
    rng: &mut R,
    max_value: U256,
    dict_values: &mut abi::types::CachedSet<U256>,
    payable_sigs: &[alloy_primitives::FixedBytes<4>],
    selector: &alloy_primitives::FixedBytes<4>,
) -> U256 {
    let is_payable = payable_sigs.contains(selector);

    if is_payable {
        // Payable function: oftenUsually pick from dict (91%) vs random (9%)
        if often_usually_bool(rng) {
            // Try to pick from dict
            from_dict_value(rng, dict_values, max_value)
        } else {
            gen_random_value(rng, max_value)
        }
    } else {
        // Non-payable: usuallyVeryRarely return 0 (99.9%) vs random (0.1%)
        if usually_very_rarely_bool(rng) {
            U256::ZERO
        } else {
            gen_random_value(rng, max_value)
        }
    }
}

/// Pick a value from dictionary, modulo max+1
fn from_dict_value<R: Rng>(
    rng: &mut R,
    dict_values: &mut abi::types::CachedSet<U256>,
    max: U256,
) -> U256 {
    if dict_values.is_empty() {
        return gen_random_value(rng, max);
    }
    let picked = *dict_values.random_pick(rng).unwrap();
    if max.is_zero() {
        U256::ZERO
    } else {
        picked % (max + U256::from(1))
    }
}

/// Generate a random value between 0 and max
fn gen_random_value<R: Rng>(rng: &mut R, max: U256) -> U256 {
    if max.is_zero() {
        return U256::ZERO;
    }
    let random_bytes: [u8; 32] = rng.gen();
    U256::from_be_bytes(random_bytes) % (max + U256::from(1))
}

/// Generate time/block delay
/// Uses oftenUsually: 91% pick from dict, 9% random
fn gen_delay<R: Rng>(
    rng: &mut R,
    max_time: u64,
    max_block: u64,
    dict_values: &mut abi::types::CachedSet<U256>,
) -> (u64, u64) {
    let time = gen_single_delay(rng, max_time, dict_values);
    let block = gen_single_delay(rng, max_block, dict_values);

    // If one is zero, make both zero (echidna's level function)
    if time == 0 || block == 0 {
        (0, 0)
    } else {
        (time, block)
    }
}

/// Generate a single delay value using dict or random
fn gen_single_delay<R: Rng>(
    rng: &mut R,
    max: u64,
    dict_values: &mut abi::types::CachedSet<U256>,
) -> u64 {
    if max == 0 {
        return 0;
    }

    // oftenUsually: 91% from dict, 9% random
    if often_usually_bool(rng) && !dict_values.is_empty() {
        let picked = *dict_values.random_pick(rng).unwrap();
        let as_u64: u64 = picked.try_into().unwrap_or(u64::MAX);
        as_u64 % (max + 1)
    } else {
        rng.gen_range(1..=max)
    }
}

/// Often returns true, usually returns false
/// weighted uses [0, sum] inclusive = [0, 11] = 12 values
/// n <= 10: u (11 values) = 11/12 ≈ 91.67%
fn often_usually_bool<R: Rng>(rng: &mut R) -> bool {
    rng.gen_ratio(11, 12) // 11/12 matches Echidna's weighted distribution
}

/// Usually returns true, rarely returns false
/// weighted uses [0, 101] = 102 values, n <= 100: u = 101/102
fn usually_rarely_bool<R: Rng>(rng: &mut R) -> bool {
    rng.gen_ratio(101, 102) // 101/102 matches Echidna's weighted distribution
}

/// Usually returns true, very rarely returns false
/// weighted uses [0, 1001] = 1002 values, n <= 1000: u = 1001/1002
fn usually_very_rarely_bool<R: Rng>(rng: &mut R) -> bool {
    rng.gen_ratio(1001, 1002) // 1001/1002 matches Echidna's weighted distribution
}

/// Generate a random sequence of transactions
pub fn rand_seq<R: Rng>(
    rng: &mut R,
    dict: &mut GenDict,
    world: &World,
    tx_conf: &TxConf,
    contract: &CompiledContract,
    contract_addr: Address,
    seq_len: usize,
    mutable_only: bool,
) -> Vec<Tx> {
    (0..seq_len)
        .filter_map(|_| {
            gen_tx(
                rng,
                dict,
                world,
                tx_conf,
                contract,
                contract_addr,
                mutable_only,
            )
        })
        .collect()
}

/// Check if a transaction can be shrunk
pub fn can_shrink_tx(tx: &Tx) -> bool {
    match &tx.call {
        TxCall::SolCall { args, .. } => {
            // Can shrink if gasprice, value, or delay are non-zero
            // or if any argument can be shrunk
            tx.gasprice != U256::ZERO
                || tx.value != U256::ZERO
                || tx.delay != (0, 0)
                || args.iter().any(|a| abi::shrink::can_shrink(a))
        }
        TxCall::NoCall => tx.delay != (0, 0),
        _ => true,
    }
}

/// Shrink a transaction
/// Uses usuallyRarely: 99% apply shrink strategy, 1% removeCallTx
///
/// OPTIMIZED: Skip strategies that would do nothing (e.g., shrink_value when value=0)
pub fn shrink_tx<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    // usuallyRarely: usually (99%) do normal shrink, rarely (1%) removeCallTx
    if usually_rarely_bool(rng) {
        // Build list of applicable strategies (skip no-ops)
        let mut strategies: Vec<fn(&mut R, &Tx) -> Tx> = Vec::with_capacity(4);

        // Always include call shrinking if there are shrinkable args
        if let TxCall::SolCall { args, .. } = &tx.call {
            if args.iter().any(|a| abi::shrink::can_shrink(a)) {
                strategies.push(shrink_call);
            }
        }

        // Only include value shrinking if value is non-zero
        if !tx.value.is_zero() {
            strategies.push(shrink_value);
        }

        // Only include gasprice shrinking if gasprice is non-zero
        if !tx.gasprice.is_zero() {
            strategies.push(shrink_gasprice);
        }

        // Only include delay shrinking if delay is non-zero
        if tx.delay != (0, 0) {
            strategies.push(shrink_delay);
        }

        // If no strategies available, return unchanged
        if strategies.is_empty() {
            return tx.clone();
        }

        // Pick a random strategy from applicable ones
        let strategy = strategies[rng.gen_range(0..strategies.len())];
        strategy(rng, tx)
    } else {
        // removeCallTx - replace call with NoCall
        remove_call_tx(tx)
    }
}

/// Remove the call from a transaction (echidna's removeCallTx)
fn remove_call_tx(tx: &Tx) -> Tx {
    Tx {
        call: TxCall::NoCall,
        src: tx.src,
        dst: tx.dst,
        gas: 0,
        gasprice: U256::ZERO, // NoCall tx doesn't need gas
        value: U256::ZERO,
        delay: tx.delay,
    }
}

fn shrink_call<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    match &tx.call {
        TxCall::SolCall { name, args } => {
            let (shrunk_name, shrunk_args) = abi::shrink::shrink_call(rng, name, args);
            Tx {
                call: TxCall::SolCall {
                    name: shrunk_name,
                    args: shrunk_args,
                },
                ..tx.clone()
            }
        }
        _ => tx.clone(),
    }
}

/// lower x = getRandomR (0, x) >>= \r -> uniform [0, r]
fn lower_u256<R: Rng>(rng: &mut R, x: U256) -> U256 {
    if x.is_zero() {
        return U256::ZERO;
    }
    let r = gen_random_value(rng, x);
    // uniform [0, r] - 50% chance of 0, 50% chance of r
    if rng.gen() {
        U256::ZERO
    } else {
        r
    }
}

fn shrink_value<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    if tx.value.is_zero() {
        return tx.clone();
    }
    // use lower function (biased towards 0)
    let new_value = lower_u256(rng, tx.value);
    Tx {
        value: new_value,
        ..tx.clone()
    }
}

fn shrink_gasprice<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    if tx.gasprice.is_zero() {
        return tx.clone();
    }
    // use lower function (biased towards 0)
    let new_gasprice = lower_u256(rng, tx.gasprice);
    Tx {
        gasprice: new_gasprice,
        ..tx.clone()
    }
}

/// Geometric shrink function for u64
///
/// Combines three strategies from the property-based testing literature:
///
/// 1. **Geometric halving** (SmallCheck-inspired): Produces a sequence 0, x/2, 3x/4, 7x/8...
///    converging to x. We pick a random element from this sequence, biased toward
///    smaller values. This is O(log n) convergent — for a delay of 270M seconds,
///    ~28 steps suffice to reach 0, vs Echidna's expected O(n) random walk.
///
/// 2. **Boundary probing**: Tries common "interesting" time boundaries (1 second,
///    1 minute, 1 hour, 1 day, 1 week) when the current value exceeds them.
///    Real smart contracts often use time-based guards (e.g., lockup periods),
///    so these values have high probability of being the minimal passing delay.
///
/// 3. **Echidna's original lower** (exploration): Random draw from [0, x] with
///    50% bias toward 0. Preserves the randomized exploration that can find
///    surprising minima that structured search misses.
///
/// The selection is weighted: 50% geometric, 20% boundary, 30% Echidna random.
fn lower_u64<R: Rng>(rng: &mut R, x: u64) -> u64 {
    if x == 0 {
        return 0;
    }

    let strategy = rng.gen_range(0..10);
    match strategy {
        // 50%: Geometric halving — pick from the SmallCheck-style shrink list
        // [0, x/2, x - x/4, x - x/8, ...] biased toward smaller values
        0..=4 => {
            // Generate the geometric sequence depth (how many halvings)
            let max_depth = 64 - x.leading_zeros() as u32; // ~log2(x) steps
            let depth = rng.gen_range(0..=max_depth);
            if depth == 0 {
                0
            } else {
                // x - x/2^depth: approaches x from below as depth increases
                x.saturating_sub(x >> depth)
            }
        }
        // 20%: Boundary probing — try semantically meaningful time values
        5 | 6 => {
            // Common EVM time boundaries in seconds
            const BOUNDARIES: [u64; 7] = [
                1,        // 1 second
                60,       // 1 minute
                3600,     // 1 hour
                86400,    // 1 day
                604800,   // 1 week
                2592000,  // 30 days
                31536000, // 1 year
            ];
            // Filter to boundaries smaller than x and pick one
            let valid: Vec<u64> = BOUNDARIES.iter().copied().filter(|&b| b < x).collect();
            if valid.is_empty() {
                // x is very small, just halve it
                x / 2
            } else {
                valid[rng.gen_range(0..valid.len())]
            }
        }
        // 30%: Echidna's original lower (randomized exploration)
        _ => {
            let r = rng.gen_range(0..=x);
            if rng.gen() {
                0
            } else {
                r
            }
        }
    }
}

/// Shrink delay with multiple strategies
///
/// Strategies (chosen uniformly):
/// 1. Lower blocks only — keeps time invariant to isolate block-delay sensitivity
/// 2. Lower time only — keeps blocks invariant to isolate time-delay sensitivity
/// 3. Lower both — maximally aggressive, reduces total delay complexity fastest
/// 4. Zero one component — tests if the contract cares about one dimension at all
///    (many contracts only check block.timestamp, not block.number, or vice versa)
/// 5. Proportional shrink — maintain the time/blocks ratio while shrinking both,
///    useful when contracts depend on consistent time-per-block relationships
fn shrink_delay<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    let (time, blocks) = tx.delay;
    let new_delay = match rng.gen_range(0..7) {
        0 => (time, lower_u64(rng, blocks)), // lower blocks only
        1 => (lower_u64(rng, time), blocks), // lower time only
        2 | 3 => (lower_u64(rng, time), lower_u64(rng, blocks)), // lower both (2x weight)
        4 => {
            // Zero one component: test if contract only uses one time dimension
            if rng.gen() {
                (0, blocks) // zero time, keep blocks
            } else {
                (time, 0) // keep time, zero blocks
            }
        }
        5 => {
            // Proportional shrink: maintain time/blocks ratio
            if blocks == 0 || time == 0 {
                (lower_u64(rng, time), lower_u64(rng, blocks))
            } else {
                let factor = rng.gen_range(2..=8u64);
                (time / factor, blocks / factor)
            }
        }
        _ => (0, 0), // try zeroing both
    };
    Tx {
        delay: new_delay,
        ..tx.clone()
    }
}

/// Shrink only the delay of a transaction, leaving call args unchanged
/// Used by delay-focused candidates in shrink_seq to decouple delay shrinking
/// from argument shrinking (avoids the competition problem where shrink_tx
/// randomly picks between delay/call/value/gasprice strategies)
pub fn shrink_delay_only<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    if tx.delay == (0, 0) {
        return tx.clone();
    }
    shrink_delay(rng, tx)
}

/// Mutate a transaction
/// Uses oftenUsually: 91% skip, 9% mutate for call arguments
/// Also mutates value, gasprice, and delay with 10% probability each
pub fn mutate_tx<R: Rng>(rng: &mut R, tx: &Tx) -> Tx {
    let mut result = tx.clone();

    // Mutate value (10% chance) - bounded to avoid overflow
    if rng.gen_ratio(1, 10) {
        result.value = mutate_tx_value(rng, result.value);
    }

    // Mutate gasprice (10% chance) - bounded to reasonable gas prices
    if rng.gen_ratio(1, 10) {
        result.gasprice = mutate_gasprice(rng, result.gasprice);
    }

    // Mutate delay (10% chance for each component)
    if rng.gen_ratio(1, 10) {
        result.delay.0 = mutate_delay_component(rng, result.delay.0);
    }
    if rng.gen_ratio(1, 10) {
        result.delay.1 = mutate_delay_component(rng, result.delay.1);
    }

    // Mutate call arguments
    match &tx.call {
        TxCall::SolCall { name, args } => {
            // oftenUsually skip (91%), else mutate (9%)
            if !often_usually_bool(rng) {
                // Use enhanced mutation with AFL++ strategies
                let mutated = abi::mutate::mutate_call_enhanced(rng, name, args);
                result.call = TxCall::SolCall {
                    name: mutated.0,
                    args: mutated.1,
                };
            }
        }
        _ => {}
    }

    result
}

/// Mutate transaction value with bounded strategies
/// Max reasonable value: 10000 ETH (prevents balance overflow)
fn mutate_tx_value<R: Rng>(rng: &mut R, value: U256) -> U256 {
    // 10000 ETH in wei - reasonable upper bound
    let max_value = U256::from(10000u64) * U256::from(10u64).pow(U256::from(18u64));

    match rng.gen_range(0..8) {
        0 => U256::ZERO,                                                   // Zero value
        1 => U256::from(1u64),                                             // 1 wei
        2 => U256::from(10u64).pow(U256::from(18u64)),                     // 1 ETH
        3 => value.saturating_add(U256::from(rng.gen_range(1u64..=1000))), // Add small wei
        4 => value.saturating_sub(U256::from(rng.gen_range(1u64..=1000))), // Sub small wei
        5 => {
            // Add/sub ETH amounts
            let eth =
                U256::from(rng.gen_range(1u64..=10)) * U256::from(10u64).pow(U256::from(18u64));
            if rng.gen() {
                value.saturating_add(eth)
            } else {
                value.saturating_sub(eth)
            }
        }
        6 => {
            // Random value up to max
            let random_bytes: [u8; 32] = rng.gen();
            U256::from_be_bytes(random_bytes) % (max_value + U256::from(1u64))
        }
        _ => value / U256::from(2u64), // Halve
    }
    .min(max_value) // Always clamp to max
}

/// Mutate gas price with bounded strategies
/// Max: 10000 gwei (prevents unreasonable gas costs)
fn mutate_gasprice<R: Rng>(rng: &mut R, gasprice: U256) -> U256 {
    let gwei = U256::from(10u64).pow(U256::from(9u64));
    let max_gasprice = U256::from(10000u64) * gwei;

    match rng.gen_range(0..6) {
        0 => U256::ZERO,               // Zero gas price
        1 => gwei,                     // 1 gwei
        2 => U256::from(20u64) * gwei, // 20 gwei (typical)
        3 => gasprice.saturating_add(gwei * U256::from(rng.gen_range(1u64..=10))),
        4 => gasprice.saturating_sub(gwei * U256::from(rng.gen_range(1u64..=10))),
        _ => U256::from(rng.gen_range(1u64..=1000)) * gwei, // Random 1-1000 gwei
    }
    .min(max_gasprice)
}

/// Mutate a delay component (time or block count)
fn mutate_delay_component<R: Rng>(rng: &mut R, delay: u64) -> u64 {
    match rng.gen_range(0..6) {
        0 => 0,                                            // Set to zero
        1 => delay.saturating_add(rng.gen_range(1..=100)), // Add small delta
        2 => delay.saturating_sub(rng.gen_range(1..=100)), // Sub small delta
        3 => rng.gen_range(0..=86400),                     // Random up to 1 day (for time)
        4 => rng.gen_range(0..=1000),                      // Random up to 1000 blocks
        _ => delay.saturating_mul(2).min(u64::MAX / 2),    // Double (capped)
    }
}
