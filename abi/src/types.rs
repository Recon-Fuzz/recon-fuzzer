//! Core ABI types for recon-fuzzer
//!

use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_json_abi::{Function, StateMutability};
use alloy_primitives::{FixedBytes, I256, U256};
use primitives::{INITIAL_BLOCK_NUMBER, INITIAL_TIMESTAMP};
use std::collections::{BTreeSet, HashMap};

/// A Solidity function signature: (name, parameter types)
pub type SolSignature = (String, Vec<String>);

/// A concrete Solidity call: (name, argument values)
pub type SolCall = (String, Vec<DynSolValue>);

/// Map from function signatures to sets of concrete calls
/// Using Vec instead of HashSet since DynSolValue doesn't impl Hash
pub type SignatureMap = HashMap<alloy_primitives::Address, Vec<SolSignature>>;

/// Configuration for generating random ABI values
#[derive(Debug, Clone)]
pub struct GenDict {
    /// Fraction of time to use dictionary vs synthesize (0.0-1.0)
    pub dict_freq: f32,

    /// Constants extracted from source, indexed by type
    /// Using Vec instead of HashSet since DynSolValue doesn't impl Hash
    pub constants: HashMap<String, Vec<DynSolValue>>,

    /// Complete calls seen during fuzzing, for replay
    pub whole_calls: HashMap<SolSignature, Vec<SolCall>>,

    /// RNG seed
    pub seed: u64,

    /// Return types from functions (for generating matching values)
    pub return_types: HashMap<String, DynSolType>,

    /// A set of int/uint constants for better performance
    /// Uses BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
    pub dict_values: BTreeSet<U256>,

    /// A set of signed int constants
    /// Contains both positive and negative variants for optimization
    /// Uses BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
    pub signed_dict_values: BTreeSet<I256>,

    /// Callback signatures for generating random callbacks
    pub callback_sigs: Vec<SolSignature>,
    
    /// Functions that have improved optimization test values (ENHANCEMENT)
    /// When a sequence improves an optimization test, we remember which functions were called.
    /// These functions are given higher weight during transaction generation.
    /// Key: function name, Value: count of times it improved optimization
    pub optimization_hot_functions: HashMap<String, usize>,
    
    /// TARGETED ARGUMENT EVOLUTION: Values that were used when optimization improved
    /// These are "hot values" that should be prioritized in argument generation
    /// We track U256 values separately for faster lookup
    /// Uses BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
    pub optimization_hot_values: BTreeSet<U256>,

    /// TARGETED ARGUMENT EVOLUTION: Signed values that were used when optimization improved
    /// Uses BTreeSet for deterministic iteration order (matches Haskell's Data.Set)
    pub optimization_hot_signed_values: BTreeSet<I256>,
}

impl Default for GenDict {
    fn default() -> Self {
        Self {
            dict_freq: 0.40, // 40% dictionary, 60% synthesis
            constants: HashMap::new(),
            whole_calls: HashMap::new(),
            seed: 0,
            return_types: HashMap::new(),
            dict_values: BTreeSet::new(),
            signed_dict_values: BTreeSet::new(),
            callback_sigs: Vec::new(),
            optimization_hot_functions: HashMap::new(),
            optimization_hot_values: BTreeSet::new(),
            optimization_hot_signed_values: BTreeSet::new(),
        }
    }
}

impl GenDict {
    pub fn new(seed: u64) -> Self {
        let mut dict = Self {
            seed,
            ..Default::default()
        };
        // These are values commonly used in bugs/edge cases
        for i in 0u64..=32 {
            dict.dict_values.insert(U256::from(i));
        }
        // Add powers of 2
        for i in 0..=8 {
            dict.dict_values.insert(U256::from(1u64 << i));
        }
        // Add common edge cases
        dict.dict_values.insert(U256::MAX);
        dict.dict_values.insert(U256::MAX - U256::from(1));
        dict.dict_values.insert(U256::from(100));
        dict.dict_values.insert(U256::from(1000));
        
        // Add magic values for common attack vectors
        Self::add_magic_values(&mut dict);
        
        // Initialize signed dictionary with edge cases 
        Self::add_signed_edge_cases(&mut dict);
        
        // This adds initialTimestamp ± 1 and initialBlockNumber ± 1 to dict
        Self::add_time_constants(&mut dict);
        
        dict
    }
    
    /// Add initial timestamp and block number constants 
    fn add_time_constants(dict: &mut GenDict) {
        // Use constants from primitives crate
        // Add timestamp ± 1
        for offset in -1i64..=1 {
            let ts = (INITIAL_TIMESTAMP as i64 + offset) as u64;
            dict.dict_values.insert(U256::from(ts));
        }
        
        // Add block number ± 1
        for offset in -1i64..=1 {
            let bn = (INITIAL_BLOCK_NUMBER as i64 + offset) as u64;
            dict.dict_values.insert(U256::from(bn));
        }
    }
    
    /// Add signed integer edge cases
    /// These are critical for finding bugs involving negative numbers
    fn add_signed_edge_cases(dict: &mut GenDict) {
        // Small signed integers (-32 to 32)
        for i in -32i64..=32 {
            if let Ok(val) = I256::try_from(i) {
                dict.signed_dict_values.insert(val);
            }
        }
        
        // Signed boundaries for common bit sizes (8 to 32 bits)
        for bits in [8u32, 16, 24, 32].iter() {
            let bits = *bits;
            // Max positive: 2^(n-1) - 1
            let max_pos = I256::try_from((1i64 << (bits - 1)) - 1).unwrap_or(I256::ZERO);
            // Min negative: -2^(n-1)  
            let min_neg = -I256::try_from(1i64 << (bits - 1)).unwrap_or(I256::ZERO);
            
            dict.signed_dict_values.insert(max_pos);
            dict.signed_dict_values.insert(min_neg);
            dict.signed_dict_values.insert(min_neg + I256::ONE);  // min + 1
            dict.signed_dict_values.insert(max_pos - I256::ONE);  // max - 1
        }
        
        // 64-bit boundaries (i64 range)
        dict.signed_dict_values.insert(I256::try_from(i64::MAX).unwrap());
        dict.signed_dict_values.insert(I256::try_from(i64::MIN).unwrap());
        
        // 128-bit boundaries (i128 range)
        dict.signed_dict_values.insert(I256::try_from(i128::MAX).unwrap());
        dict.signed_dict_values.insert(I256::try_from(i128::MIN).unwrap());
        
        // I256 boundaries (256-bit)
        dict.signed_dict_values.insert(I256::MAX);
        dict.signed_dict_values.insert(I256::MIN);
        dict.signed_dict_values.insert(I256::MIN + I256::ONE);
        dict.signed_dict_values.insert(I256::MAX - I256::ONE);
        dict.signed_dict_values.insert(I256::ZERO);
        dict.signed_dict_values.insert(-I256::ONE);
        dict.signed_dict_values.insert(I256::ONE);
    }
    
    /// Add magic values commonly used in security testing
    fn add_magic_values(dict: &mut GenDict) {
        // Common overflow/underflow boundaries
        dict.dict_values.insert(U256::ZERO);
        dict.dict_values.insert(U256::from(1));
        dict.dict_values.insert(U256::MAX);
        dict.dict_values.insert(U256::MAX - U256::from(1));
        
        // Powers of 2 (common bit boundaries)
        for i in [8, 16, 32, 64, 128, 255, 256].iter() {
            if *i < 256 {
                dict.dict_values.insert(U256::from(1u128) << i);
                dict.dict_values.insert((U256::from(1u128) << i) - U256::from(1));
            }
        }
        
        // Common time values (seconds)
        dict.dict_values.insert(U256::from(60u64));       // 1 minute
        dict.dict_values.insert(U256::from(3600u64));     // 1 hour
        dict.dict_values.insert(U256::from(86400u64));    // 1 day
        dict.dict_values.insert(U256::from(604800u64));   // 1 week
        dict.dict_values.insert(U256::from(2592000u64));  // 30 days
        dict.dict_values.insert(U256::from(31536000u64)); // 1 year
        
        // Common wei/ether values
        dict.dict_values.insert(U256::from(1_000_000_000_000_000_000u128));  // 1 ether
        dict.dict_values.insert(U256::from(1_000_000_000u64));               // 1 gwei
        dict.dict_values.insert(U256::from(1_000_000u64));                   // 1 szabo
        
        // Common percentages (basis points)
        dict.dict_values.insert(U256::from(10000u64));  // 100%
        dict.dict_values.insert(U256::from(5000u64));   // 50%
        dict.dict_values.insert(U256::from(1000u64));   // 10%
        dict.dict_values.insert(U256::from(100u64));    // 1%
        
        // Type boundaries (max values for common Solidity types)
        dict.dict_values.insert(U256::from(u8::MAX));
        dict.dict_values.insert(U256::from(u16::MAX));
        dict.dict_values.insert(U256::from(u32::MAX));
        dict.dict_values.insert(U256::from(u64::MAX));
        dict.dict_values.insert(U256::from(u128::MAX));
    }
    
    /// Generate numeric values from a constant 
    /// For a value N, generates: N-3, N-2, N-1, N, N+1, N+2, N+3
    /// AND their negations: -N-3, -N-2, -N-1, -N, -N+1, -N+2, -N+3
    /// This is critical for optimization tests and finding edge cases
    pub fn make_num_values(n: i128) -> Vec<I256> {
        let mut values = Vec::with_capacity(14);
        
        // Generate n-3 to n+3
        for offset in -3i128..=3 {
            if let Ok(val) = I256::try_from(n.saturating_add(offset)) {
                values.push(val);
            }
        }
        
        // Generate -n-3 to -n+3 (negative variants)
        let neg_n = n.saturating_neg();
        for offset in -3i128..=3 {
            if let Ok(val) = I256::try_from(neg_n.saturating_add(offset)) {
                values.push(val);
            }
        }
        
        values
    }
    
    /// Add a numeric constant and its variants to the dictionary
    pub fn add_numeric_constant(&mut self, n: i128) {
        let variants = Self::make_num_values(n);
        for val in variants {
            self.signed_dict_values.insert(val);
            // Also add to unsigned if positive
            if val >= I256::ZERO {
                if let Ok(unsigned) = val.try_into() {
                    self.dict_values.insert(unsigned);
                }
            }
        }
    }

    /// Add constants to the dictionary
    /// Updates both constants map, dict_values set, and signed_dict_values
    /// Also generates ±N and ±N±3 variants for numeric constants 
    pub fn add_constants(&mut self, values: impl IntoIterator<Item = DynSolValue>) {
        for val in values {
            // CRITICAL: Must match format used in get_from_dict
            let type_name = val.sol_type_name().map(|s| s.to_string()).unwrap_or_default();

            // Also add to dict_values if it's a numeric type
            // AND generate signed variants with make_num_values
            match &val {
                DynSolValue::Uint(u, _) => {
                    self.dict_values.insert(*u);
                    // Generate signed variants if value fits in i128
                    if *u <= U256::from(i128::MAX as u128) {
                        let n = u.try_into().unwrap_or(0i128);
                        self.add_numeric_constant(n);
                    }
                }
                DynSolValue::Int(i, _) => {
                    // Add to signed dict
                    self.signed_dict_values.insert(*i);
                    // Also generate variants
                    if let Ok(n) = i128::try_from(*i) {
                        self.add_numeric_constant(n);
                    }
                    // Add unsigned abs if positive
                    if *i >= I256::ZERO {
                        if let Ok(unsigned) = (*i).try_into() {
                            self.dict_values.insert(unsigned);
                        }
                    }
                }
                _ => {}
            }

            self.constants.entry(type_name).or_default().push(val);
        }
    }

    /// Add a single value to the dictionary
    pub fn add_value(&mut self, val: DynSolValue) {
        self.add_constants(std::iter::once(val));
    }

    /// Add a call to the dictionary
    pub fn add_call(&mut self, call: SolCall) {
        let sig = (
            call.0.clone(),
            call.1
                .iter()
                .map(|v| v.sol_type_name().map(|s| s.to_string()).unwrap_or_default())
                .collect(),
        );
        self.whole_calls.entry(sig).or_default().push(call);
    }

    /// Add calls to the dictionary
    pub fn add_calls(&mut self, calls: impl IntoIterator<Item = SolCall>) {
        for call in calls {
            self.add_call(call);
        }
    }
    
    /// Record a function that improved an optimization test value (ENHANCEMENT)
    /// These functions will be called more often during transaction generation.
    pub fn record_optimization_improving_function(&mut self, func_name: &str) {
        *self.optimization_hot_functions.entry(func_name.to_string()).or_insert(0) += 1;
    }
    
    /// Record all functions from a sequence that improved optimization (ENHANCEMENT)
    pub fn record_optimization_improving_sequence(&mut self, func_names: impl IntoIterator<Item = impl AsRef<str>>) {
        for name in func_names {
            self.record_optimization_improving_function(name.as_ref());
        }
    }
    
    /// TARGETED ARGUMENT EVOLUTION: Record values from arguments that improved optimization
    /// These values are more likely to be useful for further optimization
    pub fn record_optimization_improving_values(&mut self, args: &[DynSolValue]) {
        for arg in args {
            self.extract_hot_values_recursive(arg);
        }
    }
    
    /// Helper to extract numeric values from DynSolValue recursively
    fn extract_hot_values_recursive(&mut self, val: &DynSolValue) {
        match val {
            DynSolValue::Uint(u, _) => {
                self.optimization_hot_values.insert(*u);
            }
            DynSolValue::Int(i, _) => {
                self.optimization_hot_signed_values.insert(*i);
            }
            DynSolValue::Bool(b) => {
                // Booleans don't contribute to numeric hot values
                let _ = b;
            }
            DynSolValue::Address(_) => {
                // Addresses don't contribute to numeric hot values  
            }
            DynSolValue::FixedBytes(_, _) => {}
            DynSolValue::Bytes(_) => {}
            DynSolValue::String(_) => {}
            DynSolValue::Array(arr) | DynSolValue::FixedArray(arr) => {
                for item in arr {
                    self.extract_hot_values_recursive(item);
                }
            }
            DynSolValue::Tuple(tup) => {
                for item in tup {
                    self.extract_hot_values_recursive(item);
                }
            }
            _ => {}
        }
    }
    
    /// Check if a value is "hot" (was used in optimization-improving sequence)
    pub fn is_hot_value(&self, val: &U256) -> bool {
        self.optimization_hot_values.contains(val)
    }
    
    /// Check if a signed value is "hot"
    pub fn is_hot_signed_value(&self, val: &I256) -> bool {
        self.optimization_hot_signed_values.contains(val)
    }
    
    /// Get the weight for a function based on whether it's helped optimize (ENHANCEMENT)
    /// Hot functions get 3x weight, normal functions get 1x
    pub fn get_function_weight(&self, func_name: &str) -> usize {
        if self.optimization_hot_functions.contains_key(func_name) {
            3 // Hot functions get 3x weight
        } else {
            1 // Normal functions get 1x weight
        }
    }
    
    /// Seed dictionary from bytecode constants
    /// Extracts PUSH operands and generates ±N, ±N±3 variants 
    pub fn seed_from_bytecode(&mut self, bytecode: &[u8]) {
        let (unsigned, signed) = analysis::bytecode::extract_constants_with_variants(bytecode);
        self.dict_values.extend(unsigned);
        self.signed_dict_values.extend(signed);
    }
    
    /// Seed dictionary from multiple bytecodes
    pub fn seed_from_bytecodes(&mut self, bytecodes: impl IntoIterator<Item = impl AsRef<[u8]>>) {
        for bytecode in bytecodes {
            self.seed_from_bytecode(bytecode.as_ref());
        }
    }
    
    /// Seed dictionary from SlitherInfo (recon-generate info output)
    /// This extracts constants from source analysis and generates variants
    pub fn seed_from_slither_info(&mut self, info: &analysis::slither::SlitherInfo) {
        // Extract dict_values (U256)
        let unsigned = analysis::slither::extract_dict_values(info);
        self.dict_values.extend(unsigned);
        
        // Extract signed_dict_values (I256)
        let signed = analysis::slither::extract_signed_dict_values(info);
        self.signed_dict_values.extend(signed);
        
        // Also add enhanced constants to the constants map
        let enhanced = analysis::slither::enhance_constants(info);
        self.add_constants(enhanced.into_iter());
    }
    
    /// EXTERNAL ORACLE SEEDING: Seed dictionary from a text file
    /// Each line contains either:
    /// - A hex number (0x...) - added as U256
    /// - A decimal number - added as U256
    /// - A negative decimal - added as I256
    /// This allows users to inject known-good values from external analysis
    pub fn seed_from_file(&mut self, path: &std::path::Path) -> std::io::Result<usize> {
        use std::io::{BufRead, BufReader};
        use std::fs::File;
        
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut count = 0;
        
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue; // Skip empty lines and comments
            }
            
            // Try hex first
            if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
                if let Ok(val) = U256::from_str_radix(hex, 16) {
                    self.dict_values.insert(val);
                    count += 1;
                    continue;
                }
            }
            
            // Try negative decimal
            if trimmed.starts_with('-') {
                if let Ok(n) = trimmed.parse::<i128>() {
                    if let Ok(val) = I256::try_from(n) {
                        self.signed_dict_values.insert(val);
                        count += 1;
                    }
                }
                continue;
            }
            
            // Try positive decimal
            if let Ok(n) = trimmed.parse::<u128>() {
                self.dict_values.insert(U256::from(n));
                count += 1;
            }
        }
        
        Ok(count)
    }
    
    /// Create dict_values from a set of DynSolValues
    pub fn mk_dict_values(values: &[DynSolValue]) -> BTreeSet<U256> {
        let mut set = BTreeSet::new();
        for val in values {
            if let Some(u) = extract_uint(val) {
                set.insert(u);
            }
        }
        set
    }
}

/// Extract U256 from a DynSolValue if it's a numeric type
fn extract_uint(val: &DynSolValue) -> Option<U256> {
    match val {
        DynSolValue::Uint(n, _) => Some(*n),
        DynSolValue::Int(n, _) => {
            // Convert I256 to U256 (taking absolute value)
            let abs = n.unsigned_abs();
            Some(abs)
        }
        _ => None,
    }
}

/// Parsed contract function with ABI info
#[derive(Debug, Clone)]
pub struct ContractFunction {
    pub name: String,
    pub selector: FixedBytes<4>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub is_payable: bool,
    pub is_view: bool,
    pub is_pure: bool,
}

impl From<&Function> for ContractFunction {
    fn from(f: &Function) -> Self {
        Self {
            name: f.name.clone(),
            selector: f.selector(),
            inputs: f.inputs.iter().map(|p| p.ty.to_string()).collect(),
            outputs: f.outputs.iter().map(|p| p.ty.to_string()).collect(),
            is_payable: matches!(f.state_mutability, StateMutability::Payable),
            is_view: matches!(f.state_mutability, StateMutability::View),
            is_pure: matches!(f.state_mutability, StateMutability::Pure),
        }
    }
}
