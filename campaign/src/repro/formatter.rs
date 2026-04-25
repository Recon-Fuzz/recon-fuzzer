//! DynSolValue → Solidity literal formatting
//!
//! Converts fuzzer-generated argument values into valid Solidity source code.
//! Complex types (arrays, tuples) that cannot be inlined are emitted as local
//! variable declarations preceding the function call.

use alloy_dyn_abi::DynSolValue;
use alloy_primitives::I256;

/// Result of formatting a single function argument.
///
/// Simple scalars produce an empty `pre_statements` and the literal in `inline`.
/// Complex types (arrays, nested tuples) produce variable declarations in
/// `pre_statements` and a variable reference in `inline`.
pub struct FormattedArg {
    /// Statements to emit before the function call (e.g., array construction).
    pub pre_statements: Vec<String>,
    /// Expression to use at the call site (literal or variable name).
    pub inline: String,
}

/// Format a `DynSolValue` into Solidity source.
///
/// `var_hint` is used as a base name for any local variables that need to be
/// declared (e.g., `"arg0"` → `uint256[] memory arg0 = ...`).
///
/// `type_hint` is the struct/tuple type name from the ABI (e.g., `"LiquidationConfig"`).
/// When provided, tuples are emitted as `StructName(a, b, c)` instead of bare `(a, b, c)`.
pub fn format_arg(val: &DynSolValue, var_hint: &str, type_hint: Option<&str>) -> FormattedArg {
    match val {
        DynSolValue::Bool(b) => FormattedArg {
            pre_statements: vec![],
            inline: if *b { "true" } else { "false" }.into(),
        },

        DynSolValue::Uint(n, _bits) => FormattedArg {
            pre_statements: vec![],
            inline: format!("{}", n),
        },

        DynSolValue::Int(n, _bits) => FormattedArg {
            pre_statements: vec![],
            inline: format_i256(*n),
        },

        DynSolValue::Address(a) => FormattedArg {
            pre_statements: vec![],
            inline: format!("address({})", a),
        },

        DynSolValue::FixedBytes(word, size) => {
            let bytes = &word.as_slice()[..*size];
            FormattedArg {
                pre_statements: vec![],
                inline: format!("bytes{}(hex\"{}\")", size, hex::encode(bytes)),
            }
        }

        DynSolValue::Bytes(b) => FormattedArg {
            pre_statements: vec![],
            inline: format!("hex\"{}\"", hex::encode(b)),
        },

        DynSolValue::String(s) => FormattedArg {
            pre_statements: vec![],
            inline: format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")),
        },

        DynSolValue::Function(f) => FormattedArg {
            pre_statements: vec![],
            inline: format!("hex\"{}\"", hex::encode(f)),
        },

        DynSolValue::Array(items) | DynSolValue::FixedArray(items) => {
            format_array(items, val, var_hint)
        }

        DynSolValue::Tuple(items) => format_tuple(items, var_hint, type_hint),
    }
}

/// Format a signed 256-bit integer.
fn format_i256(v: I256) -> String {
    if v.is_negative() {
        let abs = v.wrapping_neg();
        format!("-{}", abs)
    } else {
        format!("{}", v)
    }
}

/// Infer the Solidity type name from a `DynSolValue`.
pub fn sol_type_name(val: &DynSolValue) -> String {
    match val {
        DynSolValue::Bool(_) => "bool".into(),
        DynSolValue::Uint(_, bits) => format!("uint{}", bits),
        DynSolValue::Int(_, bits) => format!("int{}", bits),
        DynSolValue::Address(_) => "address".into(),
        DynSolValue::FixedBytes(_, size) => format!("bytes{}", size),
        DynSolValue::Bytes(_) => "bytes".into(),
        DynSolValue::String(_) => "string".into(),
        DynSolValue::Function(_) => "bytes24".into(),
        DynSolValue::Array(items) => {
            let inner = items
                .first()
                .map(sol_type_name)
                .unwrap_or_else(|| "uint256".into());
            format!("{}[]", inner)
        }
        DynSolValue::FixedArray(items) => {
            let inner = items
                .first()
                .map(sol_type_name)
                .unwrap_or_else(|| "uint256".into());
            format!("{}[{}]", inner, items.len())
        }
        DynSolValue::Tuple(_) => "tuple".into(),
    }
}

/// Format an array value into a local variable declaration + element assignments.
fn format_array(items: &[DynSolValue], original: &DynSolValue, var_hint: &str) -> FormattedArg {
    let inner_type = items
        .first()
        .map(sol_type_name)
        .unwrap_or_else(|| "uint256".into());

    let mut pre = Vec::new();

    match original {
        DynSolValue::Array(_) => {
            pre.push(format!(
                "{inner_type}[] memory {var_hint} = new {inner_type}[]({});",
                items.len()
            ));
        }
        DynSolValue::FixedArray(_) => {
            pre.push(format!(
                "{inner_type}[{}] memory {var_hint};",
                items.len()
            ));
        }
        _ => unreachable!(),
    }

    for (i, item) in items.iter().enumerate() {
        let elem_hint = format!("{var_hint}_{i}");
        let formatted = format_arg(item, &elem_hint, None);
        pre.extend(formatted.pre_statements);
        pre.push(format!("{var_hint}[{i}] = {};", formatted.inline));
    }

    FormattedArg {
        pre_statements: pre,
        inline: var_hint.into(),
    }
}

/// Format a tuple (struct) value.
///
/// With a `type_hint` (struct name from ABI), emits `StructName(a, b, c)`.
/// Without a type hint, emits a TODO comment so the user can fill in the type.
fn format_tuple(
    items: &[DynSolValue],
    var_hint: &str,
    type_hint: Option<&str>,
) -> FormattedArg {
    let mut pre = Vec::new();
    let mut parts = Vec::new();

    for (i, item) in items.iter().enumerate() {
        let elem_hint = format!("{var_hint}_{i}");
        let formatted = format_arg(item, &elem_hint, None);
        pre.extend(formatted.pre_statements);
        parts.push(formatted.inline);
    }

    let values = parts.join(", ");

    let inline = if let Some(struct_name) = type_hint {
        format!("{}({})", struct_name, values)
    } else {
        // No type info — emit raw tuple with a TODO so the user knows to fix it
        pre.push(format!("// TODO: replace tuple with correct struct type for {var_hint}"));
        format!("({})", values)
    };

    FormattedArg {
        pre_statements: pre,
        inline,
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    #[test]
    fn test_format_uint() {
        let val = DynSolValue::Uint(U256::from(42u64), 256);
        let f = format_arg(&val, "x", None);
        assert!(f.pre_statements.is_empty());
        assert_eq!(f.inline, "42");
    }

    #[test]
    fn test_format_address() {
        let val = DynSolValue::Address(Address::ZERO);
        let f = format_arg(&val, "x", None);
        assert!(f.pre_statements.is_empty());
        assert!(f.inline.starts_with("address("));
    }

    #[test]
    fn test_format_array() {
        let val = DynSolValue::Array(vec![
            DynSolValue::Uint(U256::from(1u64), 256),
            DynSolValue::Uint(U256::from(2u64), 256),
        ]);
        let f = format_arg(&val, "arr", None);
        assert_eq!(f.inline, "arr");
        assert_eq!(f.pre_statements.len(), 3); // declaration + 2 assignments
        assert!(f.pre_statements[0].contains("new uint256[](2)"));
    }

    #[test]
    fn test_format_tuple_with_struct_name() {
        let val = DynSolValue::Tuple(vec![
            DynSolValue::Uint(U256::from(998982562669u64), 256),
            DynSolValue::Uint(U256::ZERO, 256),
            DynSolValue::Uint(U256::ZERO, 256),
            DynSolValue::Bool(true),
            DynSolValue::Bool(false),
        ]);
        let f = format_arg(&val, "t", Some("SpokeConfig"));
        assert!(f.pre_statements.is_empty());
        assert_eq!(f.inline, "SpokeConfig(998982562669, 0, 0, true, false)");
    }

    #[test]
    fn test_format_tuple_without_struct_name() {
        let val = DynSolValue::Tuple(vec![
            DynSolValue::Bool(true),
            DynSolValue::Uint(U256::from(99u64), 256),
        ]);
        let f = format_arg(&val, "t", None);
        assert_eq!(f.inline, "(true, 99)");
        assert!(f.pre_statements.iter().any(|s| s.contains("TODO")));
    }
}
