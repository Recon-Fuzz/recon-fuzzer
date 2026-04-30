//! Foundry test code generation via askama templates.
//!
//! Converts a shrunk reproducer (`Vec<Tx>`) into a Solidity `function test_…`
//! block ready to be appended to an existing CryticToFoundry-style file.

use alloy_json_abi::JsonAbi;
use alloy_primitives::I256;
use askama::Template;
use evm::types::{Tx, TxCall};

use crate::testing::{TestType, TestValue};

use super::formatter;

/// Askama template for a single Foundry test function.
#[derive(Template)]
#[template(path = "test_function.sol.jinja")]
struct TestFunctionTemplate {
    test_name: String,
    statements: Vec<String>,
}

/// Information about the test that produced the reproducer.
pub struct ReproContext<'a> {
    pub test_type: &'a TestType,
    pub value: &'a TestValue,
    pub reproducer: &'a [Tx],
    /// Contract ABI — used to resolve struct type names for tuple parameters.
    pub abi: Option<&'a JsonAbi>,
}

/// Generate a complete `function test_…() public { … }` block from a reproducer.
pub fn render_test_function(ctx: &ReproContext) -> anyhow::Result<String> {
    let test_name = build_test_name(ctx);
    let statements = build_statements(ctx);

    let tmpl = TestFunctionTemplate {
        test_name,
        statements,
    };
    Ok(tmpl.render()?)
}

/// Return the test name (for log messages — avoids re-rendering the full template).
pub fn test_name_for_log(ctx: &ReproContext) -> String {
    build_test_name(ctx)
}

/// Build a descriptive test function name with a timestamp suffix to avoid conflicts.
fn build_test_name(ctx: &ReproContext) -> String {
    let base = sanitize_name(ctx.test_type.name());
    let ts = compact_timestamp();

    match ctx.value {
        TestValue::IntValue(v) => format!("{base}_opt_{}_{ts}", format_i256_short(*v)),
        _ => format!("{base}_{ts}"),
    }
}

/// Short hex timestamp (seconds since epoch, last 8 hex digits) for unique suffixes.
fn compact_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{:08x}", secs as u32)
}

/// Sanitize a property/function name for use as a Solidity identifier.
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

fn format_i256_short(v: I256) -> String {
    if v.is_negative() {
        let abs = v.wrapping_neg();
        format!("neg{}", abs)
    } else {
        format!("{}", v)
    }
}

/// Convert each `Tx` in the reproducer into one or more Solidity statements.
fn build_statements(ctx: &ReproContext) -> Vec<String> {
    let mut stmts = Vec::new();

    for tx in ctx.reproducer {
        emit_delays(&mut stmts, tx);
        emit_call(&mut stmts, tx, ctx.abi);
    }

    emit_tail_assertion(&mut stmts, ctx);

    stmts
}

/// Look up a function in the ABI and extract the struct type name for each tuple parameter.
/// Returns `None` if the function isn't found. For non-tuple params, the entry is `None`.
fn resolve_param_types(func_name: &str, abi: Option<&JsonAbi>) -> Option<Vec<Option<String>>> {
    let abi = abi?;
    let func = abi.functions().find(|f| f.name == func_name)?;
    Some(
        func.inputs
            .iter()
            .map(|param| extract_struct_name(param))
            .collect(),
    )
}

/// Extract the struct type name from a parameter's `internal_type` field.
/// E.g., `struct IHub.SpokeConfig` → `IHub.SpokeConfig`.
fn extract_struct_name(param: &alloy_json_abi::Param) -> Option<String> {
    use alloy_json_abi::InternalType;
    match &param.internal_type {
        Some(InternalType::Struct { contract, ty }) => {
            if let Some(contract) = contract {
                Some(format!("{}.{}", contract, ty))
            } else {
                Some(ty.clone())
            }
        }
        _ => None,
    }
}

/// Emit `vm.warp` / `vm.roll` for non-zero delays.
fn emit_delays(stmts: &mut Vec<String>, tx: &Tx) {
    let (time_delay, block_delay) = tx.delay;
    if time_delay > 0 {
        stmts.push(format!(
            "vm.warp(block.timestamp + {});",
            time_delay
        ));
    }
    if block_delay > 0 {
        stmts.push(format!(
            "vm.roll(block.number + {});",
            block_delay
        ));
    }
}

/// Emit the function call for a transaction.
fn emit_call(stmts: &mut Vec<String>, tx: &Tx, abi: Option<&JsonAbi>) {
    match &tx.call {
        TxCall::SolCall { name, args } => {
            let param_types = resolve_param_types(name, abi);
            let mut pre_stmts = Vec::new();
            let mut inline_args = Vec::new();

            for (i, arg) in args.iter().enumerate() {
                let hint = format!("{name}_arg{i}");
                let type_hint = param_types
                    .as_ref()
                    .and_then(|params| params.get(i))
                    .and_then(|s| s.as_deref());
                let formatted = formatter::format_arg(arg, &hint, type_hint);
                pre_stmts.extend(formatted.pre_statements);
                inline_args.push(formatted.inline);
            }

            stmts.extend(pre_stmts);

            if tx.value.is_zero() {
                stmts.push(format!("{}({});", name, inline_args.join(", ")));
            } else {
                stmts.push(format!(
                    "{}{{value: {}}}({});",
                    name,
                    tx.value,
                    inline_args.join(", ")
                ));
            }
        }
        TxCall::NoCall => {
            // Pure delay tx — delays already emitted above
        }
        TxCall::SolCalldata(data) => {
            stmts.push(format!(
                "address(this).call(hex\"{}\");",
                hex::encode(data)
            ));
        }
        TxCall::SolCreate(_) => {
            stmts.push("// constructor replay not supported".into());
        }
    }
}

/// Append the property/optimization call at the end of the test.
fn emit_tail_assertion(stmts: &mut Vec<String>, ctx: &ReproContext) {
    match ctx.test_type {
        TestType::PropertyTest { name, .. } => {
            stmts.push(format!("{}();", name));
        }
        TestType::OptimizationTest { name, .. } => {
            if let TestValue::IntValue(v) = ctx.value {
                stmts.push(format!("// optimization value: {}", v));
            }
            stmts.push(format!("{}();", name));
        }
        TestType::AssertionTest { .. } => {
            // Assertion tests don't need a tail call — the assertion is
            // inside the last transaction in the reproducer.
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_dyn_abi::DynSolValue;
    use alloy_primitives::{Address, U256};

    fn make_tx(name: &str, args: Vec<DynSolValue>, delay: (u64, u64)) -> Tx {
        Tx {
            call: TxCall::SolCall {
                name: name.into(),
                args,
            },
            src: Address::ZERO,
            dst: Address::ZERO,
            gas: 12_500_000,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay,
            generate_calls_seed: None,
            generate_calls: Vec::new(),
        }
    }

    #[test]
    fn test_render_property_test() {
        let txs = vec![
            make_tx(
                "vault_deposit",
                vec![DynSolValue::Uint(U256::from(1000u64), 256)],
                (100, 5),
            ),
            make_tx(
                "vault_withdraw",
                vec![DynSolValue::Uint(U256::from(500u64), 256)],
                (0, 0),
            ),
        ];

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "property_totalSupply".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &txs,
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("function test_property_totalSupply_"));
        assert!(result.contains("vm.warp(block.timestamp + 100)"));
        assert!(result.contains("vm.roll(block.number + 5)"));
        assert!(result.contains("vault_deposit(1000)"));
        assert!(result.contains("vault_withdraw(500)"));
        assert!(result.contains("property_totalSupply()"));
    }

    #[test]
    fn test_render_assertion_test() {
        let txs = vec![make_tx(
            "vault_deposit",
            vec![DynSolValue::Uint(U256::from(42u64), 256)],
            (0, 0),
        )];

        let ctx = ReproContext {
            test_type: &TestType::AssertionTest {
                auto_detect: false,
                signature: (
                    "vault_deposit(uint256)".into(),
                    vec!["uint256".into()],
                ),
                addr: Address::ZERO,
            },
            value: &TestValue::NoValue,
            reproducer: &txs,
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("function test_vault_deposit_uint256__"));
        assert!(result.contains("vault_deposit(42)"));
        // Assertion tests should NOT append a tail property call
        assert!(!result.contains("vault_deposit(uint256)();"));
    }

    #[test]
    fn test_render_optimization_test() {
        let txs = vec![make_tx(
            "handler_swap",
            vec![DynSolValue::Uint(U256::from(999u64), 256)],
            (0, 0),
        )];

        let ctx = ReproContext {
            test_type: &TestType::OptimizationTest {
                name: "echidna_opt_profit".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::IntValue(I256::try_from(12345i64).unwrap()),
            reproducer: &txs,
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("function test_echidna_opt_profit_opt_12345_"));
        assert!(result.contains("// optimization value: 12345"));
        assert!(result.contains("echidna_opt_profit()"));
    }

    #[test]
    fn test_render_no_delays_omitted() {
        let txs = vec![make_tx(
            "do_something",
            vec![DynSolValue::Bool(true)],
            (0, 0),
        )];

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "prop".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &txs,
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(!result.contains("vm.warp"));
        assert!(!result.contains("vm.roll"));
        assert!(result.contains("do_something(true)"));
    }

    #[test]
    fn test_render_payable_value() {
        let mut tx = make_tx(
            "deposit",
            vec![],
            (0, 0),
        );
        tx.value = U256::from(1_000_000_000_000_000_000u64); // 1 ether

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "prop".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &[tx],
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("deposit{value: 1000000000000000000}()"));
    }

    #[test]
    fn test_render_nocall_delay_only() {
        let tx = Tx {
            call: TxCall::NoCall,
            src: Address::ZERO,
            dst: Address::ZERO,
            gas: 12_500_000,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay: (3600, 10),
            generate_calls_seed: None,
            generate_calls: Vec::new(),
        };

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "prop".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &[tx],
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("vm.warp(block.timestamp + 3600)"));
        assert!(result.contains("vm.roll(block.number + 10)"));
    }

    #[test]
    fn test_render_calldata_tx() {
        let tx = Tx {
            call: TxCall::SolCalldata(vec![0xde, 0xad, 0xbe, 0xef].into()),
            src: Address::ZERO,
            dst: Address::ZERO,
            gas: 12_500_000,
            gasprice: U256::ZERO,
            value: U256::ZERO,
            delay: (0, 0),
            generate_calls_seed: None,
            generate_calls: Vec::new(),
        };

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "prop".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &[tx],
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("address(this).call(hex"));
        assert!(result.contains("deadbeef"));
    }

    #[test]
    fn test_render_array_args() {
        let txs = vec![make_tx(
            "batch_transfer",
            vec![
                DynSolValue::Array(vec![
                    DynSolValue::Address(Address::ZERO),
                    DynSolValue::Address(Address::ZERO),
                ]),
                DynSolValue::Array(vec![
                    DynSolValue::Uint(U256::from(100u64), 256),
                    DynSolValue::Uint(U256::from(200u64), 256),
                ]),
            ],
            (0, 0),
        )];

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "prop".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &txs,
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("address[] memory batch_transfer_arg0 = new address[](2)"));
        assert!(result.contains("uint256[] memory batch_transfer_arg1 = new uint256[](2)"));
        assert!(result.contains("batch_transfer(batch_transfer_arg0, batch_transfer_arg1)"));
    }

    #[test]
    fn test_render_multiple_args() {
        let txs = vec![make_tx(
            "swap",
            vec![
                DynSolValue::Address(Address::ZERO),
                DynSolValue::Uint(U256::from(500u64), 256),
                DynSolValue::Bool(false),
                DynSolValue::Int(I256::try_from(-1i64).unwrap(), 256),
            ],
            (0, 0),
        )];

        let ctx = ReproContext {
            test_type: &TestType::PropertyTest {
                name: "prop".into(),
                addr: Address::ZERO,
            },
            value: &TestValue::BoolValue(false),
            reproducer: &txs,
            abi: None,
        };

        let result = render_test_function(&ctx).unwrap();
        assert!(result.contains("swap(address(0x0000000000000000000000000000000000000000), 500, false, -1)"));
    }
}
