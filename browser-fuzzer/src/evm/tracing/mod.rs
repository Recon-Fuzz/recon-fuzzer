//! Tracing module for browser-fuzzer
//!
//! Uses revm-inspectors' TracingInspector and CallTraceArena directly,
//! matching the main fuzzer's tracing pipeline:
//! 1. Run transaction with TracingInspector to collect CallTraceArena
//! 2. Use TraceDecoder to populate `decoded` fields on each CallTraceNode
//! 3. Use TraceWriter to render the decoded traces

pub mod decoder;

use alloy_primitives::{Address, Log};
use revm_inspectors::tracing::{
    TracingInspector as RevmTracingInspector, TracingInspectorConfig,
};
use serde::Serialize;

pub use revm_inspectors::tracing::CallTraceArena;

/// Create a new TracingInspector configured for call-level tracing with state diffs
pub fn create_tracing_inspector() -> RevmTracingInspector {
    RevmTracingInspector::new(
        TracingInspectorConfig::default_parity()
            .with_state_diffs()
            .record_logs(),
    )
}

/// Execution result carrying both metadata and the full CallTraceArena.
/// The arena is used for Foundry-style trace formatting via TraceWriter.
pub struct ExecResult {
    pub success: bool,
    pub gas_used: u64,
    pub output: Vec<u8>,
    pub deployed_address: Option<Address>,
    pub error: Option<String>,
    /// Full call trace arena from revm-inspectors (for TraceWriter formatting)
    pub arena: CallTraceArena,
    /// Raw logs for assertion checking
    pub raw_logs: Vec<Log>,
    /// Storage diffs from this tx
    pub state_changes: Vec<StateChange>,
}

/// Storage change entry (used for state diff tracking and JSON export)
#[derive(Serialize, Clone, Debug)]
pub struct StateChange {
    pub address: String,
    pub slot: String,
    pub old_value: String,
    pub new_value: String,
}

/// Serializable trace result for WASM JSON export (WasmEvm low-level API).
/// Produced from ExecResult by converting the arena to a simple call tree.
#[derive(Serialize, Clone, Debug)]
pub struct TraceResultJson {
    pub success: bool,
    pub gas_used: u64,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployed_address: Option<String>,
    pub calls: Vec<CallTraceJson>,
    pub logs: Vec<LogEntryJson>,
    pub state_changes: Vec<StateChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct CallTraceJson {
    pub from: String,
    pub to: String,
    pub input: String,
    pub output: String,
    pub value: String,
    pub gas_used: u64,
    pub success: bool,
    pub call_type: String,
    pub children: Vec<CallTraceJson>,
}

#[derive(Serialize, Clone, Debug)]
pub struct LogEntryJson {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

/// Convert an ExecResult to a JSON-serializable TraceResultJson for WASM export
pub fn exec_result_to_json(result: &ExecResult) -> TraceResultJson {
    // Convert arena nodes to a simple call tree
    let calls = arena_to_call_tree(&result.arena);

    // Extract logs from arena nodes
    let logs: Vec<LogEntryJson> = result.arena.nodes().iter()
        .flat_map(|node| {
            node.logs.iter().map(|log| {
                LogEntryJson {
                    address: format!("{:?}", node.trace.address),
                    topics: log.raw_log.topics().iter().map(|t| format!("{t:?}")).collect(),
                    data: hex::encode(log.raw_log.data.as_ref()),
                }
            })
        })
        .collect();

    TraceResultJson {
        success: result.success,
        gas_used: result.gas_used,
        output: hex::encode(&result.output),
        deployed_address: result.deployed_address.map(|a| format!("{a:?}")),
        calls,
        logs,
        state_changes: result.state_changes.clone(),
        error: result.error.clone(),
    }
}

/// Convert CallTraceArena into a simple nested call tree for JSON serialization
fn arena_to_call_tree(arena: &CallTraceArena) -> Vec<CallTraceJson> {
    let nodes = arena.nodes();
    if nodes.is_empty() {
        return Vec::new();
    }

    // Build tree from arena (arena is flat with parent/children indices)
    fn convert_node(arena: &CallTraceArena, idx: usize) -> CallTraceJson {
        let nodes = arena.nodes();
        let node = &nodes[idx];
        let trace = &node.trace;

        let call_type = if trace.kind.is_any_create() {
            "create"
        } else {
            match trace.kind {
                revm_inspectors::tracing::types::CallKind::DelegateCall => "delegatecall",
                revm_inspectors::tracing::types::CallKind::StaticCall => "staticcall",
                _ => "call",
            }
        };

        let children: Vec<CallTraceJson> = node.children.iter()
            .map(|&child_idx| convert_node(arena, child_idx))
            .collect();

        CallTraceJson {
            from: format!("{:?}", trace.caller),
            to: format!("{:?}", trace.address),
            input: hex::encode(&trace.data),
            output: hex::encode(&trace.output),
            value: format!("{}", trace.value),
            gas_used: trace.gas_used,
            success: trace.success,
            call_type: call_type.to_string(),
            children,
        }
    }

    // Root nodes are those at depth 0 (typically just one)
    nodes.iter().enumerate()
        .filter(|(_, node)| node.parent.is_none())
        .map(|(idx, _)| convert_node(arena, idx))
        .collect()
}
