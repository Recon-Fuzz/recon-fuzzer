//! Tracing module
//!
//! Provides execution tracing capabilities:
//! - TracingInspector for capturing detailed execution traces
//! - TraceDecoder for Foundry-style trace formatting
//! - Storage change tracking and formatting

mod decoder;
mod inspector;

// Re-export all public items from decoder (Foundry-style trace formatting)
pub use decoder::{
    compute_partial_codehash, create_tracing_inspector, decode_revert_reason,
    extract_created_contracts, extract_created_contracts_with_codehash, extract_labels_from_traces,
    extract_storage_changes, format_storage_changes, format_storage_changes_with_labels,
    format_traces, format_traces_decoded, format_traces_decoded_with_state, CallTraceArena,
    DecodedCallData, TraceConfig, TraceDecoder, TraceWriter, TraceWriterConfig,
};

// Re-export all public items from inspector (execution trace capture)
pub use inspector::{ExecutionTrace, TraceStep, TracingInspector};
