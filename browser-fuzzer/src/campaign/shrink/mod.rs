//! Test shrinking module
//!
//! Matches main fuzzer's campaign/src/shrink/ structure.
//! Contains core shrinking logic (sequence reduction, sender shrinking, etc.)

mod core;

// Re-export all public items
pub use core::{
    calculate_delay_complexity, can_shrink_tx, generate_call_to_delay_candidates,
    generate_delay_candidates, lower_u64, multi_shorten_seq, remove_useless_no_calls,
    shrink_sender, shorten_seq,
};
