//! Tests for EVM execution

use alloy_primitives::{Address, U256};
use revm::Database;

use crate::types::{Tx, TxCall, TxResult, INITIAL_BLOCK_NUMBER, INITIAL_TIMESTAMP};

use super::EvmState;

#[test]
fn test_evm_state_creation() {
    let state = EvmState::new();
    assert_eq!(state.block_number, INITIAL_BLOCK_NUMBER);
    assert_eq!(state.timestamp, INITIAL_TIMESTAMP);
}

#[test]
fn test_fund_account() {
    let mut state = EvmState::new();
    let addr = Address::repeat_byte(0x42);
    state.fund_account(addr, U256::from(1000));

    let balance = state.db.basic(addr).ok().flatten().map(|a| a.balance);
    assert_eq!(balance, Some(U256::from(1000)));
}

#[test]
fn test_nonce_increment() {
    let mut state = EvmState::new();
    let addr = Address::repeat_byte(0x42);

    assert_eq!(state.get_nonce(addr), 0);
    state.increment_nonce(addr);
    assert_eq!(state.get_nonce(addr), 1);
}

#[test]
fn test_no_call_tx() {
    let mut state = EvmState::new();
    let tx = Tx {
        call: TxCall::NoCall,
        src: Address::ZERO,
        dst: Address::ZERO,
        gas: 100000,
        gasprice: U256::ZERO,
        value: U256::ZERO,
        delay: (10, 5),
        generate_calls_seed: None,
        generate_calls: Vec::new(),
    };

    let initial_timestamp = state.timestamp;
    let initial_block = state.block_number;

    let result = state.exec_tx(&tx).unwrap();
    assert_eq!(result, TxResult::Stop);
    assert_eq!(state.timestamp, initial_timestamp + 10);
    assert_eq!(state.block_number, initial_block + 5);
}
