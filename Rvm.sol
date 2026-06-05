// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Vm.sol";

// slither-disable-start shadowing-local

/// Recon extended VM interface — inherits all Foundry cheatcodes and adds
/// storage hooks for direct state access by variable name.
interface IRvm is Vm {
    // ===================================================================
    // loadVar — read storage by variable name or packed extraction
    // ===================================================================

    /// Read a variable by dot-separated path (e.g. "x", "config.fee", "nested.data.amount").
    function loadVar(address target, string calldata path) external returns (bytes32);

    /// Read a variable by path with ABI-encoded mapping/array keys.
    function loadVar(address target, string calldata path, bytes calldata keys) external returns (bytes32);

    /// Raw packed extraction: read `size` bytes at byte `offset` from `slot`.
    function loadVar(address target, bytes32 slot, uint8 offset, uint8 size) external returns (bytes32);

    // ===================================================================
    // storeVar — write storage by variable name or packed insertion
    // ===================================================================

    /// Write a variable by dot-separated path.
    function storeVar(address target, string calldata path, bytes32 value) external;

    /// Write a variable by path with ABI-encoded mapping/array keys.
    function storeVar(address target, string calldata path, bytes calldata keys, bytes32 value) external;

    /// Raw packed write: write `size` bytes at byte `offset` in `slot`.
    function storeVar(address target, bytes32 slot, uint8 offset, uint8 size, bytes32 value) external;

    // ===================================================================
    // Layout registration
    // ===================================================================

    /// Register a storage layout (solc JSON or compact format).
    function registerStorageLayout(address target, string calldata layout_) external;

    /// Assign a compiled contract's layout to an address by name.
    function assignStorageLayout(address target, string calldata contractName) external;

    /// Register a namespaced layout (ERC-7201).
    function registerNamespace(address target, string calldata ns, string calldata layout_) external;

    /// Register a namespaced layout at a manual base slot.
    function registerNamespace(address target, uint256 baseSlot, string calldata layout_) external;
}

/// Global instance bound to the HEVM cheatcode address.
/// Includes all Foundry Vm cheatcodes + Recon storage hooks.
IRvm constant vm = IRvm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

// slither-disable-end shadowing-local
