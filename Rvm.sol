// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// slither-disable-start shadowing-local

/// Recon extended VM interface — storage hooks for direct state access.
/// Use alongside Foundry's Vm for standard cheatcodes.
interface IRvm {
    // ===================================================================
    // vm.loadVar — read storage by variable name or packed extraction
    // ===================================================================

    /// Read a variable by dot-separated path (e.g. "x", "config.fee", "nested.data.amount").
    /// Requires storage layout registered for the target address.
    function loadVar(address target, string calldata path) external returns (bytes32);

    /// Read a variable by path with ABI-encoded mapping/array keys.
    /// Keys are consumed left-to-right at each mapping/array dimension.
    /// Example: loadVar(addr, "balances", abi.encode(user))
    function loadVar(address target, string calldata path, bytes calldata keys) external returns (bytes32);

    /// Raw packed extraction: read `size` bytes at byte `offset` from `slot`.
    /// Returns right-aligned in bytes32. No storage layout needed.
    function loadVar(address target, bytes32 slot, uint8 offset, uint8 size) external returns (bytes32);

    // ===================================================================
    // vm.storeVar — write storage by variable name or packed insertion
    // ===================================================================

    /// Write a variable by dot-separated path.
    /// Value is right-aligned bytes32; for packed fields only the relevant bits are written.
    function storeVar(address target, string calldata path, bytes32 value) external;

    /// Write a variable by path with ABI-encoded mapping/array keys.
    function storeVar(address target, string calldata path, bytes calldata keys, bytes32 value) external;

    /// Raw packed write: write `size` bytes at byte `offset` in `slot`.
    /// Reads the slot, masks out the old bits, inserts the new value, writes back.
    function storeVar(address target, bytes32 slot, uint8 offset, uint8 size, bytes32 value) external;

    // ===================================================================
    // Layout registration
    // ===================================================================

    /// Register a storage layout for a target address.
    /// Accepts solc JSON format or compact format:
    ///   JSON:    '{"storage":[...],"types":{...}}'
    ///   Compact: "uint256 a, (uint128 lo, bool flag) config, mapping(address => uint256) balances"
    function registerStorageLayout(address target, string calldata layout_) external;

    /// Assign a compiled contract's storage layout to an address by name.
    /// Looks up "Vault" or "src/Vault.sol:Vault" from compiled artifacts.
    function assignStorageLayout(address target, string calldata contractName) external;

    /// Register a namespaced storage layout (ERC-7201).
    /// Computes the base slot from the namespace string and offsets all members.
    /// After registration, use loadVar(target, "ns.field") to read.
    function registerNamespace(address target, string calldata ns, string calldata layout_) external;

    /// Register a namespaced storage layout at a manual base slot.
    function registerNamespace(address target, uint256 baseSlot, string calldata layout_) external;
}

IRvm constant rvm = IRvm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

// slither-disable-end shadowing-local
