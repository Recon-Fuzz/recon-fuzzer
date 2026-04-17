/**
 * Transaction serialization utilities for corpus-compatible JSON format.
 *
 * CRITICAL: This module generates JSON that is BYTE-FOR-BYTE IDENTICAL to
 * Rust's evm::Tx serialization. This ensures:
 * - Sequences created in frontend can be replayed by backend
 * - Manually created shortcuts work with the fuzzer
 * - Corpus files can be generated from frontend
 *
 * The format matches evm/src/types.rs and evm/src/serde_utils.rs exactly.
 *
 * Example corpus entry:
 * ```json
 * {
 *   "call": {
 *     "SolCall": {
 *       "name": "transfer",
 *       "args": [
 *         {"Address": "0x1234567890abcdef1234567890abcdef12345678"},
 *         {"Uint": ["0x64", 256]}
 *       ]
 *     }
 *   },
 *   "src": "0x0000000000000000000000000000000000010000",
 *   "dst": "0x7fa9385be102ac3eac297483dd6233d62b3e1496",
 *   "gas": 30000000,
 *   "gasprice": "0x0",
 *   "value": "0x0",
 *   "delay": [0, 0]
 * }
 * ```
 */

// =============================================================================
// DynSolValue Types (matching Rust's SerializableDynSolValue exactly)
// =============================================================================

/**
 * Matches Rust's SerializableDynSolValue enum from evm/src/serde_utils.rs
 *
 * IMPORTANT: The JSON structure must be exactly:
 * - Bool: {"Bool": true}
 * - Int: {"Int": ["0xhex", bits]}
 * - Uint: {"Uint": ["0xhex", bits]}
 * - FixedBytes: {"FixedBytes": ["0xhex_padded_to_64_chars", size]}
 * - Address: {"Address": "0xlowercase"}
 * - Function: {"Function": number}
 * - Bytes: {"Bytes": [byte, byte, ...]} (array of numbers 0-255)
 * - String: {"String": "value"}
 * - Array: {"Array": [...DynSolValue]}
 * - FixedArray: {"FixedArray": [...DynSolValue]}
 * - Tuple: {"Tuple": [...DynSolValue]}
 */
export type DynSolValue =
  | { Bool: boolean }
  | { Int: [string, number] }        // [hex_value, bits] - I256 as hex
  | { Uint: [string, number] }       // [hex_value, bits] - U256 as hex
  | { FixedBytes: [string, number] } // [hex_64_chars, size] - FixedBytes<32> as hex
  | { Address: string }              // lowercase with 0x prefix
  | { Function: number }
  | { Bytes: number[] }              // array of byte values (0-255)
  | { String: string }
  | { Array: DynSolValue[] }
  | { FixedArray: DynSolValue[] }
  | { Tuple: DynSolValue[] };

// =============================================================================
// TxCall Types (matching Rust's TxCall enum exactly)
// =============================================================================

/**
 * Matches Rust's TxCall enum from evm/src/types.rs
 *
 * Serialization:
 * - SolCreate: {"SolCreate": "0xbytecode"}
 * - SolCall: {"SolCall": {"name": "fn", "args": [...]}}
 * - SolCalldata: {"SolCalldata": "0xcalldata"}
 * - NoCall: "NoCall" (string, not object!)
 */
export type TxCall =
  | { SolCreate: string }                                    // bytecode as hex
  | { SolCall: { name: string; args: DynSolValue[] } }       // function call
  | { SolCalldata: string }                                  // raw calldata as hex
  | 'NoCall';                                                // unit variant = string

// =============================================================================
// Tx Type (matching Rust's Tx struct exactly)
// =============================================================================

/**
 * Matches Rust's Tx struct from evm/src/types.rs
 *
 * Field serialization:
 * - call: TxCall (see above)
 * - src: Address as lowercase hex string "0x..."
 * - dst: Address as lowercase hex string "0x..."
 * - gas: number (u64 in Rust, safe in JS for gas values)
 * - gasprice: U256 as hex string "0x..."
 * - value: U256 as hex string "0x..."
 * - delay: [time_seconds, blocks] as array tuple
 */
export interface Tx {
  call: TxCall;
  src: string;
  dst: string;
  gas: number;
  gasprice: string;
  value: string;
  delay: [number, number];
}

// =============================================================================
// Constants (matching Rust's primitives)
// =============================================================================

export const DEFAULT_GAS = 30000000;
export const ZERO_U256 = '0x0';

// Common sender addresses used by fuzzer
export const SENDERS = {
  SENDER_1: '0x0000000000000000000000000000000000010000',
  SENDER_2: '0x0000000000000000000000000000000000020000',
  SENDER_3: '0x0000000000000000000000000000000000030000',
} as const;

// =============================================================================
// Value Formatting Utilities (CRITICAL for compatibility)
// =============================================================================

/**
 * Format a value as hex string matching Rust's U256/I256 serialization.
 * Rust uses lowercase hex with 0x prefix, no leading zeros except for 0x0.
 */
function formatHex(value: string | number | bigint): string {
  let hex: string;

  if (typeof value === 'string') {
    if (value.startsWith('0x') || value.startsWith('0X')) {
      // Already hex - normalize
      hex = value.slice(2).toLowerCase();
    } else if (value.startsWith('-')) {
      // Negative number - convert to two's complement for I256
      const abs = BigInt(value.slice(1));
      const twosComplement = (BigInt(1) << BigInt(256)) - abs;
      hex = twosComplement.toString(16);
    } else {
      // Decimal string
      hex = BigInt(value).toString(16);
    }
  } else if (typeof value === 'bigint') {
    if (value < 0n) {
      const twosComplement = (BigInt(1) << BigInt(256)) + value;
      hex = twosComplement.toString(16);
    } else {
      hex = value.toString(16);
    }
  } else {
    // number
    hex = Math.abs(value).toString(16);
    if (value < 0) {
      const twosComplement = (BigInt(1) << BigInt(256)) + BigInt(value);
      hex = twosComplement.toString(16);
    }
  }

  // Remove leading zeros but keep at least one digit
  hex = hex.replace(/^0+/, '') || '0';

  return '0x' + hex;
}

/**
 * Format address matching Rust's Address serialization.
 * Lowercase, 0x prefix, 40 hex characters.
 */
function formatAddress(address: string): string {
  let addr = address.toLowerCase();
  if (!addr.startsWith('0x')) {
    addr = '0x' + addr;
  }
  // Ensure 40 hex characters (20 bytes)
  const hex = addr.slice(2).padStart(40, '0');
  return '0x' + hex;
}

/**
 * Format FixedBytes matching Rust's FixedBytes<32> serialization.
 * Always 64 hex characters (32 bytes), right-padded with zeros.
 */
function formatFixedBytes(value: string | number[], size: number): string {
  let hex: string;

  if (typeof value === 'string') {
    hex = value.startsWith('0x') ? value.slice(2) : value;
  } else {
    hex = value.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Rust's FixedBytes<32> is always 32 bytes (64 hex chars), right-padded
  hex = hex.toLowerCase().padEnd(64, '0');

  return '0x' + hex;
}

/**
 * Convert hex string to byte array matching Rust's Vec<u8> serialization.
 */
function hexToByteArray(hex: string): number[] {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  // Ensure even length
  const paddedHex = cleanHex.length % 2 ? '0' + cleanHex : cleanHex;
  const bytes: number[] = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
  }
  return bytes;
}

// =============================================================================
// DynSolValue Constructors (generate exact Rust format)
// =============================================================================

export const DynSol = {
  /**
   * Create a Bool value
   * Serializes as: {"Bool": true} or {"Bool": false}
   */
  bool(value: boolean): DynSolValue {
    return { Bool: value };
  },

  /**
   * Create a Uint value (uint8 to uint256)
   * Serializes as: {"Uint": ["0xhex", bits]}
   *
   * @param value - The value (string, number, or bigint)
   * @param bits - Bit width: 8, 16, 24, 32, ..., 256 (default 256)
   */
  uint(value: string | number | bigint, bits: number = 256): DynSolValue {
    return { Uint: [formatHex(value), bits] };
  },

  /**
   * Create an Int value (int8 to int256)
   * Serializes as: {"Int": ["0xhex", bits]}
   * Negative values are stored as two's complement.
   *
   * @param value - The value (string, number, or bigint)
   * @param bits - Bit width: 8, 16, 24, 32, ..., 256 (default 256)
   */
  int(value: string | number | bigint, bits: number = 256): DynSolValue {
    return { Int: [formatHex(value), bits] };
  },

  /**
   * Create an Address value
   * Serializes as: {"Address": "0xlowercase40chars"}
   */
  address(address: string): DynSolValue {
    return { Address: formatAddress(address) };
  },

  /**
   * Create a dynamic Bytes value
   * Serializes as: {"Bytes": [byte, byte, ...]}
   *
   * @param value - Hex string or byte array
   */
  bytes(value: string | number[]): DynSolValue {
    if (typeof value === 'string') {
      return { Bytes: hexToByteArray(value) };
    }
    return { Bytes: value };
  },

  /**
   * Create a FixedBytes value (bytes1 to bytes32)
   * Serializes as: {"FixedBytes": ["0x64charhex", size]}
   *
   * @param value - Hex string or byte array
   * @param size - Number of bytes (1-32)
   */
  fixedBytes(value: string | number[], size: number): DynSolValue {
    return { FixedBytes: [formatFixedBytes(value, size), size] };
  },

  /**
   * Create a String value
   * Serializes as: {"String": "value"}
   */
  string(value: string): DynSolValue {
    return { String: value };
  },

  /**
   * Create a dynamic Array value
   * Serializes as: {"Array": [...elements]}
   */
  array(elements: DynSolValue[]): DynSolValue {
    return { Array: elements };
  },

  /**
   * Create a fixed-size Array value
   * Serializes as: {"FixedArray": [...elements]}
   */
  fixedArray(elements: DynSolValue[]): DynSolValue {
    return { FixedArray: elements };
  },

  /**
   * Create a Tuple value
   * Serializes as: {"Tuple": [...elements]}
   */
  tuple(elements: DynSolValue[]): DynSolValue {
    return { Tuple: elements };
  },

  /**
   * Create a Function value (rarely used)
   * Serializes as: {"Function": number}
   */
  function(value: number): DynSolValue {
    return { Function: value };
  },
};

// =============================================================================
// Type String Parsing (for convenience)
// =============================================================================

interface ParsedType {
  base: 'uint' | 'int' | 'address' | 'bool' | 'bytes' | 'string' | 'tuple';
  bits?: number;        // for uint/int
  size?: number;        // for fixed bytes
  arrayDims: (number | null)[]; // array dimensions (null = dynamic)
  components?: ParsedType[];    // for tuple
}

function parseTypeString(type: string): ParsedType {
  // Handle array suffixes
  const arrayDims: (number | null)[] = [];
  let baseType = type;

  while (true) {
    const match = baseType.match(/^(.+)\[(\d*)\]$/);
    if (!match) break;
    baseType = match[1];
    arrayDims.unshift(match[2] ? parseInt(match[2]) : null);
  }

  // Handle tuple
  if (baseType.startsWith('(') && baseType.endsWith(')')) {
    const inner = baseType.slice(1, -1);
    const components = parseTupleComponents(inner);
    return { base: 'tuple', components, arrayDims };
  }

  // Handle uint variants
  if (baseType.startsWith('uint')) {
    const bits = parseInt(baseType.slice(4)) || 256;
    return { base: 'uint', bits, arrayDims };
  }

  // Handle int variants
  if (baseType.startsWith('int')) {
    const bits = parseInt(baseType.slice(3)) || 256;
    return { base: 'int', bits, arrayDims };
  }

  // Handle fixed bytes (bytes1 to bytes32)
  if (baseType.startsWith('bytes') && baseType.length > 5) {
    const size = parseInt(baseType.slice(5));
    if (!isNaN(size) && size >= 1 && size <= 32) {
      return { base: 'bytes', size, arrayDims };
    }
  }

  // Handle dynamic bytes
  if (baseType === 'bytes') {
    return { base: 'bytes', arrayDims };
  }

  // Simple types
  if (baseType === 'address') return { base: 'address', arrayDims };
  if (baseType === 'bool') return { base: 'bool', arrayDims };
  if (baseType === 'string') return { base: 'string', arrayDims };

  throw new Error(`Unknown Solidity type: ${type}`);
}

function parseTupleComponents(inner: string): ParsedType[] {
  const components: ParsedType[] = [];
  let depth = 0;
  let current = '';

  for (const char of inner) {
    if (char === '(') {
      depth++;
      current += char;
    } else if (char === ')') {
      depth--;
      current += char;
    } else if (char === ',' && depth === 0) {
      if (current.trim()) {
        components.push(parseTypeString(current.trim()));
      }
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    components.push(parseTypeString(current.trim()));
  }

  return components;
}

function convertToDynSolValue(parsed: ParsedType, value: unknown): DynSolValue {
  // Handle arrays first (outermost)
  if (parsed.arrayDims.length > 0) {
    if (!Array.isArray(value)) {
      throw new Error(`Expected array for ${parsed.base}[], got ${typeof value}`);
    }

    const innerParsed = { ...parsed, arrayDims: parsed.arrayDims.slice(1) };
    const elements = value.map(v => convertToDynSolValue(innerParsed, v));

    // Fixed array if dimension is specified, otherwise dynamic
    const dim = parsed.arrayDims[0];
    if (dim !== null) {
      if (elements.length !== dim) {
        throw new Error(`Array length mismatch: expected ${dim}, got ${elements.length}`);
      }
      return DynSol.fixedArray(elements);
    }
    return DynSol.array(elements);
  }

  // Handle tuple
  if (parsed.base === 'tuple' && parsed.components) {
    if (!Array.isArray(value)) {
      throw new Error(`Expected array for tuple, got ${typeof value}`);
    }
    if (value.length !== parsed.components.length) {
      throw new Error(`Tuple length mismatch: expected ${parsed.components.length}, got ${value.length}`);
    }
    const elements = parsed.components.map((comp, i) => convertToDynSolValue(comp, value[i]));
    return DynSol.tuple(elements);
  }

  // Handle primitives
  switch (parsed.base) {
    case 'uint':
      return DynSol.uint(value as string | number | bigint, parsed.bits ?? 256);
    case 'int':
      return DynSol.int(value as string | number | bigint, parsed.bits ?? 256);
    case 'address':
      return DynSol.address(value as string);
    case 'bool':
      return DynSol.bool(Boolean(value));
    case 'string':
      return DynSol.string(String(value));
    case 'bytes':
      if (parsed.size !== undefined) {
        return DynSol.fixedBytes(value as string | number[], parsed.size);
      }
      return DynSol.bytes(value as string | number[]);
    default:
      throw new Error(`Unsupported type: ${parsed.base}`);
  }
}

/**
 * Convert a value to DynSolValue based on Solidity type string.
 *
 * @example
 * toDynSolValue('uint256', 100)
 * toDynSolValue('address', '0x1234...')
 * toDynSolValue('uint256[]', [1, 2, 3])
 * toDynSolValue('(uint256,address)', [100, '0x1234...'])
 * toDynSolValue('(uint256,address)[]', [[1, '0x...'], [2, '0x...']])
 */
export function toDynSolValue(type: string, value: unknown): DynSolValue {
  const parsed = parseTypeString(type);
  return convertToDynSolValue(parsed, value);
}

// =============================================================================
// Transaction Builders
// =============================================================================

export const TxBuilder = {
  /**
   * Create a function call transaction
   */
  call(params: {
    name: string;
    args: DynSolValue[];
    src: string;
    dst: string;
    value?: string | number | bigint;
    gas?: number;
    delay?: [number, number];
  }): Tx {
    return {
      call: {
        SolCall: {
          name: params.name,
          args: params.args,
        },
      },
      src: formatAddress(params.src),
      dst: formatAddress(params.dst),
      gas: params.gas ?? DEFAULT_GAS,
      gasprice: ZERO_U256,
      value: params.value ? formatHex(params.value) : ZERO_U256,
      delay: params.delay ?? [0, 0],
    };
  },

  /**
   * Create a contract creation transaction
   */
  create(params: {
    bytecode: string;
    src: string;
    dst: string;
    value?: string | number | bigint;
    gas?: number;
    delay?: [number, number];
  }): Tx {
    const bytecode = params.bytecode.startsWith('0x')
      ? params.bytecode
      : '0x' + params.bytecode;
    return {
      call: { SolCreate: bytecode },
      src: formatAddress(params.src),
      dst: formatAddress(params.dst),
      gas: params.gas ?? DEFAULT_GAS,
      gasprice: ZERO_U256,
      value: params.value ? formatHex(params.value) : ZERO_U256,
      delay: params.delay ?? [0, 0],
    };
  },

  /**
   * Create a raw calldata transaction
   */
  calldata(params: {
    data: string;
    src: string;
    dst: string;
    value?: string | number | bigint;
    gas?: number;
    delay?: [number, number];
  }): Tx {
    const data = params.data.startsWith('0x')
      ? params.data
      : '0x' + params.data;
    return {
      call: { SolCalldata: data },
      src: formatAddress(params.src),
      dst: formatAddress(params.dst),
      gas: params.gas ?? DEFAULT_GAS,
      gasprice: ZERO_U256,
      value: params.value ? formatHex(params.value) : ZERO_U256,
      delay: params.delay ?? [0, 0],
    };
  },

  /**
   * Create a delay-only transaction (no call)
   */
  delay(params: {
    src: string;
    dst: string;
    delay: [number, number];
  }): Tx {
    return {
      call: 'NoCall',
      src: formatAddress(params.src),
      dst: formatAddress(params.dst),
      gas: DEFAULT_GAS,
      gasprice: ZERO_U256,
      value: ZERO_U256,
      delay: params.delay,
    };
  },
};

// =============================================================================
// High-Level Convenience Functions
// =============================================================================

/**
 * Build a function call with typed arguments.
 *
 * @example
 * // Simple transfer
 * buildCall('transfer', [
 *   ['address', '0x1234...'],
 *   ['uint256', '1000000000000000000'],
 * ], sender, target);
 *
 * // With tuple argument
 * buildCall('complexFunc', [
 *   ['(uint256,address)', [100, '0x1234...']],
 * ], sender, target);
 *
 * // With array argument
 * buildCall('batchTransfer', [
 *   ['address[]', ['0x1111...', '0x2222...']],
 *   ['uint256[]', [100, 200]],
 * ], sender, target);
 *
 * // With nested types
 * buildCall('complexBatch', [
 *   ['(address,uint256)[]', [
 *     ['0x1111...', 100],
 *     ['0x2222...', 200],
 *   ]],
 * ], sender, target);
 */
export function buildCall(
  name: string,
  args: Array<[string, unknown]>,
  src: string,
  dst: string,
  options?: {
    value?: string | number | bigint;
    gas?: number;
    delay?: [number, number];
  }
): Tx {
  const dynArgs = args.map(([type, value]) => toDynSolValue(type, value));
  return TxBuilder.call({
    name,
    args: dynArgs,
    src,
    dst,
    ...options,
  });
}

/**
 * Build a sequence of transactions.
 *
 * @example
 * const sequence = buildSequence([
 *   {
 *     name: 'approve',
 *     args: [['address', spender], ['uint256', amount]],
 *     src: sender,
 *     dst: token,
 *   },
 *   {
 *     name: 'transferFrom',
 *     args: [['address', from], ['address', to], ['uint256', amount]],
 *     src: sender,
 *     dst: token,
 *   },
 * ]);
 */
export function buildSequence(
  txs: Array<{
    name: string;
    args: Array<[string, unknown]>;
    src: string;
    dst: string;
    value?: string | number | bigint;
    gas?: number;
    delay?: [number, number];
  }>
): Tx[] {
  return txs.map(tx => buildCall(tx.name, tx.args, tx.src, tx.dst, {
    value: tx.value,
    gas: tx.gas,
    delay: tx.delay,
  }));
}

// =============================================================================
// Serialization (generates corpus-compatible JSON)
// =============================================================================

/**
 * Serialize a transaction sequence to JSON.
 * The output is IDENTICAL to Rust's serde_json::to_string for Vec<Tx>.
 */
export function serializeSequence(txs: Tx[]): string {
  return JSON.stringify(txs);
}

/**
 * Serialize with pretty printing (for debugging/display).
 */
export function serializeSequencePretty(txs: Tx[]): string {
  return JSON.stringify(txs, null, 2);
}

/**
 * Parse a transaction sequence from JSON (corpus file format).
 */
export function parseSequence(json: string): Tx[] {
  return JSON.parse(json) as Tx[];
}

// =============================================================================
// Validation Utilities
// =============================================================================

/**
 * Validate that a DynSolValue has the correct structure.
 */
export function validateDynSolValue(value: unknown): value is DynSolValue {
  if (typeof value !== 'object' || value === null) return false;

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);

  if (keys.length !== 1) return false;
  const key = keys[0];

  switch (key) {
    case 'Bool':
      return typeof obj.Bool === 'boolean';
    case 'Uint':
    case 'Int':
      return Array.isArray(obj[key]) &&
        (obj[key] as unknown[]).length === 2 &&
        typeof (obj[key] as unknown[])[0] === 'string' &&
        typeof (obj[key] as unknown[])[1] === 'number';
    case 'FixedBytes':
      return Array.isArray(obj.FixedBytes) &&
        obj.FixedBytes.length === 2 &&
        typeof obj.FixedBytes[0] === 'string' &&
        typeof obj.FixedBytes[1] === 'number';
    case 'Address':
      return typeof obj.Address === 'string' &&
        obj.Address.startsWith('0x') &&
        obj.Address.length === 42;
    case 'Function':
      return typeof obj.Function === 'number';
    case 'Bytes':
      return Array.isArray(obj.Bytes) &&
        obj.Bytes.every(b => typeof b === 'number' && b >= 0 && b <= 255);
    case 'String':
      return typeof obj.String === 'string';
    case 'Array':
    case 'FixedArray':
    case 'Tuple':
      return Array.isArray(obj[key]) &&
        (obj[key] as unknown[]).every(validateDynSolValue);
    default:
      return false;
  }
}

/**
 * Validate that a Tx has the correct structure.
 */
export function validateTx(tx: unknown): tx is Tx {
  if (typeof tx !== 'object' || tx === null) return false;

  const obj = tx as Record<string, unknown>;

  // Check required fields
  if (typeof obj.src !== 'string' || !obj.src.startsWith('0x')) return false;
  if (typeof obj.dst !== 'string' || !obj.dst.startsWith('0x')) return false;
  if (typeof obj.gas !== 'number') return false;
  if (typeof obj.gasprice !== 'string') return false;
  if (typeof obj.value !== 'string') return false;
  if (!Array.isArray(obj.delay) || obj.delay.length !== 2) return false;

  // Check call
  const call = obj.call;
  if (call === 'NoCall') return true;
  if (typeof call !== 'object' || call === null) return false;

  const callObj = call as Record<string, unknown>;
  const callKeys = Object.keys(callObj);
  if (callKeys.length !== 1) return false;

  const callType = callKeys[0];
  if (callType === 'SolCreate' || callType === 'SolCalldata') {
    return typeof callObj[callType] === 'string';
  }
  if (callType === 'SolCall') {
    const solCall = callObj.SolCall as Record<string, unknown>;
    return typeof solCall.name === 'string' &&
      Array.isArray(solCall.args) &&
      solCall.args.every(validateDynSolValue);
  }

  return false;
}

/**
 * Validate a sequence of transactions.
 */
export function validateSequence(txs: unknown): txs is Tx[] {
  return Array.isArray(txs) && txs.every(validateTx);
}
