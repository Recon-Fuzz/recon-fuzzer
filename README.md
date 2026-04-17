# Recon Fuzzer

A high-performance smart contract fuzzer for Foundry projects, written in Rust. Echidna-inspired, with coverage-guided mutation, automatic shrinking, and parallel workers.

## Features

- **Fast & parallel** — multi-threaded fuzzing with configurable worker count
- **Multiple test modes** — property, assertion, optimization, exploration
- **Coverage-guided** — tracks per-instruction or per-branch coverage
- **ABI-aware mutation** — smart corpus-based mutation driven by contract ABI
- **Automatic shrinking** — minimizes failing sequences for reproducible reports
- **Forking** — run against live chain state via RPC
- **Echidna-compatible corpus** — share `echidna.yaml` and corpora between Recon and Echidna

## Installation

### Via reconup (recommended)

[`reconup`](https://github.com/Recon-Fuzz/reconup) is the official installer and updater. Install it once with:

```bash
curl -L https://raw.githubusercontent.com/Recon-Fuzz/reconup/refs/heads/main/install | bash
```

Then restart your shell (or `source ~/.zshrc` / `source ~/.bashrc`) and install `recon`:

```bash
reconup
```

**Updating** — run `reconup` again. It only downloads if a newer release is available.

**Supported platforms** — Linux x86_64, macOS ARM64 (Apple Silicon), macOS x86_64 (Intel), Windows x86_64. On Windows, run `reconup` from Git Bash or WSL.

**Install location** — `~/.recon/bin/recon`.

**Uninstall** — `rm -rf ~/.recon`, then remove the PATH export from your shell profile.

### Pre-built binaries (manual)

If you'd rather skip `reconup`, download directly from the [Releases](https://github.com/Recon-Fuzz/recon-fuzzer/releases) page:

```bash
# Linux x86_64
wget https://github.com/Recon-Fuzz/recon-fuzzer/releases/latest/download/recon-linux-x86_64.tar.gz
tar -xzf recon-linux-x86_64.tar.gz && sudo mv recon /usr/local/bin/

# macOS Apple Silicon
wget https://github.com/Recon-Fuzz/recon-fuzzer/releases/latest/download/recon-macos-aarch64.tar.gz
tar -xzf recon-macos-aarch64.tar.gz && sudo mv recon /usr/local/bin/
```

### Build from source

Requires Rust 1.70+.

```bash
git clone https://github.com/Recon-Fuzz/recon-fuzzer.git
cd recon-fuzzer
cargo build --release
# binary at target/release/recon
```

## Quick start

```bash
recon fuzz /path/to/foundry/project
recon fuzz . --contract MyContract --workers 8 --test-limit 100000
```

## Commands

The CLI has one subcommand: `fuzz`. Everything else happens through flags.

```
recon fuzz [OPTIONS] <PROJECT>
```

### `<PROJECT>`

Path to a Foundry project (directory containing `foundry.toml`). Recon compiles it with `forge build` and picks a target contract.

### Common options

| Flag | Description |
|---|---|
| `-c, --contract <NAME>` | Contract to fuzz (defaults to first) |
| `--config <FILE>` | YAML config file (CLI flags override) |
| `-w, --workers <N>` | Number of parallel worker threads |
| `--test-limit <N>` | Total test iterations across all workers (default: 50000) |
| `--seq-len <N>` | Calls per sequence (default: 100) |
| `--seed <N>` | Deterministic RNG seed |
| `--timeout <SEC>` | Wall-clock timeout |
| `--stop-on-fail` | Exit as soon as any test fails |
| `-q, --quiet` | Reduce log verbosity |

### Test modes

```
--test-mode property       # functions prefixed with echidna_ returning bool
--test-mode assertion      # detect assert() failures
--test-mode optimization   # maximize int return value of echidna_opt_* functions
--test-mode exploration    # coverage-only, no assertions
```

Examples below.

### Addresses and senders

```
--contract-addr <0x...>    # deployment address (default 0x00a329c0648769a73afac7f9381e08fb43dbea72)
--deployer <0x...>         # deployer address (default 0x30000)
--sender <0x...>           # sender to cycle through (repeatable)
--all-contracts            # generate calls to every deployed contract, not just the target
--mutable-only             # skip pure/view functions
```

### Forking

```
--rpc-url <URL>
--rpc-block <N>
```

### Coverage & performance

| Flag | Description |
|---|---|
| `--coverage-mode full\|branch` | `full` tracks every opcode, `branch` only JUMPI/JUMPDEST (faster) |
| `--fast` | Alias for `--coverage-mode branch` |
| `--lcov` | Emit LCOV coverage report during the run |

### Corpus management

| Flag | Description |
|---|---|
| `--corpus-dir <DIR>` | Corpus directory (shared format with Echidna) |
| `--recon-corpus-dir <DIR>` | Recon-native corpus directory (see below) |
| `--shrink` | Skip fuzzing; only shrink existing reproducers in the corpus |
| `--replay <FILE>` | Replay one reproducer file and print traces |
| `--convert` | Convert Recon corpus to Echidna format and exit |

### Other

| Flag | Description |
|---|---|
| `--format text\|json\|none` | Output format for the final report |
| `--shortcuts` | Run `shortcut_*` functions at startup to bootstrap the corpus |
| `--shrink-limit <N>` | Shrink attempts per failing test (default: 5000) |

## Web UI (experimental)

Recon ships an optional browser UI for watching a campaign live. Pass `--web` to a `recon fuzz` run:

```bash
recon fuzz . --web
```

> **Experimental.** This is still rough — not all features are wired up and the frontend is under active development. Treat it as an early preview, not a finished product. The CLI remains the supported way to run campaigns.

## Configuration file

Recon understands the Echidna-style `echidna.yaml`. CLI flags override file values.

```yaml
testMode: property
prefix: echidna_
corpusDir: corpus
testLimit: 50000
shrinkLimit: 5000
seqLen: 100
workers: 4
timeout: 86400
stopOnFail: false
contractAddr: "0x00a329c0648769a73afac7f9381e08fb43dbea72"
deployer: "0x30000"
sender:
  - "0x10000"
  - "0x20000"
  - "0x30000"
rpcUrl: "https://eth-mainnet.alchemyapi.io/v2/..."
rpcBlock: 18000000
allContracts: false
mutableOnly: false
lcovEnable: false
coverageMode: full
shortcutsEnable: false
```

```bash
recon fuzz . --config echidna.yaml
```

## Test mode examples

### Property

```solidity
contract Vault {
    uint256 public balance;

    function echidna_balance_never_negative() public view returns (bool) {
        return balance >= 0;
    }
}
```
```bash
recon fuzz . --test-mode property --contract Vault
```

### Assertion

```solidity
function transfer(uint256 amount) public {
    assert(amount <= balance);
    balance -= amount;
}
```
```bash
recon fuzz . --test-mode assertion --contract Vault
```

### Optimization

```solidity
function echidna_opt_balance() public view returns (int256) {
    return int256(balance);
}
```
```bash
recon fuzz . --test-mode optimization --contract Vault
```

### Exploration

Pure coverage exploration, no property checks:

```bash
recon fuzz . --test-mode exploration
```

## Sharing corpus with Echidna

Recon can interoperate with an Echidna corpus so you can alternate between the two tools without regenerating inputs.

### Recon ↔ Echidna layout

Echidna reads/writes plaintext reproducers under `corpusDir`. Recon's native format is richer (priorities, delay pairs, selector map). To keep both happy:

```
project/
├── echidna.yaml                 # shared config (corpusDir: corpus/)
├── corpus/                      # Echidna-format corpus (shared)
└── corpus-recon/                # Recon-native corpus
```

### Two corpora at once (recommended)

Point Recon at its own dir via `--recon-corpus-dir`. It fuzzes using the native format and **auto-exports** every new corpus entry to `--corpus-dir` (or `corpusDir:` in the config) in Echidna format:

```bash
recon fuzz . \
  --config echidna.yaml \
  --recon-corpus-dir corpus-recon
```

Run Echidna afterwards and it picks up the exported entries from `corpus/`.

### One-shot conversion

To convert an existing Recon corpus to Echidna format without fuzzing, add `--convert`:

```bash
recon fuzz . \
  --config echidna.yaml \
  --recon-corpus-dir corpus-recon \
  --convert
```

Recon exits after exporting. The Echidna-format files land in `corpus/` (or whatever `corpusDir` resolves to).

### Using an Echidna corpus from Recon

Point `--corpus-dir` (or `corpusDir:`) at the existing Echidna corpus without `--recon-corpus-dir`. Recon reads the Echidna-format reproducers directly.

```bash
recon fuzz . --corpus-dir ./echidna/corpus
```

## Replaying and shrinking

```bash
# Replay a saved reproducer and dump the trace
recon fuzz . --replay corpus/reproducers/failure_001.txt

# Re-shrink every reproducer in the corpus without running the fuzzer
recon fuzz . --corpus-dir corpus --shrink
```

## Troubleshooting

**"Contract not found"** — make sure `forge build` succeeds first.

**"Failed to compile project"** — Recon expects a standard Foundry layout with `foundry.toml`.

**Slow iterations** — try `--fast` (branch-only coverage), lower `--seq-len`, or raise `--workers`.

## Browser fuzzer (WebAssembly)

`browser-fuzzer/` is an experimental WebAssembly build of the fuzzer that runs entirely in the browser — no server, no backend. It shares the core engine with the CLI. Requires **Rust nightly** to build (uses `#![feature(thread_local)]` for multi-worker shared memory).

```bash
cd browser-fuzzer
cargo +nightly build --target wasm32-unknown-unknown --release
```

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GPL-2.0. See [LICENSE](LICENSE).

## Acknowledgments

Huge thanks to the **[Crytic](https://github.com/crytic)** team for [Echidna](https://github.com/crytic/echidna). Recon is heavily inspired by Echidna's design — the testing modes, corpus format, and many implementation details trace directly back to their work. This project would not exist without it.

Also built on top of:

- [revm](https://github.com/bluealloy/revm) — EVM execution
- [alloy](https://github.com/alloy-rs/alloy) — Ethereum primitives
- [Foundry](https://github.com/foundry-rs/foundry) — project compilation

## Disclaimer

Large portions of this codebase were written with the assistance of AI coding tools ("vibe coding"). The maintainers have reviewed and exercised the code but cannot guarantee correctness, completeness, or security of every path. **Use at your own risk.** No warranty is provided — see the [LICENSE](LICENSE) for details. Do not rely on Recon as the sole line of defense when auditing production contracts; always combine it with independent review, established tools, and human judgment.

## Support

- Issues: https://github.com/Recon-Fuzz/recon-fuzzer/issues
- Discord: https://discord.gg/47eCfmbC
