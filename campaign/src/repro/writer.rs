//! Thread-safe Foundry test file writer.
//!
//! Appends rendered test functions to an existing Solidity file. The file must
//! already exist with a contract declaration — this module inserts new functions
//! before the final closing brace.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use alloy_json_abi::JsonAbi;

use crate::testing::EchidnaTest;
use crate::output::format_timestamp;

use super::codegen::{self, ReproContext};

/// Handle for appending Foundry tests to a file.
///
/// Thread-safe: can be shared across worker threads via `Arc`. The inner mutex
/// serializes file writes and the monotonic test counter.
#[derive(Clone)]
pub struct ReproWriter {
    inner: Arc<Mutex<WriterState>>,
}

struct WriterState {
    path: PathBuf,
    abi: Option<JsonAbi>,
}

impl ReproWriter {
    pub fn new(path: PathBuf, abi: Option<JsonAbi>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(WriterState { path, abi })),
        }
    }

    /// Append a Foundry test function for a solved (or improved optimization) test.
    pub fn append_test(&self, test: &EchidnaTest) -> anyhow::Result<()> {
        let state = self.inner.lock().unwrap();

        let ctx = ReproContext {
            test_type: &test.test_type,
            value: &test.value,
            reproducer: &test.reproducer,
            abi: state.abi.as_ref(),
        };

        let rendered = codegen::render_test_function(&ctx)?;
        append_before_last_brace(&state.path, &rendered)?;

        println!(
            "{} Appended test_{} to {}",
            format_timestamp(),
            codegen::test_name_for_log(&ctx),
            state.path.display()
        );

        Ok(())
    }
}

/// Insert `content` just before the last `}` in the file.
///
/// This assumes the file is a valid Solidity contract where the final `}` closes
/// the contract declaration. The inserted block gets a blank line separator.
fn append_before_last_brace(path: &Path, content: &str) -> anyhow::Result<()> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;

    let last_brace = source
        .rfind('}')
        .ok_or_else(|| anyhow::anyhow!("No closing '}}' found in {}", path.display()))?;

    let mut out = String::with_capacity(source.len() + content.len() + 4);
    out.push_str(&source[..last_brace]);
    out.push('\n');
    out.push_str(content);
    out.push('\n');
    out.push_str(&source[last_brace..]);

    std::fs::write(path, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append_before_last_brace() {
        let dir = std::env::temp_dir().join("recon_repro_test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("Test.sol");

        std::fs::write(
            &file,
            "contract Foo is Test {\n    function setUp() public {}\n}\n",
        )
        .unwrap();

        append_before_last_brace(&file, "    function test_x() public {}\n").unwrap();

        let result = std::fs::read_to_string(&file).unwrap();
        assert!(result.contains("test_x"));
        assert!(result.ends_with("}\n"));
        assert_eq!(result.matches('}').count(), 3);

        let _ = std::fs::remove_file(&file);
    }
}
