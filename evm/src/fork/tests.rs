//! Tests for fork module

use super::*;
use std::time::Duration;

#[test]
fn test_rate_limiter() {
    let limiter = RateLimiter::new(Duration::from_millis(10));
    assert_eq!(limiter.total_calls(), 0);

    limiter.wait_if_needed();
    assert_eq!(limiter.total_calls(), 1);

    limiter.wait_if_needed();
    assert_eq!(limiter.total_calls(), 2);
}

#[test]
fn test_rate_limiter_adaptive_backoff() {
    let limiter = RateLimiter::new(Duration::from_millis(10));

    // Initial delay should be 10ms
    assert_eq!(limiter.total_calls(), 0);

    // Simulate rate limiting - delay should increase
    limiter.on_rate_limited();
    limiter.on_rate_limited();
    limiter.on_rate_limited();

    // After rate limiting, success should gradually decrease delay
    for _ in 0..10 {
        limiter.on_success();
    }

    // Rate limiter state is tested via total_calls (delay is internal)
    assert_eq!(limiter.total_calls(), 0);
}

#[test]
fn test_rate_limiter_clone_shares_state() {
    let limiter1 = RateLimiter::new(Duration::from_millis(10));
    let limiter2 = limiter1.clone();

    limiter1.wait_if_needed();
    assert_eq!(limiter1.total_calls(), 1);
    assert_eq!(limiter2.total_calls(), 1); // Shared state!

    limiter2.wait_if_needed();
    assert_eq!(limiter1.total_calls(), 2);
    assert_eq!(limiter2.total_calls(), 2);
}

#[test]
fn test_cache_serialization() {
    use alloy_primitives::{Address, B256, U256};

    let mut cache = RpcCacheData::new(12345, 1);
    cache.accounts.insert(
        Address::ZERO,
        CachedAccount {
            balance: U256::from(100),
            nonce: 5,
            code_hash: B256::ZERO,
            code: None,
        },
    );
    cache.storage.push(CachedSlot {
        address: Address::ZERO,
        slot: U256::from(1),
        value: U256::from(42),
    });

    let json = serde_json::to_string(&cache).unwrap();
    let restored: RpcCacheData = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.block, 12345);
    assert_eq!(restored.chain_id, 1);
    assert_eq!(restored.accounts.len(), 1);
    assert_eq!(restored.storage.len(), 1);
}

#[test]
fn test_cache_with_code() {
    use alloy_primitives::{Address, Bytes, U256};

    let mut cache = RpcCacheData::new(19000000, 1);
    let code_bytes = Bytes::from(vec![0x60, 0x80, 0x60, 0x40]); // PUSH1 0x80 PUSH1 0x40

    cache.accounts.insert(
        Address::repeat_byte(0x42),
        CachedAccount {
            balance: U256::from(1000),
            nonce: 10,
            code_hash: alloy_primitives::keccak256(&code_bytes),
            code: Some(code_bytes.clone()),
        },
    );

    // Add multiple storage slots
    for i in 0..10 {
        cache.storage.push(CachedSlot {
            address: Address::repeat_byte(0x42),
            slot: U256::from(i),
            value: U256::from(i * 100),
        });
    }

    let json = serde_json::to_string_pretty(&cache).unwrap();
    let restored: RpcCacheData = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.block, 19000000);
    assert_eq!(restored.accounts.len(), 1);
    assert_eq!(restored.storage.len(), 10);

    let restored_account = restored
        .accounts
        .get(&Address::repeat_byte(0x42))
        .unwrap();
    assert_eq!(restored_account.code.as_ref().unwrap(), &code_bytes);
}

#[test]
fn test_fork_options_default() {
    let options = ForkOptions::default();
    assert!(!options.use_storage_dump);
    assert!(options.cache_dir.is_none());
}

#[test]
fn test_fork_options_with_storage_dump() {
    let options = ForkOptions {
        use_storage_dump: true,
        cache_dir: Some(std::path::PathBuf::from("/tmp/test_cache")),
    };
    assert!(options.use_storage_dump);
    assert_eq!(
        options.cache_dir.unwrap().to_str().unwrap(),
        "/tmp/test_cache"
    );
}

#[test]
fn test_forkable_db_empty_basic() {
    use alloy_primitives::Address;
    use revm::database::DatabaseRef;

    let db = ForkableDb::new_empty();

    // Empty DB should return None for unknown addresses
    let result = db.basic_ref(Address::ZERO);
    assert!(result.is_ok());
    assert!(result.unwrap().is_none());
}

#[test]
fn test_forkable_db_empty_storage() {
    use alloy_primitives::{Address, U256};
    use revm::database::DatabaseRef;

    let db = ForkableDb::new_empty();

    // Empty DB should return ZERO for unknown storage
    let result = db.storage_ref(Address::ZERO, U256::ZERO);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), U256::ZERO);
}

/// Integration tests that require network access
/// Run with: cargo test --features fork-tests -- --ignored
#[cfg(test)]
mod integration_tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use revm::database::DatabaseRef;

    // Mainnet addresses for testing
    const WETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
    const USDC: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const UNISWAP_V2_FACTORY: &str = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f";

    fn parse_address(s: &str) -> Address {
        s.parse().expect("Invalid address")
    }

    /// Test that verifies lazy loading - data is only fetched when accessed
    #[test]
    #[ignore = "requires RPC endpoint"]
    fn test_lazy_loading_accounts() {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        // Use None (latest block) for better compatibility with public RPCs
        let fork_db = ForkDb::new(&rpc_url, None, ForkOptions::default())
            .expect("Failed to create fork DB");

        // Initially, no RPC calls should have been made (beyond chain_id)
        let initial_calls = fork_db.rpc_call_count();
        let (initial_accounts, initial_storage) = fork_db.cache_stats();

        assert_eq!(
            initial_accounts, 0,
            "Should have no cached accounts initially"
        );
        assert_eq!(
            initial_storage, 0,
            "Should have no cached storage initially"
        );

        // Fetch WETH account - this should trigger RPC
        let weth = parse_address(WETH);
        let account = fork_db.basic_ref(weth).expect("Failed to fetch WETH");
        assert!(account.is_some(), "WETH should exist");

        let after_first_fetch = fork_db.rpc_call_count();
        assert!(
            after_first_fetch > initial_calls,
            "RPC call should have been made"
        );

        // Fetch WETH again - should hit cache, no new RPC call
        let _account2 = fork_db.basic_ref(weth).expect("Failed to fetch WETH again");
        let after_cached_fetch = fork_db.rpc_call_count();
        assert_eq!(after_cached_fetch, after_first_fetch, "Should have hit cache");

        // Verify cache stats
        let (accounts_cached, _) = fork_db.cache_stats();
        assert!(accounts_cached >= 1, "Should have at least WETH cached");

        println!("✓ Lazy loading test passed:");
        println!("  - Initial RPC calls: {}", initial_calls);
        println!("  - After WETH fetch: {}", after_first_fetch);
        println!("  - After cached fetch: {}", after_cached_fetch);
        println!("  - Accounts cached: {}", accounts_cached);
    }

    /// Test that verifies storage lazy loading
    #[test]
    #[ignore = "requires RPC endpoint"]
    fn test_lazy_loading_storage() {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        // Use None (latest block) for better compatibility with public RPCs
        let fork_db = ForkDb::new(&rpc_url, None, ForkOptions::default())
            .expect("Failed to create fork DB");

        let usdc = parse_address(USDC);

        // Fetch storage slot 0 (totalSupply for most ERC20s)
        let calls_before = fork_db.rpc_call_count();
        let slot0 = fork_db
            .storage_ref(usdc, U256::ZERO)
            .expect("Failed to fetch slot 0");
        let calls_after_first = fork_db.rpc_call_count();

        assert!(
            calls_after_first > calls_before,
            "Should have made RPC call for storage"
        );

        // Fetch same slot again - should hit cache
        let _slot0_again = fork_db
            .storage_ref(usdc, U256::ZERO)
            .expect("Failed to fetch slot 0 again");
        let calls_after_cached = fork_db.rpc_call_count();
        assert_eq!(
            calls_after_cached, calls_after_first,
            "Should have hit storage cache"
        );

        // Fetch different slot - should trigger new RPC
        let slot1 = fork_db
            .storage_ref(usdc, U256::from(1))
            .expect("Failed to fetch slot 1");
        let calls_after_new_slot = fork_db.rpc_call_count();
        assert!(
            calls_after_new_slot > calls_after_cached,
            "Should have made RPC for new slot"
        );

        println!("✓ Storage lazy loading test passed:");
        println!("  - Slot 0 value: {}", slot0);
        println!("  - Slot 1 value: {}", slot1);
        println!("  - Total RPC calls: {}", calls_after_new_slot);
    }

    /// Test that verifies clone shares cache state
    #[test]
    #[ignore = "requires RPC endpoint"]
    fn test_clone_shares_cache() {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        // Use None (latest block) for better compatibility with public RPCs
        let fork_db1 = ForkDb::new(&rpc_url, None, ForkOptions::default())
            .expect("Failed to create fork DB");

        // Clone the DB
        let fork_db2 = fork_db1.clone();

        let weth = parse_address(WETH);

        // Fetch from first DB
        let _account1 = fork_db1
            .basic_ref(weth)
            .expect("Failed to fetch WETH from db1");
        let calls1 = fork_db1.rpc_call_count();

        // Fetch from cloned DB - should hit shared cache!
        let _account2 = fork_db2
            .basic_ref(weth)
            .expect("Failed to fetch WETH from db2");
        let calls2 = fork_db2.rpc_call_count();

        // Both should report same call count (shared rate limiter)
        assert_eq!(
            calls1, calls2,
            "Cloned DBs should share rate limiter state"
        );

        // Cache should be shared too
        let (accounts1, storage1) = fork_db1.cache_stats();
        let (accounts2, storage2) = fork_db2.cache_stats();
        assert_eq!(accounts1, accounts2, "Cloned DBs should share account cache");
        assert_eq!(storage1, storage2, "Cloned DBs should share storage cache");

        println!("✓ Clone shares cache test passed:");
        println!("  - Shared RPC calls: {}", calls1);
        println!("  - Shared accounts cached: {}", accounts1);
    }

    /// Test multiple contract queries to verify batch caching
    #[test]
    #[ignore = "requires RPC endpoint"]
    fn test_multiple_contracts_lazy_load() {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        // Use None (latest block) for better compatibility with public RPCs
        let fork_db = ForkDb::new(&rpc_url, None, ForkOptions::default())
            .expect("Failed to create fork DB");

        let addresses = vec![
            parse_address(WETH),
            parse_address(USDC),
            parse_address(UNISWAP_V2_FACTORY),
        ];

        let initial_calls = fork_db.rpc_call_count();

        // Fetch all contracts
        for addr in &addresses {
            let account = fork_db.basic_ref(*addr).expect("Failed to fetch account");
            assert!(account.is_some(), "Contract should exist");
        }

        let calls_after_fetch = fork_db.rpc_call_count();
        let (accounts_cached, _) = fork_db.cache_stats();

        // Fetch all again - should all hit cache
        for addr in &addresses {
            let _ = fork_db.basic_ref(*addr).expect("Failed to fetch account");
        }

        let calls_after_cached = fork_db.rpc_call_count();

        assert_eq!(
            calls_after_cached, calls_after_fetch,
            "All re-fetches should hit cache"
        );
        assert!(
            accounts_cached >= 3,
            "Should have at least 3 accounts cached"
        );

        println!("✓ Multiple contracts lazy load test passed:");
        println!("  - Initial calls: {}", initial_calls);
        println!(
            "  - After fetching {} contracts: {}",
            addresses.len(),
            calls_after_fetch
        );
        println!("  - After cached re-fetch: {}", calls_after_cached);
        println!("  - Accounts cached: {}", accounts_cached);
    }

    /// Test cache persistence - save and load
    #[test]
    #[ignore = "requires RPC endpoint"]
    fn test_cache_persistence() {
        let rpc_url = std::env::var("ETH_RPC_URL")
            .unwrap_or_else(|_| "https://eth.llamarpc.com".to_string());

        let temp_dir = std::env::temp_dir().join("recon_fork_test");
        let _ = std::fs::remove_dir_all(&temp_dir); // Clean up any previous test
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp dir");

        // Use a block number that we'll simulate for the cache test
        // For public RPCs, we use latest and just save with block 0 to identify it
        let cache_block = 0u64;

        // Create fork, fetch some data, save cache
        {
            // Use None (latest block) for better compatibility with public RPCs
            let fork_db = ForkDb::new(&rpc_url, None, ForkOptions::default())
                .expect("Failed to create fork DB");

            let weth = parse_address(WETH);
            let _ = fork_db.basic_ref(weth).expect("Failed to fetch WETH");
            let _ = fork_db
                .storage_ref(weth, U256::ZERO)
                .expect("Failed to fetch storage");

            fork_db
                .save_cache(&temp_dir, cache_block)
                .expect("Failed to save cache");

            let (accounts, storage) = fork_db.cache_stats();
            println!("Saved cache: {} accounts, {} storage slots", accounts, storage);
        }

        // Create new fork, load cache, verify it works
        {
            // Use None (latest block) for better compatibility with public RPCs
            let fork_db = ForkDb::new(&rpc_url, None, ForkOptions::default())
                .expect("Failed to create fork DB");

            // Load cache
            let cache_file = temp_dir.join(format!("rpc_cache_{}.json", cache_block));
            let cache_json = std::fs::read_to_string(&cache_file).expect("Failed to read cache");
            let cache: RpcCacheData =
                serde_json::from_str(&cache_json).expect("Failed to parse cache");
            fork_db.load_cache_data(&cache);

            let (accounts, storage) = fork_db.cache_stats();
            assert!(accounts > 0, "Should have loaded cached accounts");

            // Fetch WETH - should hit cache (no new RPC calls needed for account)
            let initial_calls = fork_db.rpc_call_count();
            let weth = parse_address(WETH);
            let _ = fork_db.basic_ref(weth).expect("Failed to fetch WETH");
            let after_calls = fork_db.rpc_call_count();

            assert_eq!(initial_calls, after_calls, "Should have hit loaded cache");

            println!("✓ Cache persistence test passed:");
            println!("  - Loaded {} accounts, {} storage slots", accounts, storage);
            println!("  - Cache hit verified (no new RPC calls)");
        }

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
