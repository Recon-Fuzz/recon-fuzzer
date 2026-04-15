//! Adaptive rate limiter for RPC calls

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Adaptive rate limiter for RPC calls - backs off on 429 errors
/// Uses Arc internally so Clone is cheap and shares state
#[derive(Debug, Clone)]
pub struct RateLimiter {
    inner: Arc<RateLimiterInner>,
}

#[derive(Debug)]
struct RateLimiterInner {
    /// Current delay between RPC calls (adaptive)
    current_delay: Mutex<Duration>,
    /// Minimum delay (starting point)
    min_delay: Duration,
    /// Maximum delay (cap)
    max_delay: Duration,
    /// Last RPC call timestamp
    last_call: Mutex<Instant>,
    /// Total RPC calls made
    call_count: AtomicUsize,
    /// Total 429 errors encountered
    rate_limit_count: AtomicUsize,
}

impl RateLimiter {
    pub fn new(min_interval: Duration) -> Self {
        Self {
            inner: Arc::new(RateLimiterInner {
                current_delay: Mutex::new(min_interval),
                min_delay: min_interval,
                max_delay: Duration::from_millis(500), // Cap at 500ms
                last_call: Mutex::new(Instant::now() - min_interval),
                call_count: AtomicUsize::new(0),
                rate_limit_count: AtomicUsize::new(0),
            }),
        }
    }

    /// Wait if needed to respect rate limit
    pub fn wait_if_needed(&self) {
        let delay = *self.inner.current_delay.lock().unwrap();
        let mut last = self.inner.last_call.lock().unwrap();
        let elapsed = last.elapsed();
        if elapsed < delay {
            std::thread::sleep(delay - elapsed);
        }
        *last = Instant::now();
        self.inner.call_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Called when we get a 429 error - increase delay
    pub fn on_rate_limited(&self) {
        self.inner.rate_limit_count.fetch_add(1, Ordering::Relaxed);
        let mut delay = self.inner.current_delay.lock().unwrap();
        // Double the delay, but cap at max
        let new_delay = (*delay * 2).min(self.inner.max_delay);
        if new_delay > *delay {
            tracing::warn!(
                "Rate limited! Increasing RPC delay from {:?} to {:?}",
                *delay,
                new_delay
            );
        }
        *delay = new_delay;
    }

    /// Called on successful request - gradually decrease delay
    pub fn on_success(&self) {
        let mut delay = self.inner.current_delay.lock().unwrap();
        // Decrease by 10%, but not below minimum
        let new_delay = (*delay * 9 / 10).max(self.inner.min_delay);
        *delay = new_delay;
    }

    /// Get total RPC calls made
    pub fn total_calls(&self) -> usize {
        self.inner.call_count.load(Ordering::Relaxed)
    }

    /// Create a conservative rate limiter for public RPCs (50ms = 20 calls/sec)
    pub fn for_public_rpc() -> Self {
        Self::new(Duration::from_millis(50))
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Default: Start with 10ms delay, adapt based on errors
        Self::new(Duration::from_millis(10))
    }
}
