use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::Instant;

const RATE_LIMIT_SHARDS: usize = 32;

#[derive(Debug)]
pub struct RateLimiter {
    capacity: f32,
    fill_rate: f32,
    shards: [std::sync::Mutex<std::collections::HashMap<IpAddr, TokenBucket>>; RATE_LIMIT_SHARDS],
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f32,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, fill_rate: f32) -> Self {
        Self {
            capacity: capacity as f32,
            fill_rate,
            shards: std::array::from_fn(
                |_| std::sync::Mutex::new(std::collections::HashMap::new()),
            ),
        }
    }

    fn shard_idx(ip: &IpAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % RATE_LIMIT_SHARDS
    }

    pub fn acquire(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let idx = Self::shard_idx(&ip);
        let mut guard = self.shards[idx].lock().unwrap();

        // Very basic bounded memory: if we have more than 1024 IPs in this shard,
        // prune the ones that have fully refilled (plus some margin).
        if guard.len() > 1024 {
            let threshold = (self.capacity / self.fill_rate) * 2.0;
            guard.retain(|_, b| now.duration_since(b.last_update).as_secs_f32() < threshold);

            // If it's still completely full (e.g., active DDoS from unique IPs),
            // just clear the oldest or clear it entirely to prevent OOM.
            if guard.len() > 2048 {
                guard.clear();
            }
        }

        let bucket = guard.entry(ip).or_insert(TokenBucket {
            tokens: self.capacity,
            last_update: now,
        });

        let elapsed = now.duration_since(bucket.last_update).as_secs_f32();
        bucket.tokens += elapsed * self.fill_rate;
        if bucket.tokens > self.capacity {
            bucket.tokens = self.capacity;
        }
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
