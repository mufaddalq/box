//! Kernel refusals the box observed, rate-limited into telemetry.
//!
//! A workload chooses how often it is refused, so the box records the first refusal under each
//! key at once, counts repeats, and caps how many keys it tracks. Every notification is still
//! answered: the limit drops records, never responses.

// Wired into the launches in the next commit.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// What one refusal is grouped under.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RefusalKey {
    pub(crate) executable: String,
    pub(crate) syscall: String,
    pub(crate) arguments: Option<String>,
}

/// What the limiter decided for one refusal.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    /// Emit a record standing for this call and `suppressed` earlier ones.
    Record { suppressed: u64 },
    /// The key cap just filled: emit the one overflow notice.
    Overflow,
    /// Counted, not emitted.
    Nothing,
}

/// What remains to emit when the box stops.
#[derive(Debug, Default)]
pub(crate) struct Drained {
    /// Each key's count since its last record, in key order, zero counts left out.
    pub(crate) pending: Vec<(RefusalKey, u64)>,
    /// Refusals under keys past the cap.
    pub(crate) overflow: u64,
}

#[derive(Debug)]
struct Window {
    opened: Instant,
    count: u64,
}

/// One box's refusal limiter, shared by every launch in it.
#[derive(Debug)]
pub(crate) struct RefusalLimiter {
    window: Duration,
    cap: usize,
    keys: HashMap<RefusalKey, Window>,
    overflow: u64,
}

impl RefusalLimiter {
    /// How long repeats under one key are only counted.
    pub(crate) const WINDOW: Duration = Duration::from_secs(10);
    /// How many distinct keys one box tracks.
    pub(crate) const CAP: usize = 256;

    pub(crate) fn new(window: Duration, cap: usize) -> Self {
        Self {
            window,
            cap,
            keys: HashMap::new(),
            overflow: 0,
        }
    }

    pub(crate) fn admit(&mut self, key: &RefusalKey, now: Instant) -> Admit {
        if let Some(window) = self.keys.get_mut(key) {
            if now.saturating_duration_since(window.opened) < self.window {
                window.count += 1;
                return Admit::Nothing;
            }
            let suppressed = window.count;
            *window = Window {
                opened: now,
                count: 0,
            };
            return Admit::Record { suppressed };
        }
        if self.keys.len() < self.cap {
            self.keys.insert(
                key.clone(),
                Window {
                    opened: now,
                    count: 0,
                },
            );
            return Admit::Record { suppressed: 0 };
        }
        self.overflow += 1;
        if self.overflow == 1 {
            Admit::Overflow
        } else {
            Admit::Nothing
        }
    }

    pub(crate) fn drain(&mut self) -> Drained {
        let mut pending: Vec<(RefusalKey, u64)> = self
            .keys
            .iter_mut()
            .filter(|(_, window)| window.count > 0)
            .map(|(key, window)| (key.clone(), std::mem::take(&mut window.count)))
            .collect();
        pending.sort();
        Drained {
            pending,
            overflow: std::mem::take(&mut self.overflow),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn key(syscall: &str) -> RefusalKey {
        RefusalKey {
            executable: "/bin/x".into(),
            syscall: syscall.into(),
            arguments: None,
        }
    }

    #[test]
    fn the_first_refusal_under_a_key_is_recorded_at_once() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        assert_eq!(
            limiter.admit(&key("bpf"), Instant::now()),
            Admit::Record { suppressed: 0 }
        );
    }

    #[test]
    fn repeats_inside_the_window_are_counted_and_carried_by_the_next_record() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        let start = Instant::now();
        limiter.admit(&key("bpf"), start);
        for second in 1..=5 {
            assert_eq!(
                limiter.admit(&key("bpf"), start + Duration::from_secs(second)),
                Admit::Nothing
            );
        }
        assert_eq!(
            limiter.admit(&key("bpf"), start + Duration::from_secs(11)),
            Admit::Record { suppressed: 5 }
        );
        assert_eq!(
            limiter.admit(&key("bpf"), start + Duration::from_secs(12)),
            Admit::Nothing
        );
    }

    #[test]
    fn records_and_suppressed_counts_sum_to_every_call() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        let start = Instant::now();
        let mut total = 0u64;
        for call in 0..100_000u64 {
            if let Admit::Record { suppressed } =
                limiter.admit(&key("socket"), start + Duration::from_micros(call * 3))
            {
                total += 1 + suppressed;
            }
        }
        for (_, pending) in limiter.drain().pending {
            total += 1 + (pending - 1);
        }
        assert_eq!(total, 100_000);
    }

    #[test]
    fn past_the_cap_a_new_key_announces_overflow_once_and_is_counted() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 2);
        let now = Instant::now();
        assert_eq!(
            limiter.admit(&key("a"), now),
            Admit::Record { suppressed: 0 }
        );
        assert_eq!(
            limiter.admit(&key("b"), now),
            Admit::Record { suppressed: 0 }
        );
        assert_eq!(limiter.admit(&key("c"), now), Admit::Overflow);
        assert_eq!(limiter.admit(&key("d"), now), Admit::Nothing);
        assert_eq!(limiter.admit(&key("c"), now), Admit::Nothing);
        // A key admitted before the cap keeps working.
        assert_eq!(limiter.admit(&key("a"), now), Admit::Nothing);
        let drained = limiter.drain();
        assert_eq!(drained.overflow, 3);
        assert_eq!(drained.pending, vec![(key("a"), 1)]);
    }

    #[test]
    fn drain_reports_only_nonzero_counts_and_resets_them() {
        let mut limiter = RefusalLimiter::new(Duration::from_secs(10), 256);
        let now = Instant::now();
        limiter.admit(&key("a"), now);
        limiter.admit(&key("b"), now);
        limiter.admit(&key("b"), now);
        assert_eq!(limiter.drain().pending, vec![(key("b"), 1)]);
        assert!(limiter.drain().pending.is_empty());
    }
}
