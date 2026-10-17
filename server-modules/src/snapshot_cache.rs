//! Publication scheduling and immutable snapshots, independent of CSI freshness.
use std::sync::{Arc, Mutex};

const PUBLICATION_INTERVAL_NS: u64 = 100_000_000;

/// Readers hold a cheap immutable handle; deep copies and destruction stay
/// outside the mutex used by the processing thread to publish its next snapshot.
pub struct SnapshotCache<T> {
    current: Mutex<Arc<T>>,
}

impl<T> SnapshotCache<T> {
    pub fn new(value: T) -> Self {
        Self {
            current: Mutex::new(Arc::new(value)),
        }
    }

    pub fn load(&self) -> Arc<T> {
        Arc::clone(&self.current.lock().unwrap())
    }

    pub fn publish(&self, value: T) {
        // The caller constructs value before entering this function. Allocation
        // and the displaced value's potentially expensive final drop also stay
        // outside the critical section.
        let next = Arc::new(value);
        let previous = {
            let mut current = self.current.lock().unwrap();
            std::mem::replace(&mut *current, next)
        };
        drop(previous);
    }
}

/// Space publication work from its completion, never catch up missed intervals.
/// This clock schedules work only; it never changes source/event timestamps.
pub struct PublicationSchedule {
    completed_at_ns: u64,
}

impl PublicationSchedule {
    pub fn new(initial_ns: u64) -> Self {
        Self {
            completed_at_ns: initial_ns,
        }
    }

    pub fn publish_if_due(
        &mut self,
        now_ns: u64,
        publish: impl FnOnce(),
        completion_clock: impl FnOnce() -> u64,
    ) -> bool {
        if !now_ns
            .checked_sub(self.completed_at_ns)
            .is_some_and(|elapsed| elapsed >= PUBLICATION_INTERVAL_NS)
        {
            return false;
        }
        publish();
        // Include construction, lock waiting, replacement and final destruction
        // in the completed work before starting the next minimum interval.
        self.completed_at_ns = completion_clock();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruview_server_modules::engine::{age_snapshot, Stamp, FRESH_NS};
    use serde_json::json;
    use std::{
        cell::Cell,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Weak,
        },
    };

    #[test]
    fn delayed_publication_starts_its_interval_after_250ms_work() {
        let clock = Cell::new(100_000_000);
        let calls = Cell::new(0);
        let mut schedule = PublicationSchedule::new(0);
        assert!(schedule.publish_if_due(
            clock.get(),
            || {
                calls.set(calls.get() + 1);
                clock.set(clock.get() + 250_000_000);
            },
            || clock.get(),
        ));
        for now in [350_000_000, 400_000_000, 449_999_999] {
            assert!(!schedule.publish_if_due(
                now,
                || calls.set(calls.get() + 1),
                || panic!("completion clock must not run without publication"),
            ));
        }
        assert_eq!(calls.get(), 1);
        assert!(schedule.publish_if_due(
            450_000_000,
            || calls.set(calls.get() + 1),
            || 450_000_000,
        ));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn late_loop_publishes_once_without_catching_up_missed_intervals() {
        let calls = Cell::new(0);
        let mut schedule = PublicationSchedule::new(0);
        assert!(schedule.publish_if_due(
            900_000_000,
            || calls.set(calls.get() + 1),
            || 950_000_000,
        ));
        for now in [949_999_999, 950_000_000, 1_000_000_000, 1_049_999_999] {
            assert!(!schedule.publish_if_due(now, || calls.set(calls.get() + 1), || now,));
        }
        assert_eq!(calls.get(), 1);
        assert!(schedule.publish_if_due(
            2_000_000_000,
            || calls.set(calls.get() + 1),
            || 2_000_000_000,
        ));
        assert!(!schedule.publish_if_due(
            2_000_000_000,
            || calls.set(calls.get() + 1),
            || 2_000_000_000,
        ));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn retained_reader_keeps_old_snapshot_immutable_across_publication() {
        let before = json!({"events":[{"occurrence_seq":"17","observed_at_ns":"123"}]});
        let after = json!({"events":[{"occurrence_seq":"18","observed_at_ns":"456"}]});
        let cache = SnapshotCache::new(before.clone());
        let old = cache.load();
        cache.publish(after.clone());
        let new = cache.load();
        assert!(!Arc::ptr_eq(&old, &new));
        assert_eq!(*old, before);
        assert_eq!(*new, after);
    }

    #[test]
    fn response_aging_copy_preserves_shared_event_identity_and_source_times() {
        let observed = 100_000_000u64;
        let event = json!({"occurrence_seq":"17","observed_at_ns":"123",
            "observed_monotonic_ns":observed.to_string(),"fresh":true});
        let original = json!({
            "nodes":[{"node_id":2,"last_received_at_ns":"123",
                "last_received_monotonic_ns":observed.to_string(),"fresh":true,
                "algorithms":[{"availability":"running"}]}],
            "events":[event.clone()],
            "fleet":{"availability":"running","observed_at_ns":"123",
                "observed_monotonic_ns":observed.to_string(),"fresh":true,
                "events":[event]}
        });
        let cache = SnapshotCache::new(original.clone());
        let cached = cache.load();
        let mut response = cached.as_ref().clone();
        age_snapshot(
            &mut response,
            Stamp {
                utc_ns: 10_000_000_000,
                mono_ns: observed + FRESH_NS + 1,
            },
        );
        assert_eq!(response["nodes"][0]["fresh"], false);
        assert_eq!(response["events"][0]["fresh"], false);
        assert_eq!(response["fleet"]["availability"], "stale");
        assert_eq!(response["fleet"]["events"][0]["fresh"], false);
        for key in ["occurrence_seq", "observed_at_ns", "observed_monotonic_ns"] {
            assert_eq!(response["events"][0][key], original["events"][0][key]);
            assert_eq!(
                response["fleet"]["events"][0][key],
                original["fleet"]["events"][0][key]
            );
        }
        assert_eq!(*cache.load(), original);
        assert!(Arc::ptr_eq(&cache.load(), &cached));
    }

    #[test]
    fn displaced_value_is_destroyed_after_mutex_release_and_before_completion() {
        struct DropProbe {
            cache: Weak<SnapshotCache<DropProbe>>,
            lock_was_free: Arc<AtomicBool>,
            drops: Arc<AtomicUsize>,
        }
        impl Drop for DropProbe {
            fn drop(&mut self) {
                if let Some(cache) = self.cache.upgrade() {
                    self.lock_was_free
                        .store(cache.current.try_lock().is_ok(), Ordering::SeqCst);
                    self.drops.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let lock_was_free = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let cache: Arc<SnapshotCache<DropProbe>> = Arc::new_cyclic(|weak| {
            SnapshotCache::new(DropProbe {
                cache: weak.clone(),
                lock_was_free: lock_was_free.clone(),
                drops: drops.clone(),
            })
        });
        let mut schedule = PublicationSchedule::new(0);
        assert!(schedule.publish_if_due(
            PUBLICATION_INTERVAL_NS,
            || cache.publish(DropProbe {
                cache: Weak::new(),
                lock_was_free: lock_was_free.clone(),
                drops: drops.clone(),
            }),
            || {
                assert!(lock_was_free.load(Ordering::SeqCst));
                assert_eq!(drops.load(Ordering::SeqCst), 1);
                PUBLICATION_INTERVAL_NS
            },
        ));
    }
}
