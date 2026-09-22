//! The single authority for what one origin may be asked to do (§8): how many
//! connections at once, and when it may be approached again after it pushed back.
//! Fixed caps and a deterministic backoff; no adaptive ramp until it is measured.
//! Accounting only — it never sleeps, never talks to the network, and holds its lock
//! across no await, so a stuck job cannot stall the scheduler.
use fhd_app::transport::OriginId;
use std::{collections::HashMap, sync::Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidLimits;

#[derive(Clone, Copy, Debug)]
pub struct OriginLimits {
    /// Connections one origin may carry across all jobs.
    pub connections: usize,
    /// Consecutive failures tolerated before the origin is stood down.
    pub failures_before_pause: u32,
    /// First stand-down; doubles per further failure up to `maximum_pause_ms`.
    pub pause_ms: u64,
    /// Also the ceiling on a delay the server itself asks for: a hostile or broken
    /// `Retry-After` must not park a job for years.
    pub maximum_pause_ms: u64,
}
impl Default for OriginLimits {
    fn default() -> Self {
        Self {
            connections: 8,
            failures_before_pause: 3,
            pause_ms: 1_000,
            maximum_pause_ms: 300_000,
        }
    }
}
impl OriginLimits {
    fn valid(&self) -> bool {
        (1..=64).contains(&self.connections)
            && self.failures_before_pause >= 1
            && self.pause_ms > 0
            && (self.pause_ms..=86_400_000).contains(&self.maximum_pause_ms)
    }
}

#[derive(Default)]
struct State {
    in_flight: usize,
    failures: u32,
    /// Our own doing: backoff after failures, cleared as soon as bytes arrive.
    backoff_until: u64,
    /// The server's own instruction. Bytes arriving for one job do not licence
    /// ignoring a delay the origin asked every caller to observe.
    floor_until: u64,
}
impl State {
    fn ready_at(&self) -> u64 {
        self.backoff_until.max(self.floor_until)
    }
    fn settled(&self, now_ms: u64) -> bool {
        self.in_flight == 0 && self.failures == 0 && self.ready_at() <= now_ms
    }
}

pub struct OriginGovernor {
    limits: OriginLimits,
    origins: Mutex<HashMap<OriginId, State>>,
}

impl OriginGovernor {
    pub fn new(limits: OriginLimits) -> Result<Self, InvalidLimits> {
        if !limits.valid() {
            return Err(InvalidLimits);
        }
        Ok(Self {
            limits,
            origins: Mutex::new(HashMap::new()),
        })
    }
    pub fn limits(&self) -> OriginLimits {
        self.limits
    }

    /// Grants up to `want` connections, or nothing while the origin is standing down
    /// or already at its cap. The caller holds the grant until it calls `release`.
    pub fn admit(&self, origin: OriginId, want: usize, now_ms: u64) -> usize {
        let mut origins = self.origins.lock().unwrap();
        let state = origins.entry(origin).or_default();
        if now_ms < state.ready_at() {
            return 0;
        }
        let grant = want.min(self.limits.connections.saturating_sub(state.in_flight));
        state.in_flight += grant;
        grant
    }

    /// Returns a grant. An origin with no grant, no failures and no stand-down left
    /// is forgotten, so a long run does not accumulate a row per URL ever visited.
    pub fn release(&self, origin: OriginId, granted: usize, now_ms: u64) {
        let mut origins = self.origins.lock().unwrap();
        let Some(state) = origins.get_mut(&origin) else {
            return;
        };
        state.in_flight = state.in_flight.saturating_sub(granted);
        if state.settled(now_ms) {
            origins.remove(&origin);
        }
    }

    /// The origin served bytes: our backoff no longer applies. A delay the server
    /// asked for stands until it expires — one job's success does not revoke it.
    pub fn succeeded(&self, origin: OriginId, now_ms: u64) {
        let mut origins = self.origins.lock().unwrap();
        let Some(state) = origins.get_mut(&origin) else {
            return;
        };
        state.failures = 0;
        state.backoff_until = 0;
        if state.settled(now_ms) {
            origins.remove(&origin);
        }
    }

    /// 429 or 503. The server's own delay is a floor, never shortened by backoff,
    /// and never longer than `maximum_pause_ms`.
    pub fn throttled(&self, origin: OriginId, retry_after_ms: Option<u64>, now_ms: u64) {
        let mut origins = self.origins.lock().unwrap();
        let state = origins.entry(origin).or_default();
        state.failures = state.failures.saturating_add(1);
        if let Some(asked) = retry_after_ms {
            let asked = asked.min(self.limits.maximum_pause_ms);
            state.floor_until = state.floor_until.max(now_ms.saturating_add(asked));
        }
        let ours = now_ms.saturating_add(self.pause_for(state.failures));
        state.backoff_until = state.backoff_until.max(ours);
    }

    /// A connection failure. Isolated ones are tolerated; a run of them stands the
    /// origin down, so a dead host cannot be hammered by every job that wants it.
    pub fn failed(&self, origin: OriginId, now_ms: u64) {
        let mut origins = self.origins.lock().unwrap();
        let state = origins.entry(origin).or_default();
        state.failures = state.failures.saturating_add(1);
        if state.failures >= self.limits.failures_before_pause {
            let pause = self.pause_for(state.failures - self.limits.failures_before_pause + 1);
            state.backoff_until = state.backoff_until.max(now_ms.saturating_add(pause));
        }
    }

    /// When this origin may be approached again, if it is standing down now. The
    /// scheduler sleeps to exactly this moment instead of polling.
    pub fn ready_at(&self, origin: OriginId, now_ms: u64) -> Option<u64> {
        let origins = self.origins.lock().unwrap();
        origins
            .get(&origin)
            .map(State::ready_at)
            .filter(|at| *at > now_ms)
    }

    fn pause_for(&self, failures: u32) -> u64 {
        let shift = failures.saturating_sub(1).min(31);
        self.limits
            .pause_ms
            .saturating_mul(1u64 << shift)
            .min(self.limits.maximum_pause_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin(tag: u8) -> OriginId {
        let mut bytes = [0; 16];
        bytes[0] = tag;
        OriginId::new(bytes)
    }
    fn governor() -> OriginGovernor {
        OriginGovernor::new(OriginLimits {
            connections: 4,
            failures_before_pause: 2,
            pause_ms: 1_000,
            maximum_pause_ms: 60_000,
        })
        .unwrap()
    }

    #[test]
    fn limits_that_could_never_admit_or_never_pause_are_refused() {
        for limits in [
            OriginLimits {
                connections: 0,
                ..OriginLimits::default()
            },
            OriginLimits {
                pause_ms: 0,
                ..OriginLimits::default()
            },
            OriginLimits {
                failures_before_pause: 0,
                ..OriginLimits::default()
            },
            OriginLimits {
                pause_ms: 10_000,
                maximum_pause_ms: 1_000,
                ..OriginLimits::default()
            },
        ] {
            assert_eq!(OriginGovernor::new(limits).err(), Some(InvalidLimits));
        }
    }

    #[test]
    fn grants_are_capped_per_origin_and_returned_on_release() {
        let governor = governor();
        assert_eq!(governor.admit(origin(1), 3, 0), 3);
        // The cap counts every job on the origin, not each job on its own.
        assert_eq!(governor.admit(origin(1), 3, 0), 1);
        assert_eq!(governor.admit(origin(1), 1, 0), 0);
        // A different origin has its own budget.
        assert_eq!(governor.admit(origin(2), 4, 0), 4);
        governor.release(origin(1), 4, 0);
        assert_eq!(governor.admit(origin(1), 4, 0), 4);
    }

    #[test]
    fn a_servers_retry_after_is_a_floor_that_backoff_never_shortens() {
        let governor = governor();
        governor.throttled(origin(1), Some(30_000), 1_000);
        assert_eq!(governor.admit(origin(1), 1, 1_000), 0);
        assert_eq!(governor.ready_at(origin(1), 1_000), Some(31_000));
        assert_eq!(governor.admit(origin(1), 1, 30_999), 0);
        assert_eq!(governor.admit(origin(1), 1, 31_000), 1);
    }

    #[test]
    fn a_preposterous_retry_after_cannot_park_an_origin_past_the_ceiling() {
        let governor = governor();
        governor.throttled(origin(1), Some(u64::MAX), 1_000);
        assert_eq!(governor.ready_at(origin(1), 1_000), Some(61_000));
    }

    #[test]
    fn bytes_for_one_job_do_not_revoke_a_delay_the_server_asked_of_everyone() {
        let governor = governor();
        governor.throttled(origin(1), Some(30_000), 0);
        governor.succeeded(origin(1), 0);
        // Our own backoff is spent, but the server's instruction still stands.
        assert_eq!(governor.ready_at(origin(1), 0), Some(30_000));
        assert_eq!(governor.admit(origin(1), 1, 29_999), 0);
        assert_eq!(governor.admit(origin(1), 1, 30_000), 1);
    }

    #[test]
    fn throttling_without_a_delay_backs_off_and_doubles_to_the_cap() {
        let governor = OriginGovernor::new(OriginLimits {
            connections: 4,
            failures_before_pause: 2,
            pause_ms: 1_000,
            maximum_pause_ms: 8_000,
        })
        .unwrap();
        for (round, expected) in [(1, 1_000), (2, 2_000), (3, 4_000), (4, 8_000), (5, 8_000)] {
            governor.throttled(origin(1), None, round * 100_000);
            assert_eq!(
                governor.ready_at(origin(1), round * 100_000),
                Some(round * 100_000 + expected)
            );
        }
    }

    #[test]
    fn isolated_failures_are_tolerated_but_a_run_stands_the_origin_down() {
        let governor = governor();
        governor.failed(origin(1), 0);
        assert_eq!(governor.ready_at(origin(1), 0), None);
        assert_eq!(governor.admit(origin(1), 1, 0), 1);
        governor.failed(origin(1), 0);
        assert_eq!(governor.ready_at(origin(1), 0), Some(1_000));
        // Bytes arrived: the history is spent, and the origin is usable at once.
        governor.succeeded(origin(1), 0);
        assert_eq!(governor.ready_at(origin(1), 0), None);
        governor.failed(origin(1), 0);
        assert_eq!(governor.ready_at(origin(1), 0), None);
    }

    /// In the order the scheduler uses them: release the grant, then report success.
    #[test]
    fn an_origin_with_nothing_outstanding_is_forgotten_either_way_round() {
        let governor = governor();
        for succeed_first in [false, true] {
            let grant = governor.admit(origin(9), 2, 0);
            governor.failed(origin(9), 0);
            if succeed_first {
                governor.succeeded(origin(9), 0);
                governor.release(origin(9), grant, 0);
            } else {
                governor.release(origin(9), grant, 0);
                governor.succeeded(origin(9), 0);
            }
            assert!(
                governor.origins.lock().unwrap().is_empty(),
                "a settled origin kept a row (succeed_first={succeed_first})"
            );
        }
    }
}
