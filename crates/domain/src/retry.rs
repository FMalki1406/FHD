use crate::DomainError;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    Transient,
    Throttled,
    UserAction,
    Integrity,
    Fatal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryDecision {
    RetryAt(u64),
    NeedsAction,
    Exhausted,
}
#[derive(Clone, Copy, Debug)]
pub struct RetryPolicy {
    maximum_attempts: u8,
    base_delay: u64,
    maximum_delay: u64,
}
impl RetryPolicy {
    pub fn new(
        maximum_attempts: u8,
        base_delay: u64,
        maximum_delay: u64,
    ) -> Result<Self, DomainError> {
        if !(1..=32).contains(&maximum_attempts)
            || base_delay == 0
            || maximum_delay < base_delay
            || maximum_delay > 86_400_000
        {
            return Err(DomainError::InvalidInput);
        }
        Ok(Self {
            maximum_attempts,
            base_delay,
            maximum_delay,
        })
    }
    /// `now` and Retry-After deadline share an injected monotonic millisecond clock.
    /// `jitter` must be supplied by the caller; no clock or RNG is read here.
    pub fn decide(
        self,
        class: ErrorClass,
        attempts: u8,
        now: u64,
        retry_after_deadline: Option<u64>,
        jitter: u64,
    ) -> Result<RetryDecision, DomainError> {
        if attempts == 0 {
            return Err(DomainError::InvalidInput);
        }
        if matches!(
            class,
            ErrorClass::UserAction | ErrorClass::Integrity | ErrorClass::Fatal
        ) {
            return Ok(RetryDecision::NeedsAction);
        }
        if attempts >= self.maximum_attempts {
            return Ok(RetryDecision::Exhausted);
        }
        let cap = self
            .base_delay
            .saturating_mul(1u64 << u32::from(attempts.saturating_sub(1).min(31)))
            .min(self.maximum_delay);
        let delay = jitter % (cap + 1);
        let at = now.checked_add(delay).ok_or(DomainError::Overflow)?;
        Ok(RetryDecision::RetryAt(
            at.max(retry_after_deadline.unwrap_or(now)),
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_backoff_never_undercuts_server_deadline() {
        let p = RetryPolicy::new(5, 100, 800).unwrap();
        for attempt in 1..5 {
            for jitter in 0..1000 {
                let RetryDecision::RetryAt(at) = p
                    .decide(ErrorClass::Throttled, attempt, 1000, Some(5000), jitter)
                    .unwrap()
                else {
                    panic!("expected retry")
                };
                assert_eq!(at, 5000);
            }
        }
        assert_eq!(
            p.decide(ErrorClass::Transient, 5, 0, None, 0).unwrap(),
            RetryDecision::Exhausted
        );
        assert_eq!(
            p.decide(ErrorClass::Integrity, 1, 0, None, 0).unwrap(),
            RetryDecision::NeedsAction
        );
        assert_eq!(
            p.decide(ErrorClass::Transient, 1, u64::MAX, None, 1),
            Err(DomainError::Overflow)
        );
    }
}
