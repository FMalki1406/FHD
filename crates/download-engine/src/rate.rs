//! Conservative pacing of consumed response bytes, not a wire/OS traffic meter.
use std::{num::NonZeroU64, time::Duration};

pub(super) const MAX_BYTES_PER_SECOND: u64 = 1024 * 1024 * 1024;
const MAX_SLICE_BYTES: u64 = 64 * 1024;

pub(super) fn valid_limit(limit: Option<u64>) -> bool {
    limit.is_none_or(|rate| (1..=MAX_BYTES_PER_SECOND).contains(&rate))
}

pub(super) struct BodyPacing {
    rate: Option<NonZeroU64>,
}

impl BodyPacing {
    pub(super) fn new(limit: Option<u64>) -> Result<Self, crate::Error> {
        if !valid_limit(limit) {
            return Err(crate::Error::InvalidOptions);
        }
        Ok(Self {
            rate: limit.and_then(NonZeroU64::new),
        })
    }

    pub(super) fn slice_bytes(&self) -> usize {
        self.rate.map_or(MAX_SLICE_BYTES, |rate| {
            (rate.get() / 10).clamp(1, MAX_SLICE_BYTES)
        }) as usize
    }

    // Every slice pays its complete delay before writing. There is deliberately
    // no credit from network/disk stalls, and no catch-up burst after idle time.
    // u32 byte count times 1e9 fits u64, even beyond our 64 KiB slice bound.
    pub(super) fn delay(&self, bytes: u32) -> Option<Duration> {
        self.rate.map(|rate| {
            Duration::from_nanos((u64::from(bytes) * 1_000_000_000).div_ceil(rate.get()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_and_slice_sizes_are_bounded() {
        assert!(BodyPacing::new(Some(0)).is_err());
        assert!(BodyPacing::new(Some(MAX_BYTES_PER_SECOND + 1)).is_err());
        assert!(BodyPacing::new(Some(u64::MAX)).is_err());
        for (rate, size) in [
            (1, 1),
            (9, 1),
            (10, 1),
            (1000, 100),
            (MAX_BYTES_PER_SECOND, 65536),
        ] {
            assert_eq!(BodyPacing::new(Some(rate)).unwrap().slice_bytes(), size);
        }
        let unlimited = BodyPacing::new(None).unwrap();
        assert_eq!(unlimited.slice_bytes(), 65536);
        assert_eq!(unlimited.delay(65536), None);
    }

    #[test]
    fn each_slice_is_charged_with_upward_rounding_without_saved_credit() {
        let pacing = BodyPacing::new(Some(3)).unwrap();
        assert_eq!(pacing.delay(1), Some(Duration::from_nanos(333_333_334)));
        assert_eq!(pacing.delay(1), Some(Duration::from_nanos(333_333_334)));
        assert_eq!(pacing.delay(3), Some(Duration::from_secs(1)));
        assert_eq!(
            BodyPacing::new(Some(1)).unwrap().delay(u32::MAX),
            Some(Duration::from_secs(u64::from(u32::MAX)))
        );
        assert_eq!(
            BodyPacing::new(Some(MAX_BYTES_PER_SECOND))
                .unwrap()
                .delay(65536),
            Some(Duration::from_nanos(61_036))
        );
    }
}
