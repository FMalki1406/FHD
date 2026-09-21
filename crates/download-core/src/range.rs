//! Nonempty half-open byte ranges with checked conversions.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    start: u64,
    end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeError {
    EmptyOrReversed,
    Overflow,
    SplitOutsideInterior,
}

impl ByteRange {
    pub fn new(start: u64, end_exclusive: u64) -> Result<Self, RangeError> {
        if start >= end_exclusive {
            return Err(RangeError::EmptyOrReversed);
        }
        Ok(Self {
            start,
            end: end_exclusive,
        })
    }

    pub fn from_start_and_length(start: u64, length: u64) -> Result<Self, RangeError> {
        let end = start.checked_add(length).ok_or(RangeError::Overflow)?;
        Self::new(start, end)
    }

    /// HTTP inclusive endpoints cannot represent a half-open endpoint above u64::MAX.
    pub fn from_inclusive(start: u64, end: u64) -> Result<Self, RangeError> {
        let end = end.checked_add(1).ok_or(RangeError::Overflow)?;
        Self::new(start, end)
    }

    pub fn start(self) -> u64 {
        self.start
    }
    pub fn end_exclusive(self) -> u64 {
        self.end
    }
    pub fn length(self) -> u64 {
        self.end - self.start
    }
    pub fn inclusive_end(self) -> u64 {
        self.end - 1
    }

    /// Exactly two nonempty, adjacent ranges; no allocation proportional to input.
    pub fn split_at(self, offset: u64) -> Result<(Self, Self), RangeError> {
        if offset <= self.start || offset >= self.end {
            return Err(RangeError::SplitOutsideInterior);
        }
        Ok((
            Self {
                start: self.start,
                end: offset,
            },
            Self {
                start: offset,
                end: self.end,
            },
        ))
    }
}

impl std::fmt::Display for RangeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::EmptyOrReversed => "range must be nonempty and ordered",
            Self::Overflow => "range endpoint exceeds supported size",
            Self::SplitOutsideInterior => "split must be strictly inside range",
        })
    }
}
impl std::error::Error for RangeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_and_overflowing_ranges() {
        assert_eq!(ByteRange::new(1, 1), Err(RangeError::EmptyOrReversed));
        assert_eq!(ByteRange::new(2, 1), Err(RangeError::EmptyOrReversed));
        assert_eq!(
            ByteRange::from_start_and_length(0, 0),
            Err(RangeError::EmptyOrReversed)
        );
        assert_eq!(
            ByteRange::from_start_and_length(u64::MAX, 1),
            Err(RangeError::Overflow)
        );
        assert_eq!(
            ByteRange::from_inclusive(0, u64::MAX),
            Err(RangeError::Overflow)
        );
    }

    #[test]
    fn splitting_preserves_coverage_and_never_overlaps() {
        for start in 0..20 {
            for length in 2..30 {
                let range = ByteRange::from_start_and_length(start, length).unwrap();
                for cut in (start + 1)..range.end_exclusive() {
                    let (left, right) = range.split_at(cut).unwrap();
                    assert_eq!(left.start(), start);
                    assert_eq!(left.end_exclusive(), right.start());
                    assert_eq!(right.end_exclusive(), range.end_exclusive());
                    assert_eq!(left.length() + right.length(), length);
                }
                for cut in [0, start, range.end_exclusive(), u64::MAX] {
                    assert_eq!(range.split_at(cut), Err(RangeError::SplitOutsideInterior));
                }
            }
        }
    }

    #[test]
    fn largest_supported_endpoint_and_single_byte_roundtrip() {
        let range = ByteRange::from_inclusive(u64::MAX - 1, u64::MAX - 1).unwrap();
        assert_eq!(range.length(), 1);
        assert_eq!(range.end_exclusive(), u64::MAX);
        assert_eq!(range.inclusive_end(), u64::MAX - 1);
        assert_eq!(ByteRange::new(0, u64::MAX).unwrap().length(), u64::MAX);
    }
}
