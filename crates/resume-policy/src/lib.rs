//! Conservative, side-effect-free policy for a single HTTP resume range.
#![forbid(unsafe_code)]

/// Product limit, not an HTTP protocol maximum. Oversized values fail closed.
pub const MAX_FIELD_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    MissingHeader,
    RepeatedHeader,
    FieldTooLarge,
    InvalidNumber,
    InvalidContentRange,
    InvalidStrongEtag,
    InvalidRequestRange,
    RepresentationChanged,
    RangeMismatch,
    LengthMismatch,
    NonIdentityEncoding,
    UnexpectedStatus,
}

/// Preserve duplicates from the HTTP adapter; never select only the first value.
#[derive(Clone, Copy, Default)]
pub enum Field<'a> {
    #[default]
    Missing,
    Single(&'a [u8]),
    Repeated,
}

impl std::fmt::Debug for Field<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "Missing",
            Self::Single(_) => "Single([redacted])",
            Self::Repeated => "Repeated",
        })
    }
}

impl<'a> Field<'a> {
    fn required(self) -> Result<&'a [u8], Error> {
        match self {
            Self::Missing => Err(Error::MissingHeader),
            Self::Repeated => Err(Error::RepeatedHeader),
            Self::Single(value) => bounded(value),
        }
    }
}

fn bounded(value: &[u8]) -> Result<&[u8], Error> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(Error::FieldTooLarge);
    }
    // Only HTTP OWS is removed. CR/LF and Unicode whitespace remain invalid.
    Ok(value.trim_ascii_start_ows().trim_ascii_end_ows())
}

trait Ows {
    fn trim_ascii_start_ows(&self) -> &Self;
    fn trim_ascii_end_ows(&self) -> &Self;
}

impl Ows for [u8] {
    fn trim_ascii_start_ows(&self) -> &Self {
        let start = self
            .iter()
            .position(|b| !matches!(b, b' ' | b'\t'))
            .unwrap_or(self.len());
        &self[start..]
    }

    fn trim_ascii_end_ows(&self) -> &Self {
        let end = self
            .iter()
            .rposition(|b| !matches!(b, b' ' | b'\t'))
            .map_or(0, |i| i + 1);
        &self[..end]
    }
}

fn decimal(value: &[u8]) -> Result<u64, Error> {
    if value.is_empty() {
        return Err(Error::InvalidNumber);
    }
    value.iter().try_fold(0u64, |number, digit| {
        if !digit.is_ascii_digit() {
            return Err(Error::InvalidNumber);
        }
        number
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(digit - b'0')))
            .ok_or(Error::InvalidNumber)
    })
}

/// Parsed strong entity tag. Bytes are compared exactly, with no unescaping.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StrongEtag<'a>(&'a [u8]);

impl<'a> StrongEtag<'a> {
    pub fn parse(value: &'a [u8]) -> Result<Self, Error> {
        let value = bounded(value)?;
        if value.len() < 2 || value.first() != Some(&b'"') || value.last() != Some(&b'"') {
            return Err(Error::InvalidStrongEtag);
        }
        if !value[1..value.len() - 1]
            .iter()
            .all(|b| *b == 0x21 || (0x23..=0x7e).contains(b) || *b >= 0x80)
        {
            return Err(Error::InvalidStrongEtag);
        }
        Ok(Self(value))
    }
}

impl std::fmt::Debug for StrongEtag<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StrongEtag([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentRange {
    Satisfied {
        start: u64,
        end_exclusive: u64,
        total: Option<u64>,
    },
    Unsatisfied {
        total: u64,
    },
}

impl ContentRange {
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        let value = bounded(value)?;
        if value.len() < 7 || !value[..6].eq_ignore_ascii_case(b"bytes ") {
            return Err(Error::InvalidContentRange);
        }
        let mut parts = value[6..].split(|b| *b == b'/');
        let range = parts.next().ok_or(Error::InvalidContentRange)?;
        let total = parts.next().ok_or(Error::InvalidContentRange)?;
        if parts.next().is_some() {
            return Err(Error::InvalidContentRange);
        }
        if range == b"*" {
            return Ok(Self::Unsatisfied {
                total: decimal(total)?,
            });
        }
        let total = if total == b"*" {
            None
        } else {
            Some(decimal(total)?)
        };
        let mut bounds = range.split(|b| *b == b'-');
        let start = decimal(bounds.next().ok_or(Error::InvalidContentRange)?)?;
        let end = decimal(bounds.next().ok_or(Error::InvalidContentRange)?)?;
        if bounds.next().is_some() || start > end || total.is_some_and(|size| end >= size) {
            return Err(Error::InvalidContentRange);
        }
        let end_exclusive = end.checked_add(1).ok_or(Error::InvalidContentRange)?;
        Ok(Self::Satisfied {
            start,
            end_exclusive,
            total,
        })
    }
}

/// A range in an identity-encoded representation, pinned by a strong ETag.
/// Caller must additionally bind origin, final URL, request context and generation.
#[derive(Clone, Copy, Debug)]
pub struct ResumeRequest<'a> {
    start: u64,
    end_exclusive: u64,
    total: u64,
    etag: StrongEtag<'a>,
}

impl<'a> ResumeRequest<'a> {
    pub fn new(
        start: u64,
        end_exclusive: u64,
        total: u64,
        etag: StrongEtag<'a>,
    ) -> Result<Self, Error> {
        if start >= end_exclusive || end_exclusive > total {
            return Err(Error::InvalidRequestRange);
        }
        Ok(Self {
            start,
            end_exclusive,
            total,
            etag,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ResponseHeaders<'a> {
    pub content_range: Field<'a>,
    pub content_length: Field<'a>,
    pub etag: Field<'a>,
    pub content_encoding: Field<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyPermit {
    expected_bytes: u64,
}

impl BodyPermit {
    pub fn expected_bytes(self) -> u64 {
        self.expected_bytes
    }

    /// Only call after clean HTTP framing completion; this does not mark data durable.
    pub fn verify_received_length(self, received: u64) -> Result<(), Error> {
        if received == self.expected_bytes {
            Ok(())
        } else {
            Err(Error::LengthMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Header checks passed; body framing, exact length and durable storage remain required.
    ReadRange(BodyPermit),
    /// Preserve existing partial data. A fresh generation requires a separate decision.
    RestartSeparately,
    /// Never infer completion from 416, even when the reported size matches.
    Revalidate,
    Reject(Error),
}

pub fn evaluate(request: ResumeRequest<'_>, status: u16, headers: ResponseHeaders<'_>) -> Decision {
    match status {
        200 => Decision::RestartSeparately,
        416 => Decision::Revalidate,
        206 => match check_partial(request, headers) {
            Ok(permit) => Decision::ReadRange(permit),
            Err(error) => Decision::Reject(error),
        },
        _ => Decision::Reject(Error::UnexpectedStatus),
    }
}

fn check_partial(
    request: ResumeRequest<'_>,
    headers: ResponseHeaders<'_>,
) -> Result<BodyPermit, Error> {
    match headers.content_encoding {
        Field::Missing => {}
        field => {
            if !field.required()?.eq_ignore_ascii_case(b"identity") {
                return Err(Error::NonIdentityEncoding);
            }
        }
    }
    if StrongEtag::parse(headers.etag.required()?)? != request.etag {
        return Err(Error::RepresentationChanged);
    }
    let range = ContentRange::parse(headers.content_range.required()?)?;
    if range
        != (ContentRange::Satisfied {
            start: request.start,
            end_exclusive: request.end_exclusive,
            total: Some(request.total),
        })
    {
        return Err(Error::RangeMismatch);
    }
    let expected_bytes = request
        .end_exclusive
        .checked_sub(request.start)
        .ok_or(Error::InvalidRequestRange)?;
    if decimal(headers.content_length.required()?)? != expected_bytes {
        return Err(Error::LengthMismatch);
    }
    Ok(BodyPermit { expected_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ResumeRequest<'static> {
        ResumeRequest::new(4, 8, 12, StrongEtag::parse(b"\"version-1\"").unwrap()).unwrap()
    }

    fn headers() -> ResponseHeaders<'static> {
        ResponseHeaders {
            content_range: Field::Single(b"bytes 4-7/12"),
            content_length: Field::Single(b"4"),
            etag: Field::Single(b"\"version-1\""),
            content_encoding: Field::Missing,
        }
    }

    #[test]
    fn diagnostics_never_echo_untrusted_header_values() {
        let secret = b"\"signed-resource-secret\"";
        let raw = Field::Single(secret);
        let response = ResponseHeaders {
            etag: raw,
            content_range: raw,
            content_length: raw,
            content_encoding: raw,
        };
        let tag = StrongEtag::parse(secret).unwrap();
        let request = ResumeRequest::new(0, 1, 1, tag).unwrap();
        for output in [
            format!("{raw:?}"),
            format!("{response:?}"),
            format!("{tag:?}"),
            format!("{request:?}"),
        ] {
            assert!(!output.contains("signed-resource-secret"));
            assert!(output.contains("[redacted]"));
        }
    }

    #[test]
    fn matching_headers_only_authorize_a_bounded_body() {
        let Decision::ReadRange(permit) = evaluate(request(), 206, headers()) else {
            panic!("rejected valid range")
        };
        assert_eq!(permit.expected_bytes(), 4);
        assert_eq!(permit.verify_received_length(4), Ok(()));
        assert_eq!(permit.verify_received_length(3), Err(Error::LengthMismatch));
        assert_eq!(permit.verify_received_length(5), Err(Error::LengthMismatch));
    }

    #[test]
    fn full_response_and_unsatisfied_range_never_append_or_complete() {
        assert_eq!(
            evaluate(request(), 200, headers()),
            Decision::RestartSeparately
        );
        assert_eq!(evaluate(request(), 416, headers()), Decision::Revalidate);
        assert_eq!(
            evaluate(request(), 500, headers()),
            Decision::Reject(Error::UnexpectedStatus)
        );
    }

    #[test]
    fn altered_identity_or_bounds_fail_closed() {
        for value in [
            b"bytes 3-7/12".as_slice(),
            b"bytes 4-8/12",
            b"bytes 4-7/13",
            b"bytes 4-7/*",
            b"bytes */12",
        ] {
            assert_eq!(
                evaluate(
                    request(),
                    206,
                    ResponseHeaders {
                        content_range: Field::Single(value),
                        ..headers()
                    }
                ),
                Decision::Reject(Error::RangeMismatch)
            );
        }
        assert_eq!(
            evaluate(
                request(),
                206,
                ResponseHeaders {
                    etag: Field::Single(b"\"version-2\""),
                    ..headers()
                }
            ),
            Decision::Reject(Error::RepresentationChanged)
        );
    }

    #[test]
    fn unvalidated_or_ambiguous_headers_never_authorize() {
        for field in [
            Field::Missing,
            Field::Repeated,
            Field::Single(b"W/\"version-1\""),
            Field::Single(b"\"version-1\", \"version-1\""),
        ] {
            assert!(matches!(
                evaluate(
                    request(),
                    206,
                    ResponseHeaders {
                        etag: field,
                        ..headers()
                    }
                ),
                Decision::Reject(_)
            ));
        }
        for field in [
            Field::Missing,
            Field::Repeated,
            Field::Single(b"4, 4"),
            Field::Single(b"+4"),
            Field::Single(b"18446744073709551616"),
            Field::Single(b"3"),
        ] {
            assert!(matches!(
                evaluate(
                    request(),
                    206,
                    ResponseHeaders {
                        content_length: field,
                        ..headers()
                    }
                ),
                Decision::Reject(_)
            ));
        }
        assert!(matches!(
            evaluate(
                request(),
                206,
                ResponseHeaders {
                    content_range: Field::Repeated,
                    ..headers()
                }
            ),
            Decision::Reject(_)
        ));
    }

    #[test]
    fn compressed_and_stacked_codings_cannot_mix_with_identity() {
        for field in [
            Field::Repeated,
            Field::Single(b"gzip"),
            Field::Single(b"identity,gzip"),
            Field::Single(b""),
        ] {
            assert!(matches!(
                evaluate(
                    request(),
                    206,
                    ResponseHeaders {
                        content_encoding: field,
                        ..headers()
                    }
                ),
                Decision::Reject(_)
            ));
        }
        assert!(matches!(
            evaluate(
                request(),
                206,
                ResponseHeaders {
                    content_encoding: Field::Single(b" Identity\t"),
                    ..headers()
                }
            ),
            Decision::ReadRange(_)
        ));
    }

    #[test]
    fn range_parser_rejects_overflow_reversed_bounds_and_smuggling() {
        for value in [
            b"bytes 0-18446744073709551615/*".as_slice(),
            b"bytes 0-1/18446744073709551616",
            b"bytes 5-4/12",
            b"bytes 0-12/12",
            b"bytes 0-0/0",
            b"bytes 4-7/12\r\nx: y",
            b"bytes +4-7/12",
            b"bytes 4-7/12,bytes 4-7/12",
            b"bytes 4-7/12/12",
            b"bytes */*",
            b"bytes  4-7/12",
        ] {
            assert!(ContentRange::parse(value).is_err(), "{value:?}");
        }
        assert_eq!(
            ContentRange::parse(b" BYTES 4-7/12\t"),
            Ok(ContentRange::Satisfied {
                start: 4,
                end_exclusive: 8,
                total: Some(12)
            })
        );
        assert_eq!(
            ContentRange::parse(b"bytes */0"),
            Ok(ContentRange::Unsatisfied { total: 0 })
        );
    }

    #[test]
    fn etag_grammar_is_byte_exact_and_does_not_unescape() {
        for value in [b"\"\"".as_slice(), b"\"\\\"", b"\"\xff\""] {
            assert!(StrongEtag::parse(value).is_ok());
        }
        for value in [
            b"W/\"a\"".as_slice(),
            b"\"a b\"",
            b"\"a\"b\"",
            b"\"a\n\"",
            b"\"\x7f\"",
            b"*",
            b"\"",
        ] {
            assert!(StrongEtag::parse(value).is_err());
        }
        assert_ne!(StrongEtag::parse(b"\"A\""), StrongEtag::parse(b"\"a\""));
    }

    #[test]
    fn input_limits_and_u64_boundary_are_enforced() {
        assert_eq!(
            ContentRange::parse(&vec![b'0'; MAX_FIELD_BYTES + 1]),
            Err(Error::FieldTooLarge)
        );
        assert_eq!(
            StrongEtag::parse(&vec![b'a'; MAX_FIELD_BYTES + 1]),
            Err(Error::FieldTooLarge)
        );
        let tag = StrongEtag::parse(b"\"a\"").unwrap();
        assert!(ResumeRequest::new(0, 0, 0, tag).is_err());
        assert!(ResumeRequest::new(4, 3, 12, tag).is_err());
        assert!(ResumeRequest::new(4, 13, 12, tag).is_err());
        let req = ResumeRequest::new(u64::MAX - 1, u64::MAX, u64::MAX, tag).unwrap();
        let response = ResponseHeaders {
            content_range: Field::Single(
                b"bytes 18446744073709551614-18446744073709551614/18446744073709551615",
            ),
            content_length: Field::Single(b"1"),
            etag: Field::Single(b"\"a\""),
            content_encoding: Field::Missing,
        };
        assert!(matches!(
            evaluate(req, 206, response),
            Decision::ReadRange(_)
        ));
    }
}
