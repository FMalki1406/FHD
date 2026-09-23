//! The wire contract between the engine and its clients (§3.1, §13). Pure: it
//! parses and builds bytes and knows nothing about pipes, sockets or jobs.
//!
//! Every frame is a four-byte big-endian length and that many bytes of JSON. The
//! length is checked before a byte is allocated, unknown fields are refused rather
//! than ignored, and the version is explicit, so an older engine tells a newer
//! client plainly instead of acting on half a message it does not understand.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// The largest frame either side will build or accept (§19).
pub const MAX_FRAME: usize = 256 * 1024;
/// This contract. A peer that sends anything else is answered, not guessed at.
pub const VERSION: u16 = 1;
const MAX_URL: usize = 16_384;
const MAX_PATH: usize = 32_768;
/// A listing is paged rather than unbounded, so one answer always fits a frame.
pub const MAX_JOBS_PER_PAGE: usize = 512;
/// The largest single read a transport is expected to hand `Frames`. It only
/// widens the reassembly allowance so a legal pipelined read is not refused.
pub const MAX_READ: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    /// The declared length is beyond what either side will hold.
    TooLarge,
    /// Not the contract: bad JSON, an unknown field, a missing one, a bad type.
    Malformed,
    /// A version this build does not implement.
    UnsupportedVersion(u16),
    /// Structurally valid, but a value no request may carry.
    Invalid,
}
impl ProtocolError {
    /// A stable code for the wire. Never carries the offending input back.
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLarge => "IPC-TOO-LARGE",
            Self::Malformed => "IPC-MALFORMED",
            Self::UnsupportedVersion(_) => "IPC-VERSION",
            Self::Invalid => "IPC-INVALID",
        }
    }
}

/// What a client asks the engine to do. The engine authorises separately: peer
/// identity proves only that the caller is the same user (§3.1).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Request {
    Add(AddRequest),
    /// A page of jobs, oldest identifier first, continuing after `after`.
    List {
        #[serde(default)]
        after: Option<u64>,
    },
    Pause {
        job: u64,
    },
    Resume {
        job: u64,
    },
    Cancel {
        job: u64,
    },
    /// Stop accepting work and let running jobs stop durably.
    Shutdown,
}

/// One thing to fetch. The client names the destination: nothing is derived from
/// the URL, so no server can choose where its own bytes are written.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AddRequest {
    pub url: String,
    pub destination: String,
    /// A link that must never be written to disk, such as a signed one.
    #[serde(default)]
    pub sensitive: bool,
    /// Lowercase hex of the expected SHA-256, when the caller knows it.
    #[serde(default)]
    pub expected_sha256: Option<String>,
    pub max_bytes: u64,
    #[serde(default)]
    pub allow_http: bool,
}
/// Never prints the link or the path: both are the caller's business, and this
/// type crosses layers that log.
impl std::fmt::Debug for AddRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddRequest")
            .field("url", &"<redacted>")
            .field("destination", &"<redacted>")
            .field("sensitive", &self.sensitive)
            .field("expected_sha256", &self.expected_sha256.is_some())
            .field("max_bytes", &self.max_bytes)
            .field("allow_http", &self.allow_http)
            .finish()
    }
}
/// Hides the request's contents for the same reason.
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Add(add) => f.debug_tuple("Add").field(add).finish(),
            Self::List { after } => f.debug_struct("List").field("after", after).finish(),
            Self::Pause { job } => f.debug_struct("Pause").field("job", job).finish(),
            Self::Resume { job } => f.debug_struct("Resume").field("job", job).finish(),
            Self::Cancel { job } => f.debug_struct("Cancel").field("job", job).finish(),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Response {
    Accepted {
        job: u64,
    },
    Jobs {
        jobs: Vec<JobSummary>,
        /// Present when more jobs follow: pass it back as `List { after }`.
        #[serde(default)]
        next: Option<u64>,
    },
    Done,
    /// A stable code, never a message built from input or from a server's text.
    Failed {
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobSummary {
    pub job: u64,
    /// The domain state's name, as the engine reports it.
    pub state: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub durable_bytes: u64,
    #[serde(default)]
    pub total: Option<u64>,
}

/// Values a structurally valid message may still not carry.
trait Checked {
    fn check(&self) -> Result<(), ProtocolError>;
}
impl Checked for Request {
    fn check(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Add(add) => {
                if add.url.is_empty()
                    || add.url.len() > MAX_URL
                    || add.destination.is_empty()
                    || add.destination.len() > MAX_PATH
                    || add.max_bytes == 0
                {
                    return Err(ProtocolError::Invalid);
                }
                match &add.expected_sha256 {
                    // Lowercase hex only: one spelling per digest, so a comparison
                    // downstream cannot disagree with itself.
                    Some(hex)
                        if hex.len() != 64
                            || !hex
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
                    {
                        Err(ProtocolError::Invalid)
                    }
                    _ => Ok(()),
                }
            }
            // Zero is never a job: the domain refuses it, so the wire does too.
            Self::Pause { job } | Self::Resume { job } | Self::Cancel { job } => {
                if *job == 0 {
                    Err(ProtocolError::Invalid)
                } else {
                    Ok(())
                }
            }
            Self::List { after } => match after {
                Some(0) => Err(ProtocolError::Invalid),
                _ => Ok(()),
            },
            Self::Shutdown => Ok(()),
        }
    }
}
impl Checked for Response {
    fn check(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Accepted { job } if *job == 0 => Err(ProtocolError::Invalid),
            Self::Jobs { jobs, .. } if jobs.len() > MAX_JOBS_PER_PAGE => {
                Err(ProtocolError::Invalid)
            }
            Self::Jobs { jobs, .. } if jobs.iter().any(|job| job.job == 0) => {
                Err(ProtocolError::Invalid)
            }
            Self::Failed { code } if code.is_empty() || code.len() > 64 => {
                Err(ProtocolError::Invalid)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    v: u16,
    /// Echoed in the answer, so a client can match them up.
    id: u64,
    body: T,
}

fn encode<T: Serialize + Checked>(id: u64, body: &T) -> Result<Vec<u8>, ProtocolError> {
    body.check()?;
    let json = serde_json::to_vec(&Envelope {
        v: VERSION,
        id,
        body,
    })
    .map_err(|_| ProtocolError::Malformed)?;
    if json.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(
        &u32::try_from(json.len())
            .map_err(|_| ProtocolError::TooLarge)?
            .to_be_bytes(),
    );
    frame.extend_from_slice(&json);
    Ok(frame)
}

fn decode<T: serde::de::DeserializeOwned + Checked>(
    frame: &[u8],
) -> Result<(u64, T), ProtocolError> {
    if frame.len() > MAX_FRAME {
        return Err(ProtocolError::TooLarge);
    }
    // The version is read before the body, so a message shaped for a contract this
    // build does not implement is named as such rather than called malformed.
    let version: VersionOnly =
        serde_json::from_slice(frame).map_err(|_| ProtocolError::Malformed)?;
    if version.v != VERSION {
        return Err(ProtocolError::UnsupportedVersion(version.v));
    }
    let envelope: Envelope<T> =
        serde_json::from_slice(frame).map_err(|_| ProtocolError::Malformed)?;
    envelope.body.check()?;
    Ok((envelope.id, envelope.body))
}

#[derive(Deserialize)]
struct VersionOnly {
    v: u16,
}

pub fn encode_request(id: u64, request: &Request) -> Result<Vec<u8>, ProtocolError> {
    encode(id, request)
}
pub fn decode_request(frame: &[u8]) -> Result<(u64, Request), ProtocolError> {
    decode(frame)
}
pub fn encode_response(id: u64, response: &Response) -> Result<Vec<u8>, ProtocolError> {
    encode(id, response)
}
pub fn decode_response(frame: &[u8]) -> Result<(u64, Response), ProtocolError> {
    decode(frame)
}

/// Reassembles frames from a byte stream that splits and joins them freely. It
/// never holds more than one frame: a peer that announces a huge length is refused
/// at the header, before anything is allocated for it.
#[derive(Default)]
pub struct Frames {
    buffer: Vec<u8>,
}
impl Frames {
    pub fn new() -> Self {
        Self::default()
    }
    /// Adds received bytes. Refuses the peer once it has announced a frame too
    /// large, rather than accumulating towards it.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        // One whole frame plus whatever of the next one arrived with it: a peer
        // pipelining legally must not be mistaken for one announcing too much.
        if self.buffer.len().saturating_add(bytes.len()) > 4 + MAX_FRAME + MAX_READ {
            return Err(ProtocolError::TooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        self.declared()?;
        Ok(())
    }
    /// The next complete frame, if one has arrived.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, ProtocolError> {
        let Some(length) = self.declared()? else {
            return Ok(None);
        };
        if self.buffer.len() < 4 + length {
            return Ok(None);
        }
        let frame = self.buffer[4..4 + length].to_vec();
        self.buffer.drain(..4 + length);
        Ok(Some(frame))
    }
    /// The announced length, checked as soon as the header is complete.
    fn declared(&self) -> Result<Option<usize>, ProtocolError> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let length = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        if length == 0 {
            // A frame of nothing is not a size problem; it is not the contract.
            return Err(ProtocolError::Malformed);
        }
        if length > MAX_FRAME {
            return Err(ProtocolError::TooLarge);
        }
        Ok(Some(length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add() -> Request {
        Request::Add(AddRequest {
            url: "https://example.test/file".into(),
            destination: "/downloads/file.bin".into(),
            sensitive: false,
            expected_sha256: Some("a".repeat(64)),
            max_bytes: 1 << 30,
            allow_http: false,
        })
    }

    #[test]
    fn every_request_survives_the_wire_unchanged() {
        for request in [
            add(),
            Request::List { after: None },
            Request::List { after: Some(7) },
            Request::Pause { job: 1 },
            Request::Resume { job: 2 },
            Request::Cancel { job: 3 },
            Request::Shutdown,
        ] {
            let frame = encode_request(42, &request).unwrap();
            let (id, decoded) = decode_request(&frame[4..]).unwrap();
            assert_eq!(id, 42);
            assert!(decoded == request, "{request:?} changed on the wire");
        }
    }

    #[test]
    fn every_response_survives_the_wire_unchanged() {
        for response in [
            Response::Accepted { job: 9 },
            Response::Jobs {
                jobs: vec![JobSummary {
                    job: 4,
                    state: "Transferring".into(),
                    reason: None,
                    durable_bytes: 17,
                    total: Some(99),
                }],
                next: Some(5),
            },
            Response::Done,
            Response::Failed {
                code: "ENGINE-INVALID-INPUT".into(),
            },
        ] {
            let frame = encode_response(1, &response).unwrap();
            let (_, decoded) = decode_response(&frame[4..]).unwrap();
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn a_link_never_reaches_a_log_through_a_debug_print() {
        let printed = format!("{:?}", add());
        assert!(!printed.contains("example.test"), "{printed}");
        assert!(!printed.contains("/downloads/"), "{printed}");
    }

    #[test]
    fn a_message_from_another_contract_is_named_not_guessed_at() {
        let frame = br#"{"v":2,"id":1,"body":{"kind":"shutdown"}}"#;
        assert_eq!(
            decode_request(frame),
            Err(ProtocolError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn unknown_and_missing_fields_are_refused_rather_than_ignored() {
        for frame in [
            // An extra field: a newer client meaning something this build would drop.
            br#"{"v":1,"id":1,"body":{"kind":"pause","job":1,"force":true}}"#.as_slice(),
            br#"{"v":1,"id":1,"body":{"kind":"pause"}}"#.as_slice(),
            br#"{"v":1,"id":1,"body":{"kind":"unheard-of"}}"#.as_slice(),
            br#"{"v":1,"body":{"kind":"shutdown"}}"#.as_slice(),
            br#"{"v":1,"id":"one","body":{"kind":"shutdown"}}"#.as_slice(),
            b"not json at all".as_slice(),
            b"".as_slice(),
        ] {
            assert_eq!(
                decode_request(frame),
                Err(ProtocolError::Malformed),
                "accepted {}",
                String::from_utf8_lossy(frame)
            );
        }
    }

    #[test]
    fn values_no_request_may_carry_are_refused_on_both_sides() {
        let long = "u".repeat(MAX_URL + 1);
        for request in [
            Request::Pause { job: 0 },
            Request::List { after: Some(0) },
            Request::Add(AddRequest {
                url: long,
                destination: "/tmp/x".into(),
                sensitive: false,
                expected_sha256: None,
                max_bytes: 1,
                allow_http: false,
            }),
            Request::Add(AddRequest {
                url: "https://example.test/f".into(),
                destination: String::new(),
                sensitive: false,
                expected_sha256: None,
                max_bytes: 1,
                allow_http: false,
            }),
            Request::Add(AddRequest {
                url: "https://example.test/f".into(),
                destination: "/tmp/x".into(),
                sensitive: false,
                // Uppercase hex is a second spelling of one digest: refused.
                expected_sha256: Some("A".repeat(64)),
                max_bytes: 1,
                allow_http: false,
            }),
        ] {
            assert_eq!(encode_request(1, &request), Err(ProtocolError::Invalid));
        }
        // And a peer that sends one anyway does not get it past the decoder.
        let frame = br#"{"v":1,"id":1,"body":{"kind":"cancel","job":0}}"#;
        assert_eq!(decode_request(frame), Err(ProtocolError::Invalid));
    }

    #[test]
    fn frames_survive_being_split_and_joined_by_the_stream() {
        let first = encode_request(1, &Request::Shutdown).unwrap();
        let second = encode_request(2, &Request::Pause { job: 5 }).unwrap();
        let stream: Vec<u8> = first.iter().chain(second.iter()).copied().collect();
        let mut frames = Frames::new();
        let mut decoded = Vec::new();
        // One byte at a time is the worst a stream can do to a frame.
        for byte in stream {
            frames.push(&[byte]).unwrap();
            while let Some(frame) = frames.next_frame().unwrap() {
                decoded.push(decode_request(&frame).unwrap());
            }
        }
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].0, 1);
        assert_eq!(decoded[1].1, Request::Pause { job: 5 });
    }

    #[test]
    fn an_announced_frame_too_large_is_refused_at_the_header() {
        let mut frames = Frames::new();
        let header = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
        assert_eq!(frames.push(&header), Err(ProtocolError::TooLarge));
        // A frame of nothing is not a size problem; the peer is told which it is.
        let mut zero = Frames::new();
        assert_eq!(zero.push(&[0, 0, 0, 0]), Err(ProtocolError::Malformed));
    }

    /// A read may finish one frame and carry the beginning of the next; refusing
    /// that would break any peer that pipelines, which the contract allows.
    #[test]
    fn a_read_that_completes_one_frame_and_starts_another_is_accepted() {
        let big = Request::Add(AddRequest {
            url: format!("https://example.test/{}", "u".repeat(MAX_URL - 40)),
            destination: "/downloads/large".into(),
            sensitive: false,
            expected_sha256: None,
            max_bytes: 1 << 30,
            allow_http: false,
        });
        let first = encode_request(1, &big).unwrap();
        let second = encode_request(2, &Request::Shutdown).unwrap();
        let mut frames = Frames::new();
        let mut stream: Vec<u8> = first.clone();
        stream.extend_from_slice(&second);
        frames.push(&stream).unwrap();
        let one = frames.next_frame().unwrap().unwrap();
        assert_eq!(decode_request(&one).unwrap().0, 1);
        let two = frames.next_frame().unwrap().unwrap();
        assert_eq!(decode_request(&two).unwrap().1, Request::Shutdown);
    }

    #[test]
    fn a_listing_is_paged_rather_than_unbounded() {
        let jobs = (1..=MAX_JOBS_PER_PAGE as u64 + 1)
            .map(|job| JobSummary {
                job,
                state: "Queued".into(),
                reason: None,
                durable_bytes: 0,
                total: None,
            })
            .collect();
        assert_eq!(
            encode_response(1, &Response::Jobs { jobs, next: None }),
            Err(ProtocolError::Invalid)
        );
    }

    #[test]
    fn deeply_nested_input_is_refused_without_recursing_into_it() {
        let mut frame = br#"{"v":1,"id":1,"body":"#.to_vec();
        frame.extend(std::iter::repeat_n(b'[', 4096));
        frame.extend(std::iter::repeat_n(b']', 4096));
        frame.extend_from_slice(b"}");
        assert!(decode_request(&frame).is_err());
    }
}
