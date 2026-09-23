//! The local control surface (§3.1): a Windows named pipe or a Unix socket that
//! only the user who owns the engine can reach. It carries frames and nothing else
//! -- what a request means is the composition root's business, and what it may do
//! is decided there too. Peer identity proves "the same user", never more.
#![forbid(unsafe_code)]

use fhd_protocol::{
    decode_request, decode_response, encode_request, encode_response, Frames, ProtocolError,
    Request, Response,
};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A connection that has asked for nothing yet is cheap to make and must stay
/// cheap to hold: an unauthenticated peer may not occupy the engine for minutes.
/// It counts from the connection, not from the last byte, so dribbling a byte
/// before it expires buys nothing.
const FIRST_REQUEST: Duration = Duration::from_secs(5);
/// Between requests, a client that has already spoken is given longer.
const IDLE: Duration = Duration::from_secs(120);
/// One client may not keep the engine writing forever either.
const WRITE: Duration = Duration::from_secs(30);
/// Nor may one answer take forever: the engine says it is busy instead.
const HANDLE: Duration = Duration::from_secs(20);
/// What a client waits, in total, for one answer.
const ANSWER: Duration = Duration::from_secs(60);
/// Connections served at once. Every one of them costs a read buffer and a
/// reassembly buffer, so the count is a declared budget rather than a surprise.
const MAX_CLIENTS: usize = 32;

#[derive(Debug)]
pub enum IpcError {
    /// The endpoint already exists: another engine owns this user's directory,
    /// or someone took the name first. On Unix the client checks the owner before
    /// it speaks, so taking the name denies service rather than granting entry.
    /// **On Windows there is no such check yet** (§3.1, enterprise-ipc.md): taking
    /// the name there means the client speaks to whoever took it.
    Taken,
    /// The directory or socket is not ours alone.
    Untrusted,
    Protocol(ProtocolError),
    Io(io::ErrorKind),
}
impl IpcError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Taken => "IPC-ENDPOINT-TAKEN",
            Self::Untrusted => "IPC-ENDPOINT-UNTRUSTED",
            Self::Protocol(error) => error.code(),
            Self::Io(_) => "IPC-IO",
        }
    }
}
impl From<io::Error> for IpcError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}
impl From<ProtocolError> for IpcError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Where this user's engine listens. The path is derived from the platform's own
/// per-user runtime location; it is never in a world-writable directory.
#[derive(Clone)]
pub struct Endpoint(pub String);
/// A socket path carries the user's home directory on Unix. It is not a secret,
/// but it is theirs, so it is not printed by accident.
impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Endpoint(<redacted>)")
    }
}

#[cfg(windows)]
impl Endpoint {
    /// `\\.\pipe\fhd-<name>`, where the name identifies the engine's own state
    /// directory. **This is not yet what §3.1 asks for:** it carries no user SID
    /// and no session, so it is predictable, and nothing here stops another user
    /// taking the name first. See docs/enterprise-ipc.md.
    pub fn for_user(name: &str) -> Self {
        Self(format!(r"\\.\pipe\fhd-{name}"))
    }
}
#[cfg(unix)]
impl Endpoint {
    /// `$XDG_RUNTIME_DIR/fhd/<name>`, or `~/.local/state/fhd/run/<name>`. Never
    /// `/tmp`: a shared directory is somewhere another user can race us.
    pub fn for_user(name: &str) -> Self {
        Self(Self::directory().join(name).to_string_lossy().into_owned())
    }
    /// Refuses a path a Unix socket cannot hold: `sun_path` is 108 bytes on Linux
    /// and 104 on macOS, and a truncated path would name something else entirely.
    pub fn usable(&self) -> Result<(), IpcError> {
        let limit = if cfg!(target_os = "macos") { 104 } else { 108 };
        if self.0.len() >= limit {
            return Err(IpcError::Untrusted);
        }
        Ok(())
    }
    /// The runtime directory if the session really has one, else the user's own
    /// state directory. A set but unusable XDG_RUNTIME_DIR -- a service account, a
    /// session without one -- must not leave the engine unreachable.
    fn directory() -> PathBuf {
        let home =
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state/fhd/run"));
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|runtime| !runtime.is_empty())
            .map(|runtime| PathBuf::from(runtime).join("fhd"));
        for candidate in [runtime, home].into_iter().flatten() {
            if std::fs::create_dir_all(&candidate).is_ok() {
                return candidate;
            }
        }
        // Nowhere of this user's own to put it. An empty path fails to bind,
        // which is the right answer: a socket in the working directory could be
        // anywhere, including somewhere another user can reach.
        PathBuf::new()
    }
}

/// Answers one request. The engine supplies this; the socket layer neither knows
/// nor decides what a request means.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, request: Request) -> impl Future<Output = Response> + Send;
}

pub struct Server {
    endpoint: Endpoint,
    #[cfg(unix)]
    listener: tokio::net::UnixListener,
    /// The uid this engine runs as; every peer is checked against it.
    #[cfg(unix)]
    owner: u32,
    #[cfg(windows)]
    options: tokio::net::windows::named_pipe::ServerOptions,
    #[cfg(windows)]
    first: Option<tokio::net::windows::named_pipe::NamedPipeServer>,
}

impl Server {
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Serves until `stop` resolves. Each client is handled on its own task; one
    /// slow or silent client never blocks another or the engine.
    pub async fn serve<H: Handler>(mut self, handler: Arc<H>, stop: impl Future<Output = ()>) {
        tokio::pin!(stop);
        // Clients are held here rather than let loose: when the engine stops, their
        // connections close with it, and nothing they hold outlives the server.
        let mut clients = tokio::task::JoinSet::new();
        loop {
            // Reaped without racing the accept: waiting on both would cancel a
            // connection in progress every time a previous client finished.
            while clients.try_join_next().is_some() {}
            // At the ceiling, wait for a client to leave before taking another.
            // Accepting anyway would let one process hold the engine's memory.
            if clients.len() >= MAX_CLIENTS {
                tokio::select! {
                    biased;
                    () = &mut stop => {
                        clients.shutdown().await;
                        return;
                    }
                    _ = clients.join_next() => continue,
                }
            }
            let accepted = tokio::select! {
                biased;
                () = &mut stop => {
                    clients.shutdown().await;
                    return;
                }
                accepted = self.accept() => accepted,
            };
            match accepted {
                Ok(stream) => {
                    let handler = handler.clone();
                    clients.spawn(async move { serve_client(stream, handler).await });
                }
                // A failed accept is this client's problem, not the engine's: the
                // listener stays up, because a resident service that quits on one
                // bad connection is a denial of service with extra steps. It waits
                // a moment first, so a permanent failure cannot become a hot loop.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    impl Server {
        /// Claims the endpoint for this user. The directory is created 0700 and
        /// checked: if it exists and is not ours alone, we refuse rather than
        /// listen somewhere another user can reach.
        pub fn bind(endpoint: Endpoint) -> Result<Self, IpcError> {
            endpoint.usable()?;
            let path = PathBuf::from(&endpoint.0);
            if !path.is_absolute() {
                return Err(IpcError::Untrusted);
            }
            let directory = path.parent().ok_or(IpcError::Untrusted)?.to_path_buf();
            std::fs::create_dir_all(&directory)?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
            let owner = trusted_directory(&directory)?;
            // A socket left by a crash is ours to clear; a live one is not, and we
            // refuse rather than take a name another engine is still answering on.
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(_) => return Err(IpcError::Taken),
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                endpoint,
                listener,
                owner,
            })
        }

        pub(super) async fn accept(&mut self) -> Result<tokio::net::UnixStream, IpcError> {
            loop {
                let (stream, _) = self.listener.accept().await?;
                // SO_PEERCRED: the kernel's answer about who connected, never the
                // client's claim. It proves the same user and nothing more (§3.1).
                let credentials = stream.peer_cred()?;
                if credentials.uid() == self.owner {
                    return Ok(stream);
                }
                // Someone else reached a socket that should be unreachable. Drop
                // the connection, say so, and keep serving.
                fhd_telemetry::emit(fhd_telemetry::Event::new(
                    fhd_telemetry::Code::PolicyRejected,
                ));
            }
        }
    }

    /// The uid that owns this process, learned once by making a file and reading
    /// it back: no unsafe call, the same answer on Linux and macOS, and no write
    /// on the path of every connection afterwards.
    fn our_uid(directory: &Path) -> Result<u32, IpcError> {
        static OURS: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        if let Some(uid) = OURS.get() {
            return Ok(*uid);
        }
        let probe = directory.join(format!(".owner-probe-{}", std::process::id()));
        let file = std::fs::File::create(&probe)?;
        let uid = file.metadata()?.uid();
        drop(file);
        let _ = std::fs::remove_file(&probe);
        Ok(*OURS.get_or_init(|| uid))
    }

    /// The directory must be ours, a real directory, and closed to everyone else.
    fn trusted_directory(directory: &Path) -> Result<u32, IpcError> {
        let metadata = std::fs::symlink_metadata(directory)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(IpcError::Untrusted);
        }
        let uid = our_uid(directory)?;
        if metadata.uid() != uid {
            return Err(IpcError::Untrusted);
        }
        Ok(uid)
    }

    impl Drop for Server {
        fn drop(&mut self) {
            // Leave nothing behind that a later run would mistake for a live engine.
            let _ = std::fs::remove_file(&self.endpoint.0);
        }
    }

    /// Connects to this user's engine, checking who owns the endpoint before a
    /// single byte is sent: a socket someone else planted is not talked to.
    pub async fn connect(endpoint: &Endpoint) -> Result<tokio::net::UnixStream, IpcError> {
        endpoint.usable()?;
        let path = PathBuf::from(endpoint.0.clone());
        let directory = path.parent().ok_or(IpcError::Untrusted)?;
        let uid = trusted_directory(directory)?;
        let metadata = std::fs::symlink_metadata(&path)?;
        if metadata.uid() != uid
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.file_type().is_symlink()
        {
            return Err(IpcError::Untrusted);
        }
        Ok(tokio::net::UnixStream::connect(&path).await?)
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    impl Server {
        /// Claims the pipe name. `first_pipe_instance` means a name already taken
        /// is an error here rather than a second engine quietly serving beside us.
        pub fn bind(endpoint: Endpoint) -> Result<Self, IpcError> {
            let mut options = ServerOptions::new();
            options
                .first_pipe_instance(true)
                // A pipe is reachable over the network unless this is set.
                .reject_remote_clients(true)
                .max_instances(16);
            let first = options
                .create(&endpoint.0)
                .map_err(|error| match error.kind() {
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrInUse => IpcError::Taken,
                    _ => IpcError::Io(error.kind()),
                })?;
            Ok(Self {
                endpoint,
                options,
                first: Some(first),
            })
        }

        pub(super) async fn accept(&mut self) -> Result<NamedPipeServer, IpcError> {
            // The first instance is created at bind so the name is held from the
            // start; later ones are created as each client is taken.
            let server = match self.first.take() {
                Some(server) => server,
                // Only the instance that claimed the name may ask to be first;
                // asking again would fail for every client after the first.
                None => {
                    self.options.first_pipe_instance(false);
                    self.options.create(&self.endpoint.0)?
                }
            };
            server.connect().await?;
            Ok(server)
        }
    }

    /// Every instance being busy is ordinary here: the engine creates the next
    /// one as it takes the previous client, so a caller that arrives in between
    /// waits briefly instead of being told the engine is unreachable.
    const ERROR_PIPE_BUSY: i32 = 231;
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
    const SECURITY_SQOS_PRESENT: u32 = 0x0010_0000;

    /// Connects to this user's engine.
    pub async fn connect(
        endpoint: &Endpoint,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, IpcError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            match ClientOptions::new()
                // A fake server must not be able to act as us: identification
                // lets it check who we are and nothing more. Set here rather
                // than relied upon as somebody else's default.
                .security_qos_flags(SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT)
                .open(&endpoint.0)
            {
                Ok(client) => return Ok(client),
                Err(error)
                    if error.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && std::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(IpcError::Io(error.kind())),
            }
        }
    }
}

pub use platform::connect;

/// Reads frames, answers them in order, and stops on anything it does not accept.
/// Errors are answered with a code where the frame parsed, and end the connection
/// where it did not: there is nothing useful to say to a peer talking nonsense.
async fn serve_client<S, H>(mut stream: S, handler: Arc<H>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    H: Handler,
{
    let mut frames = Frames::new();
    let mut buffer = vec![0u8; 16 * 1024];
    // Until a whole request has arrived, the clock runs from when the connection
    // was made. A peer that sends one byte a minute is not a slow client asking
    // for something; it is a peer holding the engine open, so it is dropped.
    let opened = tokio::time::Instant::now();
    let mut asked = false;
    loop {
        let patience = if asked {
            IDLE
        } else {
            match FIRST_REQUEST.checked_sub(opened.elapsed()) {
                Some(left) => left,
                None => return,
            }
        };
        let read = match tokio::time::timeout(patience, stream.read(&mut buffer)).await {
            Ok(Ok(0)) | Err(_) => return,
            Ok(Ok(read)) => read,
            Ok(Err(_)) => return,
        };
        if frames.push(&buffer[..read]).is_err() {
            return;
        }
        loop {
            let frame = match frames.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(_) => return,
            };
            // A complete request: this peer is a client, not a squatter.
            asked = true;
            let (id, response) = match decode_request(&frame) {
                // An answer that never comes would hold this connection, and on
                // Windows one of a small number of pipe instances with it.
                Ok((id, request)) => (
                    id,
                    match tokio::time::timeout(HANDLE, handler.handle(request)).await {
                        Ok(response) => response,
                        Err(_) => Response::Failed {
                            code: "ENGINE-BUSY".to_owned(),
                        },
                    },
                ),
                // The frame was whole and wrong: name the fault and keep going,
                // so a client with one bad message is not left guessing.
                Err(error) => (
                    0,
                    Response::Failed {
                        code: error.code().to_owned(),
                    },
                ),
            };
            // A response this contract cannot carry is still answered: dropping
            // the connection would leave the client guessing.
            let bytes = match encode_response(id, &response) {
                Ok(bytes) => bytes,
                Err(_) => match encode_response(
                    id,
                    &Response::Failed {
                        code: "IPC-INTERNAL".to_owned(),
                    },
                ) {
                    Ok(bytes) => bytes,
                    Err(_) => return,
                },
            };
            if tokio::time::timeout(WRITE, stream.write_all(&bytes))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// One request, one answer. Used by the CLI and by tests; it holds the connection
/// only as long as the exchange.
pub async fn ask<S>(stream: &mut S, id: u64, request: &Request) -> Result<Response, IpcError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let bytes = encode_request(id, request)?;
    tokio::time::timeout(WRITE, stream.write_all(&bytes))
        .await
        .map_err(|_| IpcError::Io(io::ErrorKind::TimedOut))??;
    let mut frames = Frames::new();
    let mut buffer = vec![0u8; 16 * 1024];
    // One answer, one budget. Without it a server that sends a byte before every
    // read deadline keeps a client waiting for as long as it likes.
    let deadline = tokio::time::Instant::now() + ANSWER;
    loop {
        let left = deadline
            .checked_duration_since(tokio::time::Instant::now())
            .ok_or(IpcError::Io(io::ErrorKind::TimedOut))?;
        let read = tokio::time::timeout(left, stream.read(&mut buffer))
            .await
            .map_err(|_| IpcError::Io(io::ErrorKind::TimedOut))??;
        if read == 0 {
            return Err(IpcError::Io(io::ErrorKind::UnexpectedEof));
        }
        frames.push(&buffer[..read])?;
        if let Some(frame) = frames.next_frame()? {
            let (answered, response) = decode_response(&frame)?;
            if answered != id {
                return Err(IpcError::Protocol(ProtocolError::Malformed));
            }
            return Ok(response);
        }
    }
}
