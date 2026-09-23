//! The local control surface (§3.1): a Windows named pipe or a Unix socket that
//! only the user who owns the engine can reach. It carries frames and nothing else
//! -- what a request means is the composition root's business, and what it may do
//! is decided there too. Peer identity proves "the same user", never more.
#![forbid(unsafe_code)]

use fhd_protocol::{
    decode_request, decode_response, encode_request, encode_response, Frames, ProtocolError,
    Request, Response, MAX_FRAME,
};
#[cfg(unix)]
use std::path::{Path, PathBuf};
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A client that sends nothing is dropped rather than held open forever.
const IDLE: Duration = Duration::from_secs(120);
/// One client may not keep the engine writing forever either.
const WRITE: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum IpcError {
    /// The endpoint already exists: another engine owns this user's directory,
    /// or someone squatted the name first (§3.1 declares this as a denial of
    /// service, not a way in -- the client still checks who owns it).
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
#[derive(Clone, Debug)]
pub struct Endpoint(pub String);

#[cfg(windows)]
impl Endpoint {
    /// `\\.\pipe\fhd-<session>-<name>`: the pipe namespace is per machine, so the
    /// name carries the session and the engine's own directory identity.
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
    fn directory() -> PathBuf {
        match std::env::var_os("XDG_RUNTIME_DIR") {
            Some(runtime) if !runtime.is_empty() => PathBuf::from(runtime).join("fhd"),
            _ => match std::env::var_os("HOME") {
                Some(home) => PathBuf::from(home).join(".local/state/fhd/run"),
                None => PathBuf::from(".fhd-run"),
            },
        }
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
            let path = PathBuf::from(&endpoint.0);
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

    /// The uid that owns this process, learned by making a file and reading it
    /// back: no unsafe call, and it works the same on Linux and macOS.
    fn our_uid(directory: &Path) -> Result<u32, IpcError> {
        let probe = directory.join(".owner-probe");
        let file = std::fs::File::create(&probe)?;
        let uid = file.metadata()?.uid();
        drop(file);
        let _ = std::fs::remove_file(&probe);
        Ok(uid)
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

    /// Connects to this user's engine.
    pub async fn connect(
        endpoint: &Endpoint,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeClient, IpcError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match ClientOptions::new().open(&endpoint.0) {
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
    loop {
        let read = match tokio::time::timeout(IDLE, stream.read(&mut buffer)).await {
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
            let (id, response) = match decode_request(&frame) {
                Ok((id, request)) => (id, handler.handle(request).await),
                // The frame was whole and wrong: name the fault and keep going,
                // so a client with one bad message is not left guessing.
                Err(error) => (
                    0,
                    Response::Failed {
                        code: error.code().to_owned(),
                    },
                ),
            };
            let Ok(bytes) = encode_response(id, &response) else {
                return;
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
    loop {
        let read = tokio::time::timeout(IDLE, stream.read(&mut buffer))
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
        if read > MAX_FRAME {
            return Err(IpcError::Protocol(ProtocolError::TooLarge));
        }
    }
}
