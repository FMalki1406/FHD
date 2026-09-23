//! Operating-system primitives the rest of the engine cannot express safely.
//!
//! This is the one crate §4 allows `unsafe`, and it exists for a single reason:
//! §3.1's control surface needs a Windows named pipe that carries the user's SID
//! and session in its name, is created with a security descriptor only that user
//! can reach, and can be checked by the client for who owns it before it sends a
//! byte. None of that is expressible without calling Win32 directly.
//!
//! Every `unsafe` block here states what makes the call sound. Nothing in this
//! crate decides policy: it reports what the system says and hands back handles.
#![cfg_attr(not(windows), forbid(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]

use std::io;

/// What the caller may know about this machine's idea of "the same user".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserScope {
    /// The user's security identifier, as a string. Stable for the account.
    pub identity: String,
    /// The logon session. Two sessions of one account do not share a surface.
    pub session: u32,
}
impl UserScope {
    /// A short, stable component for an endpoint name: it identifies the account
    /// and session without being a secret, which is exactly §3.1's requirement.
    pub fn tag(&self) -> String {
        format!("{}-{}", self.identity, self.session)
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    /// Unix identifies the peer by credentials on the socket itself, so the name
    /// carries nothing: `fhd-ipc` checks ownership of the directory and socket
    /// and asks the kernel who connected.
    pub fn user_scope() -> io::Result<UserScope> {
        Ok(UserScope {
            identity: "unix".to_owned(),
            session: 0,
        })
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::{ffi::c_void, iter::once, os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{GetCurrentProcess, GetCurrentProcessId, OpenProcessToken},
        },
    };

    /// Frees a pointer the system allocated with `LocalAlloc`.
    struct Local(*mut c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a Win32 call documented to
                // allocate with LocalAlloc, and it is freed exactly once here.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn last_error() -> io::Error {
        // SAFETY: reads a thread-local error code; no memory is touched.
        io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
    }

    /// The SID of the account this process runs as, and its logon session.
    pub fn user_scope() -> io::Result<UserScope> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no close;
        // `token` is a valid out-parameter that the call fills on success.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(last_error());
        }
        // SAFETY: the call above produced an owned token handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token as *mut _) };
        let identity = token_user_sid(&token)?;
        let mut session = 0u32;
        // SAFETY: `session` is a valid out-parameter; the process id is our own.
        let resolved = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) };
        if resolved == 0 {
            return Err(last_error());
        }
        Ok(UserScope { identity, session })
    }

    fn token_user_sid(token: &OwnedHandle) -> io::Result<String> {
        use std::os::windows::io::AsRawHandle;
        let handle = token.as_raw_handle() as HANDLE;
        let mut needed = 0u32;
        // SAFETY: asking for the required size with a null buffer is the
        // documented first step; it fails with ERROR_INSUFFICIENT_BUFFER.
        unsafe { GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(last_error());
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: the buffer is at least `needed` bytes, as the call just said.
        let read = unsafe {
            GetTokenInformation(
                handle,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if read == 0 {
            return Err(last_error());
        }
        // SAFETY: on success the buffer holds a TOKEN_USER whose Sid points
        // inside that same buffer, which outlives this borrow.
        let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `user.User.Sid` is a valid SID for as long as `buffer` lives.
        let converted = unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) };
        if converted == 0 || text.is_null() {
            return Err(last_error());
        }
        let owned = Local(text.cast());
        // SAFETY: the system returned a null-terminated wide string.
        let length = unsafe { (0..).take_while(|i| *text.add(*i as usize) != 0).count() };
        // SAFETY: `length` units of that string are readable.
        let slice = unsafe { std::slice::from_raw_parts(text, length) };
        let sid = String::from_utf16_lossy(slice);
        drop(owned);
        Ok(sid)
    }

    /// Only the owning user and the system may touch this pipe, and nothing
    /// below medium integrity may open it at all -- which is what keeps a
    /// sandboxed process of the same account out (§3.1, §16.1).
    fn owner_only_descriptor(sid: &str) -> io::Result<(Local, SECURITY_ATTRIBUTES)> {
        // O: the owner, stated rather than left to the token's default. An
        // elevated process on Windows stamps objects with the Administrators
        // group as owner, and the client's check compares against the user, so
        // leaving it implicit would make that check fail on exactly the machines
        // where the engine runs with more rights, not fewer.
        // D: the access control list. A: allow, FA: full access, P: protected,
        // so nothing is inherited into it.
        // S: the mandatory label. ML at medium, NR|NW|NX: no read, write or
        // execute up, so a lower-integrity process cannot reach the pipe.
        let sddl = format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)S:(ML;;NRNWNX;;;ME)");
        let wide: Vec<u16> = std::ffi::OsStr::new(&sddl)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a null-terminated wide string that outlives the call;
        // `descriptor` is a valid out-parameter the system allocates into.
        let built = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                ptr::null_mut(),
            )
        };
        if built == 0 || descriptor.is_null() {
            return Err(last_error());
        }
        let owned = Local(descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        Ok((owned, attributes))
    }

    /// Creates one instance of a pipe only this user can reach. `first` asks the
    /// system to refuse if the name already exists, which is how a squatter is
    /// detected rather than silently joined.
    pub fn create_pipe(
        name: &str,
        first: bool,
    ) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let scope = user_scope()?;
        let (_descriptor, mut attributes) = owner_only_descriptor(&scope.identity)?;
        let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(16);
        // SAFETY: the descriptor behind `attributes` lives until this function
        // returns, and the call copies what it needs before that. The pointer is
        // non-null and points at a SECURITY_ATTRIBUTES whose size field is set.
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
        }
    }

    /// Opens the pipe only when this user owns it. A client that skipped this
    /// would hand its request -- and any credential in it -- to whoever took the
    /// name first, which is exactly the attack §3.1 names.
    pub fn open_pipe(name: &str) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        use windows_sys::Win32::{
            Security::{Authorization::GetSecurityInfo, Authorization::SE_KERNEL_OBJECT, PSID},
            Storage::FileSystem::{
                CreateFileW, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
                OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
            },
        };
        const OWNER_SECURITY_INFORMATION: u32 = 0x0000_0001;
        let wide: Vec<u16> = std::ffi::OsStr::new(name)
            .encode_wide()
            .chain(once(0))
            .collect();
        // SAFETY: `wide` is a null-terminated wide string. The flags ask for an
        // overlapped handle, which is what tokio requires, and for identification
        // only, so a fake server cannot act as us.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(last_error());
        }
        // SAFETY: CreateFileW returned a valid handle we now own.
        let owned = unsafe { OwnedHandle::from_raw_handle(handle as *mut _) };
        let mut owner: PSID = ptr::null_mut();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: both out-parameters are valid; the descriptor is allocated by
        // the system and freed below.
        let queried = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        let _descriptor = Local(descriptor);
        if queried != 0 || owner.is_null() {
            return Err(io::Error::other("pipe owner could not be read"));
        }
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `owner` points into the descriptor, which is still alive.
        let converted = unsafe { ConvertSidToStringSidW(owner, &mut text) };
        if converted == 0 || text.is_null() {
            return Err(last_error());
        }
        let owned_text = Local(text.cast());
        // SAFETY: the system returned a null-terminated wide string.
        let length = unsafe { (0..).take_while(|i| *text.add(*i as usize) != 0).count() };
        // SAFETY: `length` units of that string are readable.
        let slice = unsafe { std::slice::from_raw_parts(text, length) };
        let owner_sid = String::from_utf16_lossy(slice);
        drop(owned_text);
        if owner_sid != user_scope()?.identity {
            // Someone else's pipe wearing our name: say nothing to it. Note this
            // compares the account, not the group: a pipe an administrator owns
            // is not ours even when we could take it.
            return Err(io::Error::other("the endpoint is owned by another user"));
        }
        // SAFETY: the handle is a valid, overlapped pipe handle that we own and
        // do not use again; tokio takes ownership of it here.
        unsafe {
            tokio::net::windows::named_pipe::NamedPipeClient::from_raw_handle(
                std::os::windows::io::IntoRawHandle::into_raw_handle(owned),
            )
        }
    }
}

pub use imp::user_scope;
#[cfg(windows)]
pub use imp::{create_pipe, open_pipe};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scope_names_this_account_and_session() {
        let scope = user_scope().expect("the system knows who we are");
        assert!(!scope.identity.is_empty());
        let tag = scope.tag();
        assert!(tag.contains(&scope.identity));
        // Two calls must agree, or an endpoint name would move under us.
        assert_eq!(user_scope().unwrap(), scope);
    }

    #[cfg(windows)]
    #[test]
    fn the_scope_is_a_real_sid_on_windows() {
        let scope = user_scope().unwrap();
        assert!(
            scope.identity.starts_with("S-1-"),
            "not a SID: {}",
            scope.identity
        );
    }

    /// The owner is stated in the descriptor, so it is the account either way:
    /// an elevated process would otherwise stamp the Administrators group and
    /// fail its own client check.
    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_we_made_is_owned_by_the_account_that_made_it() {
        let name = format!(
            r"\\.\pipe\fhd-owner-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let _server = create_pipe(&name, true).expect("create");
        // open_pipe refuses anything whose owner is not this account, so its
        // success is the assertion.
        open_pipe(&name).expect("the pipe is owned by this account");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn a_pipe_we_made_is_one_we_will_talk_to() {
        let name = format!(
            r"\\.\pipe\fhd-platform-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let server = create_pipe(&name, true).expect("create");
        // Taking the same name again is refused: that is how a squatter shows up.
        assert!(create_pipe(&name, true).is_err());
        let client = open_pipe(&name).expect("the owner check accepts our own pipe");
        server.connect().await.expect("connect");
        drop(client);
        drop(server);
    }
}
