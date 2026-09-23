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
                ConvertStringSidToSidW, SDDL_REVISION_1,
            },
            EqualSid, GetTokenInformation, TokenUser, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
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
        // Aligned for the pointer inside TOKEN_USER: a Vec<u8> is byte-aligned,
        // and a reference to a misaligned TOKEN_USER is undefined behaviour even
        // where the allocator happens to return a suitable address.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
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
        // inside that same buffer, which outlives this borrow, and the buffer is
        // 8-aligned because it is a Vec<u64>.
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
        // D: the access control list. A: allow, FA: full access, P: protected.
        // Only the account itself: LocalSystem needs nothing here, and granting
        // it would make every process running as SYSTEM an authorised client of
        // an ordinary user's engine, since this list is the whole authorisation.
        // S: the mandatory label. ML at medium, NR|NW|NX: no read, write or
        // execute up, so a lower-integrity process cannot reach the pipe.
        let sddl = format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;ME)");
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

    /// Everything below medium integrity is a process that could not have
    /// applied this label, which is the property the check rests on.
    const MEDIUM: u32 = 8192;
    /// Instances of the pipe that may exist at once. It is the real ceiling on
    /// concurrent clients on Windows, so it matches the socket layer's budget
    /// rather than quietly undercutting it.
    pub const MAX_INSTANCES: usize = 32;

    /// A principal named in a descriptor, as a SID the system allocated. Accepts
    /// both spellings SDDL uses: a literal `S-1-...` and a two-letter alias.
    fn parse_sid(text: &str) -> Option<Local> {
        let wide: Vec<u16> = std::ffi::OsStr::new(text)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut sid: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a null-terminated wide string that outlives the call,
        // and `sid` is a valid out-parameter the system allocates into.
        let parsed = unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) };
        if parsed == 0 || sid.is_null() {
            return None;
        }
        Some(Local(sid))
    }

    /// Whether two principals named in a descriptor are the same account.
    ///
    /// Windows prints a well-known SID as its SDDL alias when it converts a
    /// descriptor to text: `LA` for the account that built the machine, `SY` for
    /// the system. So the text of a descriptor we asked for does not have to
    /// come back as the text we asked with, even though the account is
    /// identical. Comparing the strings made the engine refuse its own pipe on
    /// every account that has an alias -- an administrator account among them,
    /// which is why the build machine found this and a developer's did not. An
    /// account is a SID, so this compares SIDs.
    fn same_principal(printed: &str, ours: &str) -> bool {
        if printed == ours {
            return true;
        }
        let (Some(printed), Some(ours)) = (parse_sid(printed), parse_sid(ours)) else {
            return false;
        };
        // SAFETY: both pointers came back from `ConvertStringSidToSidW`, so each
        // points at a valid SID, and both `Local` guards live to the end of this
        // function.
        unsafe { EqualSid(printed.0, ours.0) != 0 }
    }

    /// Whether this descriptor is one this account's engine would have created:
    /// owned by the account, carrying a mandatory label at medium or above, and
    /// granting nothing to a group that would let anyone else in.
    ///
    /// Both answers can be tested: a descriptor a sandboxed process could
    /// produce must be refused, not merely a foreign owner.
    pub fn acceptable_descriptor(sddl: &str, sid: &str) -> bool {
        // The owner runs from after "O:" to the letter that opens the next
        // section. Splitting on the letters themselves would cut a SID in half,
        // since every one of them begins with S.
        let Some(rest) = sddl.strip_prefix("O:") else {
            return false;
        };
        let owner = match rest.find(':') {
            Some(next) => &rest[..next.saturating_sub(1)],
            None => rest,
        };
        if !same_principal(owner, sid) {
            return false;
        }
        // Anything that would admit more than this account.
        const BROAD: [&str; 8] = [
            ";;;WD)",
            ";;;AC)",
            ";;;BU)",
            ";;;AU)",
            ";;;IU)",
            ";;;S-1-1-0)",
            ";;;S-1-5-32-545)",
            ";;;S-1-15-2-1)",
        ];
        if BROAD.iter().any(|principal| sddl.contains(principal)) {
            return false;
        }
        // The label: a process may not label an object above its own integrity,
        // so a medium label cannot come from a low-integrity or AppContainer
        // process running as this same account.
        let Some(label) = sddl.split("(ML;;").nth(1) else {
            return false;
        };
        let Some(level) = label
            .split(";;;")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
        else {
            return false;
        };
        match level {
            "ME" | "HI" | "SI" => true,
            other => other
                .strip_prefix("S-1-16-")
                .and_then(|value| value.parse::<u32>().ok())
                .is_some_and(|value| value >= MEDIUM),
        }
    }

    /// This object's owner, group, access list and label, as text.
    fn describe(handle: HANDLE) -> io::Result<String> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
        };
        const OWNER: u32 = 0x0000_0001;
        const GROUP: u32 = 0x0000_0002;
        const DACL: u32 = 0x0000_0004;
        const LABEL: u32 = 0x0000_0010;
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: the out-parameter is valid and the system allocates into it;
        // every other pointer argument is optional and passed as null.
        let queried = unsafe {
            GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER | GROUP | DACL | LABEL,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if queried != 0 || descriptor.is_null() {
            return Err(io::Error::other("the endpoint's descriptor is unreadable"));
        }
        let owned = Local(descriptor);
        let mut text: *mut u16 = ptr::null_mut();
        let mut length = 0u32;
        // SAFETY: `descriptor` is a valid self-relative descriptor that outlives
        // the call; both out-parameters are valid.
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                OWNER | GROUP | DACL | LABEL,
                &mut text,
                &mut length,
            )
        };
        drop(owned);
        if converted == 0 || text.is_null() {
            return Err(io::Error::other("the endpoint's descriptor is unreadable"));
        }
        let owned_text = Local(text.cast());
        // SAFETY: the system returned `length` units of a wide string.
        let slice = unsafe { std::slice::from_raw_parts(text, length as usize) };
        let described = String::from_utf16_lossy(slice);
        drop(owned_text);
        Ok(described.trim_end_matches('\0').to_owned())
    }

    /// Whether two named principals are one account, for a test that has to
    /// compare what the system printed against what this account is.
    #[cfg(test)]
    pub(crate) fn same_principal_for_test(printed: &str, ours: &str) -> bool {
        same_principal(printed, ours)
    }

    /// The descriptor of a pipe we are holding. Only tests need this: production
    /// reads the descriptor of a pipe it is about to talk to, not one it made.
    #[cfg(test)]
    pub(crate) fn describe_for_test(
        server: &tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> io::Result<String> {
        use std::os::windows::io::AsRawHandle;
        describe(server.as_raw_handle() as HANDLE)
    }

    /// Creates one instance of a pipe only this user can reach. `first` asks the
    /// system to refuse if the name already exists, which is how a squatter is
    /// detected rather than silently joined. Must be called inside a Tokio
    /// runtime with the I/O driver enabled.
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
            .max_instances(MAX_INSTANCES);
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

    /// Opens the pipe only when it is this account's engine: the owner, and a
    /// mandatory label no sandboxed process of the same account could have
    /// applied. A client that skipped this would hand its request -- and any
    /// credential in it -- to whoever took the name first, which is the attack
    /// §3.1 names. Must be called inside a Tokio runtime with the I/O driver.
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
        // The owner alone is not enough. A sandboxed process running as this
        // same account can create a pipe, and it owns what it creates -- so an
        // owner check would pass and the client would hand it the request. What
        // such a process cannot do is stamp a mandatory label at or above medium
        // integrity, because a process may not label an object above its own
        // level. So the descriptor is what is checked, not the owner alone.
        let descriptor_text = describe(handle)?;
        if !acceptable_descriptor(&descriptor_text, &user_scope()?.identity) {
            return Err(io::Error::other(
                "the endpoint is not this account's engine",
            ));
        }
        let _ = owner_sid;
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
pub use imp::{acceptable_descriptor, create_pipe, open_pipe};

#[cfg(test)]
mod tests {
    use super::*;

    /// A name no other test in this process will claim.
    #[cfg(windows)]
    fn pipe_name(label: &str) -> String {
        format!(
            r"\\.\pipe\fhd-platform-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }

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

    /// The descriptor the kernel actually stamped, read back. Without this the
    /// access list and the label could both be dropped and every other test here
    /// would still pass.
    #[cfg(windows)]
    #[tokio::test]
    async fn the_pipe_carries_the_descriptor_we_asked_for() {
        let name = pipe_name("descriptor");
        let server = create_pipe(&name, true).expect("create");
        let sid = user_scope().unwrap().identity;
        let described = super::imp::describe_for_test(&server).expect("read the descriptor back");
        // Asserted as identity, not as spelling: the system prints a well-known
        // SID as its alias, so a machine whose account has one would fail a text
        // comparison while owning the pipe perfectly well.
        let owner = described
            .strip_prefix("O:")
            .and_then(|rest| rest.find(':').map(|next| &rest[..next - 1]))
            .expect("the descriptor names an owner");
        assert!(
            super::imp::same_principal_for_test(owner, &sid),
            "the account does not own it: {described}"
        );
        assert!(
            described.contains("(ML;;"),
            "no mandatory label was applied: {described}"
        );
        // Exactly one access entry, for this account: nothing was widened.
        assert_eq!(
            described.matches("(A;").count(),
            1,
            "more than this account may reach it: {described}"
        );
        // The entry ends at its own ')': closing it first keeps the label's
        // trailing fields, which are also ';;;'-separated, out of the answer.
        let granted = described
            .split("(A;")
            .nth(1)
            .and_then(|rest| rest.split(')').next())
            .and_then(|entry| entry.rsplit(";;;").next())
            .expect("the access entry names a principal");
        assert!(
            super::imp::same_principal_for_test(granted, &sid),
            "the entry is not for this account: {described}"
        );
        // And the check the client runs accepts precisely this.
        assert!(acceptable_descriptor(&described, &sid));
    }

    /// What a process in a sandbox, running as this same account, could produce.
    /// It owns what it creates, so an owner check alone would admit it.
    #[cfg(windows)]
    #[test]
    fn a_descriptor_a_sandboxed_process_could_make_is_refused() {
        let sid = "S-1-5-21-1-2-3-1001";
        let ours = format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;ME)");
        assert!(acceptable_descriptor(&ours, sid));
        for refused in [
            // No label at all: the ordinary product of a low-integrity creator.
            format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})"),
            // A label it could apply -- its own level, below medium.
            format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;LW)"),
            format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;S-1-16-4096)"),
            // Owned by somebody else entirely.
            format!("O:S-1-5-21-9-9-9-500G:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;ME)"),
            // Correct label, but open to everyone.
            format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;WD)S:(ML;;NRNWNX;;;ME)"),
            // Open to every AppContainer.
            format!("O:{sid}G:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;AC)S:(ML;;NRNWNX;;;ME)"),
        ] {
            assert!(
                !acceptable_descriptor(&refused, sid),
                "accepted a descriptor this account's engine would never create: {refused}"
            );
        }
    }

    /// The build machine caught what a developer's machine could not: the system
    /// prints a well-known SID as its SDDL alias, so the descriptor of a pipe we
    /// just created comes back spelled differently from the SID we created it
    /// with. Comparing text refused our own pipe on any account with an alias,
    /// which is every administrator account. These two spellings must agree, and
    /// two different accounts must still not.
    #[cfg(windows)]
    #[test]
    fn a_well_known_account_is_recognised_under_either_spelling() {
        // `LA` is how the system writes the account that built the machine.
        let literal = super::imp::same_principal_for_test("LA", "LA");
        assert!(literal, "an alias does not even match itself");
        let system = "S-1-5-18";
        assert!(
            super::imp::same_principal_for_test("SY", system),
            "the alias and the SID of the system account were read as two accounts"
        );
        assert!(
            super::imp::same_principal_for_test(system, "SY"),
            "the comparison is not symmetric"
        );
        assert!(
            !super::imp::same_principal_for_test("SY", "S-1-5-19"),
            "two different well-known accounts were read as one"
        );
        // Nonsense resolves to nothing and must not be treated as a match.
        assert!(!super::imp::same_principal_for_test("ZZ", system));
        assert!(!super::imp::same_principal_for_test("", system));
        // And the whole check, with the owner written the way the system writes it.
        let sid = "S-1-5-21-1-2-3-1001";
        assert!(acceptable_descriptor(
            &format!("O:SYG:{sid}D:P(A;;FA;;;{sid})S:(ML;;NRNWNX;;;ME)"),
            system
        ));
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
