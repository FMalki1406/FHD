//! Operating-system primitives the rest of the engine cannot express safely.
//!
//! This is the one crate Â§4 allows `unsafe`, and it exists for a single reason:
//! Â§3.1's control surface needs a Windows named pipe that carries the user's SID
//! and session in its name, is created with a security descriptor only that user
//! can reach, and can be checked by the client for who owns it before it sends a
//! byte. None of that is expressible without calling Win32 directly.
//!
//! Every `unsafe` block here states what makes the call sound. Nothing in this
//! crate decides policy: it reports what the system says and hands back handles.
// `deny` rather than `forbid` off Windows, so that named places can lift it and
// nothing else can. `forbid` cannot be overridden at all, which sounds stronger
// and in practice pushed the answer into a probe file that had to guess a unique
// name and failed closed at random when two callers guessed the same one.
// Reviewed calls are the smaller risk. Every other `unsafe` off Windows still
// fails the build, and every allowance is named in `tools/check-architecture.mjs`
// against the item it sits on.
//
// There are two off Windows: `our_uid` calls `geteuid(2)`, and the Linux
// `link_into_directory` calls `linkat(2)` using the held source and directory.
// macOS has no corresponding publication call and refuses publication.
#![cfg_attr(not(windows), deny(unsafe_code))]
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
    /// and session without being a secret, which is exactly Â§3.1's requirement.
    pub fn tag(&self) -> String {
        format!("{}-{}", self.identity, self.session)
    }
}

/// What an owner means for a directory we are asked to adopt.
///
/// Split out from the Win32 call so the rule can be exercised without the
/// privilege that creating a directory owned by somebody else requires. What is
/// tested here is the decision; that the owner is read at all, and that a real
/// foreign-owned directory is refused, is a separate check needing a second
/// account -- recorded as such rather than claimed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// Ours, or an account that can take ownership anyway.
    Trusted,
    /// Somebody else. An owner holds WRITE_DAC whatever the access list says, so
    /// they can re-grant themselves at any moment.
    Foreign,
    /// The system reported no owner. Refused rather than assumed.
    Missing,
}

/// Decides what an owner SID means, given who we are.
///
/// `owner` is `None` when the descriptor carried none. The trusted set is this
/// account, the system, and the local administrators: an administrator can take
/// ownership regardless, so naming them a finding would be noise.
pub fn judge_owner(owner: Option<&str>, us: &str) -> OwnerVerdict {
    // `NT SERVICE\TrustedInstaller`, the Windows servicing identity. It is here
    // for a reason inside the trust model, not because of a privilege ranking:
    // becoming it requires Administrator or SYSTEM, both already in this set, so
    // it widens the set by nothing.
    //
    // It is needed because the Windows servicing roots are owned by it. Measured
    // on this machine, 2026-09-23: `C:\` and `C:\Program Files` are
    // TrustedInstaller's; `C:\Users` and `C:\Users\<name>` are SYSTEM's. An
    // earlier comment here named `C:\Users` and was wrong -- the load-bearing
    // component is `C:\` itself, which the walk reads as the delete-child parent
    // of `C:\Users`. Calling it foreign refuses every path on the system volume.
    //
    // And it is trusted only as an *owner*. It is absent from the access-list
    // trusted sets in `foreign_writers` and `holders`, so an entry granting it
    // write is still reported.
    const TRUSTED_INSTALLER: &str =
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    match owner {
        None => OwnerVerdict::Missing,
        Some(owner) if owner == us => OwnerVerdict::Trusted,
        Some("S-1-5-18") | Some("S-1-5-32-544") | Some(TRUSTED_INSTALLER) => OwnerVerdict::Trusted,
        Some(_) => OwnerVerdict::Foreign,
    }
}

/// A path component an untrusted account could rename, and who could do it.
///
/// Protecting the state directory settles who may write *into* it. It says
/// nothing about who may move it aside: renaming needs `DELETE` on the component
/// itself or `FILE_DELETE_CHILD` on its parent, and neither is a right the
/// directory's own list grants. If any component of the path can be swapped, then
/// every check made against that path describes a directory that may no longer be
/// the one we open a moment later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwappableComponent {
    pub path: std::path::PathBuf,
    pub principals: Vec<String>,
}

/// Who may write to a directory besides the people we already trust.
///
/// "Trusted" is the account that runs the engine, the system account, and the
/// local administrators: an administrator can take ownership and SYSTEM can read
/// anything, so listing them would be noise rather than a finding.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ForeignWriters(Vec<String>);
impl ForeignWriters {
    /// The SIDs, as text, of every principal outside the trusted set that the
    /// directory's own access list grants write access to.
    pub fn sids(&self) -> &[String] {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::ffi::{CString, OsStr};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::fs::File;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::io::AsRawFd;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::path::Path;

    /// Not available without a platform call this crate does not yet make.
    pub fn process_cpu() -> Option<std::time::Duration> {
        None
    }

    /// Creates `name` inside `directory` as another name for the file this
    /// handle holds.
    ///
    /// **The source is the open file description, not a path**, which is the
    /// whole reason this exists rather than `std::fs::hard_link`. `hard_link`
    /// resolves two paths when it runs, so between proving some bytes and
    /// publishing them either end can be made to mean something else. The
    /// Windows side of this crate fixes both ends with handles; this is the
    /// same guarantee where the system offers one.
    ///
    /// **Linux.** `linkat(AT_FDCWD, "/proc/self/fd/N", dirfd, name,
    /// AT_SYMLINK_FOLLOW)`. The magic symlink under `/proc/self/fd` resolves to
    /// the inode the descriptor holds, and `AT_SYMLINK_FOLLOW` makes `linkat`
    /// follow it to that inode rather than linking the symlink -- so the object
    /// published is the object verified when the kernel permits linking it.
    /// The destination is `dirfd` plus one component, so no destination parent
    /// path is resolved again. The case where the source has no remaining name
    /// has not been measured and is not needed to prove a successful link safe.
    ///
    /// `AT_EMPTY_PATH` would say this more directly and is not usable: for
    /// `linkat` the kernel requires `CAP_DAC_READ_SEARCH` for it, which a
    /// download manager does not have and should not want. The procfs route is
    /// the unprivileged equivalent and is what `O_TMPFILE` users are told to
    /// use. Its cost is a dependency on `/proc` being mounted; where it is not,
    /// this fails rather than falling back to a path.
    ///
    /// **macOS.** This function is Linux-only. macOS currently refuses
    /// publication; a prior `F_GETPATH` proposal was rejected because it would
    /// re-resolve the source name between verification and linking.
    ///
    /// **Never replaces.** `linkat` fails with `EEXIST` on an occupied name,
    /// which surfaces as `AlreadyExists`.
    ///
    /// **A failure creates nothing.** `linkat` is one system call: it either
    /// creates the name or reports why it did not. The port's contract requires
    /// that, because a refused link is recorded as "nothing was made" and the
    /// part is unsealed on that basis.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
        // A relative name under a directory is exactly one component. Any
        // separator would reopen the path resolution this call exists to avoid,
        // and an interior NUL cannot cross the C boundary at all.
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(std::path::Component::Normal(_)), None) => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a link name must be a single path component",
                ));
            }
        }
        let leaf = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a link name holds a NUL"))?;
        let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a descriptor with a NUL"))?;

        // SAFETY: both descriptors are borrowed from open `File`s and outlive
        // the call; `source` and `leaf` are NUL-terminated and stay alive for
        // its duration. `linkat` reads them and returns a status, taking no
        // ownership of either. `AT_SYMLINK_FOLLOW` is what makes the procfs
        // entry resolve to the object the descriptor holds rather than to the
        // magic symlink itself.
        let created = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                directory.as_raw_fd(),
                leaf.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if created == 0 {
            return Ok(());
        }
        Err(io::Error::last_os_error())
    }

    /// Copies the file this handle holds into `directory` under `name`, by
    /// cloning it.
    ///
    /// **Measured, not adopted.** Nothing in the engine calls this: macOS still
    /// refuses to publish. It exists so the one remaining candidate mechanism
    /// there can be measured on a real macOS rather than argued about, which is
    /// what `docs/publication-contract.md` section 11 asks for before anything
    /// is built on it.
    ///
    /// `fclonefileat(2)` is the only call on macOS that takes **an open
    /// descriptor as its source** and a directory descriptor plus one name as
    /// its destination. Everything else there starts from a path, and a path is
    /// what publication must not re-resolve: between proving some bytes and
    /// publishing them, a name can be made to mean another file.
    ///
    /// **What it is not.** It does not create a hard link. It creates a new
    /// inode that shares storage copy-on-write, so the published file and the
    /// part are *different objects* holding the same bytes. That difference is
    /// the reason this is not simply wired in: the engine claims `At` only when
    /// the requested path leads to the object it published, and it currently
    /// asks that question about the part. Adopting this means `link` handing
    /// back the object it created so the comparison is against that -- which is
    /// the sentence the publication code already uses, and does not yet do.
    ///
    /// It needs APFS. On any other filesystem it fails rather than copying, and
    /// a copy is not what publication may quietly fall back to.
    #[cfg(target_os = "macos")]
    #[allow(unsafe_code)]
    pub fn clone_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(std::path::Component::Normal(_)), None) => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a link name must be a single path component",
                ));
            }
        }
        let leaf = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a link name holds a NUL"))?;

        // SAFETY: both descriptors are borrowed from open `File`s and outlive
        // the call; `leaf` is NUL-terminated and owned here for its duration.
        // `fclonefileat` reads them and returns a status, taking ownership of
        // nothing. The flags are zero: no `CLONE_NOFOLLOW` is wanted, because
        // the source is a descriptor rather than a name, and nothing here wants
        // to drop ownership information.
        let created = unsafe {
            libc::fclonefileat(file.as_raw_fd(), directory.as_raw_fd(), leaf.as_ptr(), 0)
        };
        if created == 0 {
            return Ok(());
        }
        Err(io::Error::last_os_error())
    }

    /// Unix identifies the peer by credentials on the socket itself, so the name
    /// carries nothing: `fhd-ipc` checks ownership of the directory and socket
    /// and asks the kernel who connected.
    pub fn user_scope() -> io::Result<UserScope> {
        Ok(UserScope {
            identity: "unix".to_owned(),
            session: 0,
        })
    }

    /// Who besides us may write into this directory, from its mode and owner.
    ///
    /// This used to answer "nobody", on the reasoning that Unix sets the mode it
    /// wants rather than inheriting one. That is true of a directory we create
    /// and false of one we find -- and the caller's whole question is about one
    /// it found. A review pointed out the consequence: on Unix a `.fhd-parts`
    /// somebody else had already made, world-writable, passed this check and was
    /// adopted, while the same case on Windows was refused.
    ///
    /// Group and other write are reported, and so is an owner who is not us,
    /// because an owner can put the mode back whatever we set. Read access is
    /// not reported here: the name says writers, and the caller refuses on
    /// anything non-empty either way.
    pub fn foreign_writers(path: &std::path::Path) -> io::Result<ForeignWriters> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)?;
        let mut foreign = Vec::new();
        // Group- or other-writable. The sticky bit narrows deletion, not
        // writing, so it does not make this safe.
        let mode = metadata.mode();
        if mode & 0o020 != 0 {
            foreign.push(format!("group:{}", metadata.gid()));
        }
        if mode & 0o002 != 0 {
            foreign.push("other".to_owned());
        }
        let us = our_uid();
        if metadata.uid() != us {
            foreign.push(format!("owner:{}", metadata.uid()));
        }
        Ok(ForeignWriters(foreign))
    }

    /// The effective user id of this process.
    ///
    /// `geteuid(2)` answers it directly, cannot fail, and returns the id the
    /// kernel uses for the permission checks this module is reasoning about --
    /// which is what makes it the right question rather than merely the
    /// convenient one.
    ///
    /// Two workarounds preceded it and both were worse. A probe file had to
    /// invent a unique name, and when two parallel callers invented the same one
    /// the read failed and the answer became "owner unknown", which reads as a
    /// foreign owner -- so the engine refused a directory it had just created,
    /// at random, on a macOS runner. `/proc/self` is Linux-only, and its
    /// ownership is a property of a filesystem rather than of the call, so it
    /// would have needed its own argument about when that property holds.
    ///
    /// The `unsafe` is one call with no arguments, no pointers and no failure
    /// mode, and `deny` rather than `forbid` at the top of this file is what
    /// allows exactly this one and nothing else.
    #[allow(unsafe_code)]
    fn our_uid() -> u32 {
        // SAFETY: `geteuid` takes nothing, returns a `uid_t` by value, touches
        // no memory this side owns, and is documented as always succeeding.
        unsafe { libc::geteuid() }
    }

    /// Replaces an inherited access list with one of our own.
    ///
    /// Nothing to do on Unix, and deliberately: there is no inherited list
    /// there, only a umask, and a directory that came out of the umask
    /// group-writable has already been that way for as long as it has existed.
    /// Setting the mode afterwards closes nothing -- it leaves the window it was
    /// meant to remove, which is the create-then-repair pattern the Windows half
    /// of this module was rewritten to get rid of.
    ///
    /// The secure primitive is `create_protected_directory`, which passes the
    /// mode to `mkdir(2)` so the directory never exists unprotected. Callers
    /// wanting a private directory on Unix use that one.
    ///
    /// And a directory we merely found is not narrowed here. Changing an
    /// operator's permissions unasked is a worse surprise than declining to use
    /// the directory, which is what `own_directory` does instead.
    pub fn protect_new_directory(_: &std::path::Path) -> io::Result<()> {
        Ok(())
    }

    /// Not implemented, and this returns "nothing found" rather than "not
    /// examined" -- so `STATE-PATH-SWAPPABLE` can never fire on Unix.
    ///
    /// An earlier comment here claimed the opposite. It was wrong, and the
    /// difference matters: a state directory under a group- or world-writable
    /// parent is accepted on Unix exactly as it would have been before any of
    /// this work. Closing it needs `openat`/`O_NOFOLLOW`/`RESOLVE_BENEATH`
    /// walking rather than a permission read. Until then the guarantee names
    /// Unix as unchecked instead of the code implying it is clean.
    pub fn swappable_components(_: &std::path::Path) -> io::Result<Vec<SwappableComponent>> {
        Ok(Vec::new())
    }

    /// Created with its mode, not repaired afterwards.
    ///
    /// `create_dir` then `set_permissions` leaves the directory readable by the
    /// process umask's idea of the world for as long as the two calls take --
    /// the same create-then-repair window the Windows side was rewritten to
    /// remove. `DirBuilder::mode` passes the mode to `mkdir(2)`, so there is no
    /// interval to lose.
    pub fn create_protected_directory(path: &std::path::Path) -> io::Result<bool> {
        use std::os::unix::fs::DirBuilderExt;
        match std::fs::DirBuilder::new().mode(0o700).create(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::fs::File;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::{
        ffi::{c_void, OsStr},
        iter::once,
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr,
    };
    use windows_sys::Wdk::Storage::FileSystem::{
        FileLinkInformation, NtSetInformationFile, FILE_LINK_INFORMATION,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::{
        Foundation::{GetLastError, LocalFree, HANDLE, INVALID_HANDLE_VALUE},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                ConvertStringSidToSidW, GetNamedSecurityInfoW, SetNamedSecurityInfoW,
                SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            EqualSid, GetAce, GetSecurityDescriptorDacl, GetTokenInformation, TokenUser,
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
            INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO},
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

    /// How much processor time this process has used, in total, across every
    /// thread. Measurements need it to say where the work goes; nothing in the
    /// download path reads it.
    pub fn process_cpu() -> Option<std::time::Duration> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the four out-parameters are valid for the call's duration, and
        // GetCurrentProcess is a pseudo-handle that needs no closing.
        let read = unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        };
        if read == 0 {
            return None;
        }
        // Both are hundreds of nanoseconds since the process started.
        let ticks =
            |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        Some(std::time::Duration::from_nanos(
            (ticks(kernel) + ticks(user)) * 100,
        ))
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
    /// sandboxed process of the same account out (Â§3.1, Â§16.1).
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
    /// Everything that counts as writing. `GENERIC_WRITE` and `GENERIC_ALL` are
    /// included because an inherited entry may still carry the generic form, and
    /// `WRITE_DAC`/`WRITE_OWNER` because either one lets the holder grant itself
    /// the rest.
    const WRITE_RIGHTS: u32 = 0x0002   // FILE_WRITE_DATA / FILE_ADD_FILE
        | 0x0004  // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
        | 0x0010  // FILE_WRITE_EA
        // FILE_DELETE_CHILD: deleting the database or a part file destroys work
        // just as surely as rewriting it, and a grant of this alone carries none
        // of the other bits. Leaving it out reported such a directory as clean.
        | 0x0040
        | 0x0100  // FILE_WRITE_ATTRIBUTES
        | 0x0001_0000  // DELETE
        | 0x0004_0000  // WRITE_DAC
        | 0x0008_0000  // WRITE_OWNER
        | 0x1000_0000  // GENERIC_ALL
        | 0x4000_0000; // GENERIC_WRITE

    /// ACE types whose layout begins with a header, a mask and a SID, and which
    /// grant rather than deny. Type 0 is the plain allow entry; type 9 is the
    /// callback form, whose condition Windows evaluates and which can be written
    /// to be true for everyone.
    pub(crate) const ALLOW_TYPES: [u8; 2] = [0, 9];
    /// Denies and audits. Anything not in either list is unknown to this build and
    /// is reported rather than skipped: the next type Microsoft adds must not
    /// punch a silent hole.
    pub(crate) const NON_GRANTING_TYPES: [u8; 5] = [1, 2, 3, 10, 11];
    /// Placeholders that are legitimately inherit-only and name no real account.
    const PLACEHOLDERS: [&str; 2] = ["S-1-3-0", "S-1-3-1"];

    /// Who, besides this account and the system and the administrators, the
    /// directory's access list lets write into it.
    ///
    /// The engine never set permissions on Windows, and what a directory inherits
    /// depends entirely on where it is: under `%LOCALAPPDATA%` the inherited list
    /// is owner, SYSTEM and Administrators, while a directory made on a data
    /// volume or at a drive root inherits `Authenticated Users: Modify` -- every
    /// account on the machine. That directory holds the job database and every
    /// partial file, so it decides whether "the same user" means anything at rest.
    ///
    /// This reports rather than repairs: the caller refuses a directory it cannot
    /// vouch for, which is honest about a path the operator chose. Changing the
    /// permissions of a folder the operator pointed at would be a surprise, and on
    /// a shared or redirected folder a destructive one.
    pub fn foreign_writers(path: &std::path::Path) -> io::Result<ForeignWriters> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut owner: *mut c_void = ptr::null_mut();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a null-terminated path that outlives the call, and the
        // out-parameters are valid. On success the system allocates one descriptor
        // owning both the owner SID and the ACL; `Local` frees it exactly once.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _owned = Local(descriptor);
        let scope = user_scope()?;
        let trusted = [scope.identity.as_str(), "S-1-5-18", "S-1-5-32-544"];
        let known = |sid: *mut c_void| {
            trusted
                .iter()
                .any(|text| parse_sid(text).is_some_and(|known| equal(known.0, sid)))
        };
        let mut foreign: Vec<String> = Vec::new();

        // The owner first, because it is not in the access list at all. An owner
        // holds WRITE_DAC whatever the list says, so a stranger who pre-creates
        // this directory, leaves a list naming only trusted accounts, and keeps
        // ownership can re-grant themselves at any moment. Reading the list alone
        // called that directory clean.
        // The same rule `judge_owner` states, applied to what the system said.
        // Reading it through that function keeps the decision in one place, where
        // it can be tested without a second account.
        let owner_text = (!owner.is_null()).then(|| sid_text(owner)).flatten();
        match judge_owner(owner_text.as_deref(), &scope.identity) {
            OwnerVerdict::Trusted => {}
            OwnerVerdict::Missing => foreign.push("<no owner>".to_owned()),
            OwnerVerdict::Foreign => {
                foreign.push(owner_text.unwrap_or_else(|| "<unreadable owner>".to_owned()));
            }
        }

        // A null access list is not an empty one: it grants everyone everything.
        // Reporting it as "no foreign writers" would invert the answer.
        if dacl.is_null() {
            foreign.push("S-1-1-0".to_owned());
            return Ok(ForeignWriters(foreign));
        }
        // SAFETY: `dacl` points at an ACL inside the descriptor kept alive above.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `index` is below the count the same ACL reported.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                foreign.push("<unreadable entry>".to_owned());
                continue;
            }
            // SAFETY: every ACE begins with a header, whatever follows it. The
            // header is read on its own, before anything is projected through a
            // type the memory might not be.
            let (kind, flags) = unsafe {
                let header = ace.cast::<ACE_HEADER>();
                ((*header).AceType, u32::from((*header).AceFlags))
            };
            // Denies and audits grant nothing. A type this build does not know is
            // reported rather than skipped: the alternative is a new entry type
            // quietly widening a directory we then call clean.
            if NON_GRANTING_TYPES.contains(&kind) {
                continue;
            }
            if !ALLOW_TYPES.contains(&kind) {
                foreign.push(format!("<unknown entry type {kind}>"));
                continue;
            }
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: both allowed types begin with header, mask and SID, and the
            // type was checked above.
            let mask = unsafe { (*ace).Mask };
            if mask & WRITE_RIGHTS == 0 {
                continue;
            }
            // SAFETY: in both allowed types the SID begins at `SidStart`.
            let sid = unsafe { ptr::addr_of!((*ace).SidStart).cast::<c_void>().cast_mut() };
            // An inherit-only entry does not apply to this directory -- but its
            // children are the asset. The database and every part file are created
            // inside it, and an inherit-only grant reaches every one of them. Only
            // an entry that inherits to nothing is genuinely about nothing.
            if flags & INHERIT_ONLY_ACE != 0
                && flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) == 0
            {
                continue;
            }
            // CREATOR OWNER and CREATOR GROUP are placeholders that name no
            // account; they are replaced at creation by the real owner, which the
            // check above already covers.
            if PLACEHOLDERS
                .iter()
                .any(|text| parse_sid(text).is_some_and(|holder| equal(holder.0, sid)))
            {
                continue;
            }
            if known(sid) {
                continue;
            }
            let text = sid_text(sid).unwrap_or_else(|| "<unreadable>".to_owned());
            if !foreign.contains(&text) {
                foreign.push(text);
            }
        }
        Ok(ForeignWriters(foreign))
    }

    /// Gives a directory we just created an access list of its own: this account,
    /// the system and the administrators, and inheritance switched off.
    ///
    /// Only for a directory this process created. What a new directory inherits
    /// depends on where it sits -- under `%LOCALAPPDATA%\Temp` it picks up entries
    /// for packaged applications, and on a data volume or a drive root it picks up
    /// `Authenticated Users: Modify`. Since the state directory holds the job
    /// record and every partial file, it gets stated permissions rather than
    /// inherited ones.
    ///
    /// A directory we did not create is never touched: the operator may have
    /// pointed at something shared or redirected, and rewriting its permissions
    /// would be a worse surprise than refusing it.
    /// Creates the state directory **with** its access list, or reports that it
    /// was already there.
    ///
    /// Creating first and setting permissions afterwards leaves a window in which
    /// the directory carries whatever it inherited -- on a data volume, write
    /// access for every account on the machine. Windows decides access when a
    /// handle is opened, so a handle taken in that window survives the list being
    /// replaced, and a file planted in it is already inside. Handing the list to
    /// `CreateDirectoryW` closes the window: there is no moment when the
    /// directory exists under anything but its stated permissions.
    ///
    /// Returns whether this call created it. `false` means it was already there,
    /// and a directory we did not create is inspected rather than rewritten.
    pub fn create_protected_directory(path: &std::path::Path) -> io::Result<bool> {
        use windows_sys::Win32::Foundation::ERROR_ALREADY_EXISTS;
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
        let (_descriptor, attributes) = owner_only_directory_descriptor()?;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
        // SAFETY: `wide` is a null-terminated path and `attributes` points at a
        // SECURITY_ATTRIBUTES whose descriptor lives until this function returns;
        // the call copies what it needs before that.
        let made = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) };
        // Non-zero is success, and success means this call is what created it.
        if made != 0 {
            return Ok(true);
        }
        let error = last_error();
        if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
            return Ok(false);
        }
        Err(error)
    }

    /// The access list a state directory gets: this account, the system and the
    /// administrators, inheritance off, inherited by what is created inside.
    fn owner_only_directory_descriptor() -> io::Result<(Local, SECURITY_ATTRIBUTES)> {
        let sid = user_scope()?.identity;
        let sddl = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        descriptor_from(&sddl)
    }

    /// Builds a descriptor from SDDL and the attributes that carry it.
    fn descriptor_from(sddl: &str) -> io::Result<(Local, SECURITY_ATTRIBUTES)> {
        let wide: Vec<u16> = std::ffi::OsStr::new(sddl)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a null-terminated wide string that outlives the call,
        // and `descriptor` is a valid out-parameter the system allocates into.
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
        Ok((
            Local(descriptor),
            SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        ))
    }

    pub fn protect_new_directory(path: &std::path::Path) -> io::Result<()> {
        let sid = user_scope()?.identity;
        // OICI: the same entries are inherited by what we create inside, so the
        // parts and the database do not each need their own call. P: protected,
        // so nothing the parent grants leaks back in.
        let sddl = format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
        let wide: Vec<u16> = std::ffi::OsStr::new(&sddl)
            .encode_wide()
            .chain(once(0))
            .collect();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a null-terminated wide string that outlives the call,
        // and `descriptor` is a valid out-parameter the system allocates into.
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
        let mut dacl: *mut ACL = ptr::null_mut();
        let (mut present, mut defaulted) = (0, 0);
        // SAFETY: `descriptor` is a valid descriptor built above, and the three
        // out-parameters are valid for the call.
        let read = unsafe {
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
        };
        if read == 0 || present == 0 || dacl.is_null() {
            return Err(last_error());
        }
        let target: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
        // SAFETY: `target` is a null-terminated path and `dacl` points inside the
        // descriptor, which `owned` keeps alive until after this call returns.
        let status = unsafe {
            SetNamedSecurityInfoW(
                target.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        drop(owned);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    /// Rights that let the holder move a directory aside. `DELETE` on the
    /// component itself, and `FILE_DELETE_CHILD` on its parent, which permits
    /// deleting a child regardless of that child's own list.
    /// Rights that let the holder move a component aside. `DELETE` is the
    /// obvious one; `WRITE_DAC` and `WRITE_OWNER` are here for the reason
    /// `WRITE_RIGHTS` already gives -- either one lets the holder grant itself
    /// the rest and then delete at leisure. Leaving them out reported a directory
    /// whose list said `Everyone:(WDAC,WO)` as unswappable.
    const RENAME_RIGHTS: u32 = 0x0001_0000 | 0x0004_0000 | 0x0008_0000;
    /// The same, on the parent: delete-child reaches a component whatever its own
    /// list says, and either of the other two buys delete-child.
    const DELETE_CHILD: u32 = 0x0000_0040 | 0x0004_0000 | 0x0008_0000;

    /// Every component of `path`, from the root down, that somebody outside the
    /// trusted set could rename or delete.
    ///
    /// Giving the state directory a list of its own decides who may write into
    /// it. It does not decide who may replace it: on a data volume every ancestor
    /// typically grants `Authenticated Users: Modify`, and a directory whose
    /// parent grants delete-child can be moved aside between the moment it is
    /// checked and the moment it is opened -- after which every check describes a
    /// directory that is no longer there.
    /// Whether two spellings name the same directory.
    ///
    /// `canonicalize` returns `\\?\D:\x` where `absolute` returns `D:\x`, so a
    /// plain equality check never matched and every component of the resolved
    /// chain was read a second time -- twice the security reads on every start,
    /// for nothing. Comparison ignores the verbatim prefix and case, which is
    /// what NTFS itself does.
    fn same_path(left: &std::path::Path, right: &std::path::Path) -> bool {
        fn plain(path: &std::path::Path) -> String {
            let text = path.to_string_lossy();
            let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
            text.trim_end_matches('\\').to_lowercase()
        }
        plain(left) == plain(right)
    }

    /// Every directory on the way to `path`, root first.
    fn ancestors(path: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut chain: Vec<std::path::PathBuf> =
            path.ancestors().map(std::path::Path::to_path_buf).collect();
        chain.reverse();
        chain
    }

    pub fn swappable_components(path: &std::path::Path) -> io::Result<Vec<SwappableComponent>> {
        // Both chains, because neither one alone is the set of directories that
        // can move us. A security review demonstrated the half that was missing:
        // with `base\gate` granting another account Modify and `base\gate\link`
        // a junction onto a clean `base\real`, every check passed -- and then
        // `gate` was used to repoint `link` at the attacker's directory, and the
        // next open by path landed there. `gate` and `link` are exactly what
        // canonicalising erases.
        //
        // So: the resolved chain catches a junction *we* were pointed through
        // onto hostile ground, and the typed chain catches the hostile ground
        // that *holds the junction*. Missing either is a path somebody else can
        // swap while the check says clean.
        //
        // Every component is judged on its own parent rather than on its place
        // in a list, because several chains concatenated have no single
        // ordering.
        //
        // And the two endpoints are not enough either. A second review built
        // `clean\link2` -> `mid\link3` -> `real`, granting only `mid` to another
        // account: `canonicalize` jumps to `real` and the typed spelling stops
        // at `link2`, so `mid` -- the directory that actually holds the redirect
        // -- appears in neither. The same is true of a path reached through a
        // `subst` drive. Both were refused, but only because the component was
        // flagged as a reparse point, which named nobody and rested on a clause
        // no test constrained.
        //
        // So every redirect is followed to what it points at, and that target's
        // own ancestors are walked too. The question the check answers is "who
        // can move us", and that is whoever holds any hop on the way.
        let mut chain: Vec<std::path::PathBuf> = Vec::new();
        let mut pending = vec![std::path::absolute(path)?, std::fs::canonicalize(path)?];
        // A junction may point at a path that leads back through itself, and a
        // deep tree costs a security read per component, so the walk is bounded
        // rather than trusted to terminate on its own.
        const COMPONENT_LIMIT: usize = 512;
        while let Some(next) = pending.pop() {
            for component in ancestors(&next) {
                if chain.iter().any(|seen| same_path(seen, &component)) {
                    continue;
                }
                if chain.len() >= COMPONENT_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the state path passes through more directories than this check will walk",
                    ));
                }
                let redirect = std::fs::symlink_metadata(&component)
                    .ok()
                    .filter(|metadata| {
                        use std::os::windows::fs::MetadataExt;
                        metadata.file_attributes() & 0x400 != 0
                    })
                    .and_then(|_| std::fs::read_link(&component).ok());
                chain.push(component);
                if let Some(target) = redirect {
                    pending.push(target);
                }
            }
        }

        let mut found = Vec::new();
        for component in &chain {
            // An unreadable component is a finding, not a pass. Skipping here
            // failed open on the one condition an attacker can induce, while
            // `holders(..)?` a few lines below failed closed on the same one.
            let metadata = match std::fs::symlink_metadata(component) {
                Ok(metadata) => metadata,
                Err(error) => {
                    found.push(SwappableComponent {
                        path: component.clone(),
                        principals: vec![format!("<unreadable: {}>", error.kind())],
                    });
                    continue;
                }
            };
            let mut principals = Vec::new();
            // A reparse point is not itself a finding. It says the path bends
            // here, and the walk above already followed the bend and put what it
            // points at into the chain, so whoever can rewrite the target is
            // named by their own rights rather than by this flag.
            //
            // Reporting the flag alone refused a junction the operator owns
            // outright -- a layout this project's own documentation calls
            // ordinary for somebody short of disk space, and one a download
            // manager invites -- and handed them a count with no principal to
            // act on. A volume mount point would have been refused the same way.
            //
            // What is still a finding is a bend we could not follow, because
            // then the chain is short by however much lies beyond it.
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 && std::fs::read_link(component).is_err()
                {
                    principals.push("<redirect that could not be followed>".to_owned());
                }
            }
            // Who may delete the component outright. A volume root is exempt:
            // `D:\` carries a DELETE grant that means nothing, because no volume
            // root can be renamed -- and its delete-child is still checked below
            // as the parent of the next component, which is the part that bites.
            if component.parent().is_some() {
                for holder in holders(component, RENAME_RIGHTS)? {
                    if !principals.contains(&holder) {
                        principals.push(holder);
                    }
                }
            }
            // And its parent: delete-child there reaches this component whatever
            // its own list says. Taken from the component itself, not from a
            // neighbouring index, so it stays right across both chains.
            if let Some(parent) = component.parent() {
                for holder in holders(parent, DELETE_CHILD)? {
                    if !principals.contains(&holder) {
                        principals.push(holder);
                    }
                }
            }
            if !principals.is_empty() {
                found.push(SwappableComponent {
                    path: component.clone(),
                    principals,
                });
            }
        }
        Ok(found)
    }

    /// Whether two open handles name the same file on the same volume.
    ///
    /// Publication links a path, and verification holds a handle, so the object
    /// proved and the object delivered are two resolutions of one name. Asking
    /// the kernel which object each handle actually refers to is how that gap
    /// becomes visible.
    ///
    /// `GetFileInformationByHandleEx` with `FileIdInfo` answers it: a 128-bit
    /// file id and the volume it lives on, both read from the handle rather than
    /// from a name. `std`'s equivalent (`file_index`, `volume_serial_number`) is
    /// still unstable, which is why this lives here instead of in the storage
    /// adapter -- that crate forbids `unsafe` and may not depend on this one.
    ///
    /// **This detects; it does not prevent.** Linking from the verified handle
    /// is what would prevent, and it needs `NtSetInformationFile` with
    /// `FILE_LINK_INFORMATION`: `SetFileInformationByHandle` does not accept
    /// `FileLinkInfo`, so the documented Win32 surface has no route. Whether to
    /// take the NT one is an open decision, and until it is taken this is the
    /// difference between publishing the wrong bytes and refusing to.
    pub fn same_object(left: &File, right: &File) -> io::Result<bool> {
        fn identity(file: &File) -> io::Result<FILE_ID_INFO> {
            let mut info = FILE_ID_INFO {
                VolumeSerialNumber: 0,
                FileId: Default::default(),
            };
            // SAFETY: the handle is borrowed from a live `File`, the class and
            // the buffer match (`FileIdInfo` expects a `FILE_ID_INFO`), and the
            // size is that buffer's own. Nothing is retained.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle() as HANDLE,
                    FileIdInfo,
                    (&raw mut info).cast(),
                    u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(0),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(info)
        }
        let left = identity(left)?;
        let right = identity(right)?;
        Ok(left.VolumeSerialNumber == right.VolumeSerialNumber
            && left.FileId.Identifier == right.FileId.Identifier)
    }

    /// STATUS_OBJECT_NAME_COLLISION.
    const NAME_COLLISION: u32 = 0xC000_0035;
    /// Without it, opening a directory as a `File` fails on Windows.
    const BACKUP_SEMANTICS: u32 = 0x0200_0000;

    /// Opens a directory as a handle, so a later call can name a file inside the
    /// directory *object* rather than inside whatever the path leads to then.
    ///
    /// `fhd-storage` opens its own, because it may not depend on this crate in
    /// any dependency kind. The duplication is three lines and is deliberate:
    /// the alternative is a dependency the architecture gate refuses.
    pub fn open_directory(path: &Path) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(BACKUP_SEMANTICS)
            .open(path)
    }

    /// Creates `name` inside `directory` as another name for the file this
    /// handle holds.
    ///
    /// **Both ends are handles, and that is the whole point.** `hard_link` takes
    /// two paths and resolves them at the moment it runs, so between proving
    /// some bytes and publishing them either end can be made to mean something
    /// else. Both were measured: the source name was taken over and the other
    /// file's bytes were published; the destination folder was moved aside and a
    /// new directory took its name, and the file landed in that one. A handle
    /// cannot be redirected that way, so `file` fixes *which object* is
    /// published and `directory` fixes *where*. Only the last component is
    /// resolved, and it is resolved inside a directory object already held --
    /// which is why `name` must be one component and is rejected otherwise.
    ///
    /// `SetFileInformationByHandle` has no class for this: `FileLinkInfo` is an
    /// NT-level class, so `NtSetInformationFile` from ntdll is the only route.
    /// **It is not part of the Win32 API contract.** It is documented under the
    /// Windows Driver Kit, exported from ntdll.dll and callable from user mode,
    /// and nothing here pins Microsoft to keeping it so. That limit belongs
    /// beside the mechanism rather than in a footnote.
    ///
    /// Never replaces: `ReplaceIfExists` is false, so an occupied name comes
    /// back as `AlreadyExists`, which is what `hard_link` does today.
    ///
    /// `directory` must be opened with `FILE_FLAG_BACKUP_SEMANTICS`, which is
    /// how a directory is opened at all on Windows.
    #[allow(unsafe_code)]
    pub fn link_into_directory(file: &File, directory: &File, name: &OsStr) -> io::Result<()> {
        // A relative name under a root directory is exactly one component. Any
        // separator, and any drive or root spelling, would reopen the path
        // resolution this call exists to avoid, so it is refused rather than
        // sanitized.
        let mut components = Path::new(name).components();
        match (components.next(), components.next()) {
            (Some(std::path::Component::Normal(_)), None) => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "a link name must be a single path component",
                ));
            }
        }
        let name: Vec<u16> = name.encode_wide().collect();
        let name_bytes = std::mem::size_of_val(name.as_slice());

        // The struct ends in a one-character array the name runs past, so the
        // buffer is the header plus the remaining characters.
        let header = std::mem::size_of::<FILE_LINK_INFORMATION>();
        let total = header + name_bytes.saturating_sub(std::mem::size_of::<u16>());
        let mut buffer = vec![0u64; total.div_ceil(8)];
        let info = buffer.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
        // SAFETY: `buffer` is a `Vec<u64>` large enough for `total` bytes, so it
        // is at least as aligned as this struct and long enough for the header
        // and the name. It outlives the call below.
        unsafe {
            (*info).Anonymous.ReplaceIfExists = false;
            (*info).RootDirectory = directory.as_raw_handle() as HANDLE;
            (*info).FileNameLength = u32::try_from(name_bytes).unwrap_or(0);
            ptr::copy_nonoverlapping(
                name.as_ptr().cast::<u8>(),
                ptr::addr_of_mut!((*info).FileName).cast::<u8>(),
                name_bytes,
            );
        }

        // SAFETY: zeroed is a valid state for this out-parameter, which the call
        // fills in.
        let mut status_block: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is borrowed from a live `File`; the buffer holds a
        // `FILE_LINK_INFORMATION` and its name and is `total` bytes long, which
        // is what is passed; the status block is a live local. Nothing is
        // retained after the call returns.
        let status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle() as HANDLE,
                ptr::addr_of_mut!(status_block),
                buffer.as_ptr().cast(),
                u32::try_from(total).unwrap_or(0),
                FileLinkInformation,
            )
        };
        match status as u32 {
            0 => Ok(()),
            // An occupied name, which callers already handle from `hard_link`.
            NAME_COLLISION => Err(io::Error::from(io::ErrorKind::AlreadyExists)),
            other => Err(io::Error::other(format!(
                "NtSetInformationFile(FileLinkInformation) failed: {other:#010x}"
            ))),
        }
    }

    /// Untrusted principals an object grants any of `rights` to, its owner
    /// included.
    fn holders(path: &std::path::Path, rights: u32) -> io::Result<Vec<String>> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(once(0)).collect();
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut owner: *mut c_void = ptr::null_mut();
        let mut descriptor: *mut c_void = ptr::null_mut();
        // SAFETY: `wide` is a null-terminated path outliving the call, and the
        // out-parameters are valid; the descriptor owns the owner SID and the ACL
        // and is freed once.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                &mut dacl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let _owned = Local(descriptor);
        let scope = user_scope()?;
        let trusted = [scope.identity.as_str(), "S-1-5-18", "S-1-5-32-544"];
        let mut out: Vec<String> = Vec::new();
        // The owner, which no access list mentions. An owner holds WRITE_DAC
        // implicitly, so a component owned by somebody else can be re-granted and
        // then renamed whatever its list says today -- the same argument the
        // state directory's own check makes, applied to every ancestor.
        let owner_text = (!owner.is_null()).then(|| sid_text(owner)).flatten();
        match judge_owner(owner_text.as_deref(), &scope.identity) {
            OwnerVerdict::Trusted => {}
            OwnerVerdict::Missing => out.push("<no owner>".to_owned()),
            OwnerVerdict::Foreign => {
                out.push(owner_text.unwrap_or_else(|| "<unreadable owner>".to_owned()));
            }
        }
        if dacl.is_null() {
            out.push("S-1-1-0".to_owned());
            return Ok(out);
        }
        // SAFETY: `dacl` points inside the descriptor kept alive above.
        let count = unsafe { (*dacl).AceCount };
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: `index` is below the count the ACL reported.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
                out.push("<unreadable entry>".to_owned());
                continue;
            }
            // SAFETY: every ACE begins with a header.
            let (kind, flags) = unsafe {
                let header = ace.cast::<ACE_HEADER>();
                ((*header).AceType, u32::from((*header).AceFlags))
            };
            // Denies and audits grant nothing; a type this build does not know is
            // reported, not skipped. `foreign_writers` already learned this and
            // the rule was not carried over to here.
            if NON_GRANTING_TYPES.contains(&kind) {
                continue;
            }
            if !ALLOW_TYPES.contains(&kind) {
                out.push(format!("<unknown entry type {kind}>"));
                continue;
            }
            // Unlike `foreign_writers`, an inherit-only entry really is about
            // nothing here: this asks who can rename *this* component, and an
            // entry that applies only to its children cannot. Do not "fix" this
            // into agreement with the other function.
            if flags & INHERIT_ONLY_ACE != 0 {
                continue;
            }
            let ace = ace.cast::<ACCESS_ALLOWED_ACE>();
            // SAFETY: the type was checked, so mask and SID are where they belong.
            let mask = unsafe { (*ace).Mask };
            // GENERIC_ALL carries every specific right, delete among them.
            if mask & (rights | 0x1000_0000) == 0 {
                continue;
            }
            // SAFETY: the SID begins at `SidStart` in both allowed types.
            let sid = unsafe { ptr::addr_of!((*ace).SidStart).cast::<c_void>().cast_mut() };
            if trusted
                .iter()
                .any(|text| parse_sid(text).is_some_and(|known| equal(known.0, sid)))
            {
                continue;
            }
            let text = sid_text(sid).unwrap_or_else(|| "<unreadable>".to_owned());
            if !out.contains(&text) {
                out.push(text);
            }
        }
        Ok(out)
    }

    /// Whether two SID pointers name the same account.
    fn equal(a: *mut c_void, b: *mut c_void) -> bool {
        // SAFETY: both point at valid SIDs owned by their callers for this call.
        unsafe { EqualSid(a, b) != 0 }
    }

    /// A SID as text, for a message a person has to act on.
    fn sid_text(sid: *mut c_void) -> Option<String> {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `sid` is a valid SID and `text` a valid out-parameter the
        // system allocates into.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
            return None;
        }
        let owned = Local(text.cast());
        let mut length = 0;
        // SAFETY: the system returned a null-terminated wide string.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` is the count of units before the terminator.
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
        drop(owned);
        Some(value)
    }

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
    /// Â§3.1 names. Must be called inside a Tokio runtime with the I/O driver.
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

/// Exported so it can be measured on a real macOS. Nothing calls it.
#[cfg(target_os = "macos")]
pub use imp::clone_into_directory;
#[cfg(target_os = "linux")]
pub use imp::link_into_directory;
#[cfg(windows)]
pub use imp::{
    acceptable_descriptor, create_pipe, link_into_directory, open_directory, open_pipe, same_object,
};
pub use imp::{
    create_protected_directory, foreign_writers, process_cpu, protect_new_directory,
    swappable_components, user_scope,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory nobody outside the trusted set may write is reported clean,
    /// and one that grants a foreign account write access is reported by name.
    ///
    /// The second half is what makes this test worth having: a check that always
    /// answers "clean" would pass the first half alone, and the engine would adopt
    /// a directory every account on the machine can rewrite.
    #[cfg(windows)]
    #[test]
    fn a_directory_a_stranger_may_write_is_reported() {
        use std::process::Command;
        let base = std::env::temp_dir().join(format!(
            "fhd-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let private = base.join("private");
        let shared = base.join("shared");
        std::fs::create_dir(&private).unwrap();
        std::fs::create_dir(&shared).unwrap();

        // Inheritance is switched off and a single entry for this account is
        // written, which is what a directory the engine may adopt looks like.
        let sid = user_scope().unwrap().identity;
        let ok = Command::new("icacls")
            .arg(&private)
            .args(["/inheritance:r", "/grant"])
            .arg(format!("*{sid}:(OI)(CI)F"))
            .output()
            .expect("icacls runs");
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        assert!(
            foreign_writers(&private).unwrap().is_empty(),
            "a directory only this account may write must be clean"
        );

        // The same, plus write access for a well-known account that is not us:
        // S-1-5-11 is Authenticated Users, which is exactly what a data volume
        // hands out by inheritance.
        let ok = Command::new("icacls")
            .arg(&shared)
            .args(["/inheritance:r", "/grant"])
            .arg(format!("*{sid}:(OI)(CI)F"))
            .arg("/grant")
            .arg("*S-1-5-11:(OI)(CI)M")
            .output()
            .expect("icacls runs");
        assert!(
            ok.status.success(),
            "{}",
            String::from_utf8_lossy(&ok.stderr)
        );
        let foreign = foreign_writers(&shared).unwrap();
        assert!(
            foreign.sids().iter().any(|found| found == "S-1-5-11"),
            "a stranger with write access went unreported: {foreign:?}"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Every way the check used to say "clean" about a directory somebody else
    /// could write. A security review found all four and demonstrated each one
    /// against live Windows; this is what stops them coming back.
    #[cfg(windows)]
    #[test]
    fn the_ways_this_check_used_to_fail_open() {
        use std::process::Command;
        let base = std::env::temp_dir().join(format!(
            "fhd-failopen-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let sid = user_scope().unwrap().identity;
        let mine = format!("*{sid}:(OI)(CI)F");
        let icacls = |dir: &std::path::Path, arguments: &[String]| {
            let out = Command::new("icacls")
                .arg(dir)
                .args(arguments)
                .output()
                .expect("icacls runs");
            assert!(
                out.status.success(),
                "icacls {arguments:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let make = |name: &str| {
            let dir = base.join(name);
            std::fs::create_dir(&dir).unwrap();
            icacls(
                &dir,
                &[
                    "/inheritance:r".to_owned(),
                    "/grant".to_owned(),
                    mine.clone(),
                ],
            );
            assert!(
                foreign_writers(&dir).unwrap().is_empty(),
                "the baseline for {name} is not clean"
            );
            dir
        };

        // 1. Delete-child only. No write bit, but every account on the machine
        //    could delete the job database and every partial file.
        let dir = make("delete-child");
        icacls(
            &dir,
            &["/grant".to_owned(), "*S-1-5-11:(DC,RD,RA,REA,X)".to_owned()],
        );
        assert!(
            !foreign_writers(&dir).unwrap().is_empty(),
            "a grant of delete-child alone was reported clean"
        );

        // 2. Inherit-only. The directory itself grants nothing, and everything
        //    created inside it -- which is the whole asset -- is writable.
        let dir = make("inherit-only");
        icacls(
            &dir,
            &["/grant".to_owned(), "*S-1-5-11:(OI)(CI)(IO)M".to_owned()],
        );
        let found = foreign_writers(&dir).unwrap();
        assert!(
            !found.is_empty(),
            "an inherit-only grant to everyone was reported clean"
        );

        // 3. An entry type this build does not know. Skipping it was how a
        //    conditional allow entry -- which Windows evaluates, and which can be
        //    written so it is true for everyone -- granted full control while the
        //    directory read as clean. Unknown types are reported now, so the next
        //    type Microsoft adds cannot open a hole in silence.
        assert!(
            imp::ALLOW_TYPES.contains(&9),
            "the conditional allow entry must be inspected, not skipped"
        );
        for unknown in 12u8..=16 {
            assert!(
                !imp::NON_GRANTING_TYPES.contains(&unknown) && !imp::ALLOW_TYPES.contains(&unknown),
                "type {unknown} is classified, so this no longer proves anything"
            );
        }

        // 4. The owner, which is not in the access list at all. The decision is
        //    tested on its own in `the_owner_rule_is_decided_not_assumed`; here
        //    the half that needs a real directory is asserted: this account is
        //    accepted as the owner of what it created.
        let dir = make("owned");
        assert!(
            foreign_writers(&dir).unwrap().is_empty(),
            "the account that created a directory must be allowed to own it"
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The three ways the swap check said "clean" about a path somebody else
    /// could move. A review demonstrated each of them against live Windows; this
    /// is what stops them coming back.
    ///
    /// Everything is built under a base this account protects, so the baseline is
    /// clean and each case is the only difference from it.
    #[cfg(windows)]
    #[test]
    fn the_ways_the_swap_check_used_to_miss() {
        use std::process::Command;
        let base = std::env::var_os("LOCALAPPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "fhd-swap-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&base).unwrap();
        protect_new_directory(&base).unwrap();
        let icacls = |dir: &std::path::Path, arguments: &[String]| {
            Command::new("icacls")
                .arg(dir)
                .args(arguments)
                .output()
                .expect("icacls runs")
                .status
                .success()
        };

        // The baseline: a protected directory under a protected base.
        let plain = base.join("plain");
        std::fs::create_dir(&plain).unwrap();
        assert!(
            swappable_components(&plain).unwrap().is_empty(),
            "the baseline is not clean, so nothing below proves anything"
        );

        // 1. Write-DAC only. No DELETE bit, but the holder can grant itself one.
        let wdac = base.join("wdac");
        std::fs::create_dir(&wdac).unwrap();
        let child = wdac.join("state");
        std::fs::create_dir(&child).unwrap();
        assert!(
            icacls(
                &wdac,
                &["/grant".to_owned(), "*S-1-5-11:(WDAC,WO)".to_owned()],
            ),
            "this case needs icacls to grant WRITE_DAC; without it the WRITE_DAC \
             path is uncovered rather than covered"
        );
        assert!(
            !swappable_components(&child).unwrap().is_empty(),
            "an ancestor granting WRITE_DAC alone was called unswappable"
        );

        // 2. The junction bypass, built exactly as the security review built it.
        //
        //    An earlier version of this case pointed a junction at a target
        //    inside the same protected base and asserted the two spellings
        //    agreed. They did -- both were clean -- so the assertion read
        //    `true == true` and pinned nothing. Worse, the one thing that could
        //    fail it was the reparse clause, which canonicalising makes dead
        //    code for this shape.
        //
        //    The real bypass is the other way round: a *hostile gate* holding a
        //    junction onto *clean ground*. Canonicalising erases the gate, so
        //    every check passed -- and then the gate was used to repoint the
        //    junction and the next open by path landed in the attacker's
        //    directory.
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        let gate = base.join("gate");
        std::fs::create_dir(&gate).unwrap();
        assert!(
            icacls(
                &gate,
                &["/grant".to_owned(), "*S-1-5-11:(OI)(CI)M".to_owned()]
            ),
            "this case needs icacls to grant Modify on the gate; without it the \
             junction bypass is uncovered rather than covered"
        );
        let link = gate.join("link");
        let made = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false);
        // A directory junction needs no privilege, so failing to make one is a
        // missing environment requirement and is recorded as one. Skipping
        // quietly would leave the bypass this case exists for with no coverage
        // and nothing saying so.
        assert!(
            made,
            "this case needs a directory junction; without it the junction bypass \
             is uncovered rather than covered"
        );
        let through = link.join("inner");
        std::fs::create_dir(&through).unwrap();

        // The resolved chain is clean, so this is the whole finding: it comes
        // from the typed chain or not at all.
        let direct = swappable_components(&target.join("inner")).unwrap();
        assert!(
            direct.is_empty(),
            "the negative control is dirty, so the assertion below would pass \
             against a check that refuses everything: {direct:?}"
        );
        let via = swappable_components(&through).unwrap();
        assert!(
            !via.is_empty(),
            "a path reached through a junction whose holder another account can \
             rewrite was called unswappable"
        );

        // 3. A junction the operator owns outright is not a finding.
        //
        //    Reporting every reparse point refused this, and handed back a count
        //    with no principal in it. The layout is ordinary -- somebody short of
        //    space points the application directory at another disk -- and a
        //    download manager invites it. A volume mount point looks the same to
        //    this code.
        let owned = base.join("owned");
        std::fs::create_dir(&owned).unwrap();
        let owned_link = base.join("owned-link");
        assert!(
            Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&owned_link)
                .arg(&owned)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false),
            "this case needs a directory junction; without it the false positive \
             is uncovered rather than covered"
        );
        let inside = owned_link.join("state");
        std::fs::create_dir(&inside).unwrap();
        let verdict = swappable_components(&inside).unwrap();
        assert!(
            verdict.is_empty(),
            "a junction nobody else can move was called swappable: {verdict:?}"
        );

        // 4. A junction whose holder is hostile is a finding -- and the hostile
        //    holder is *named*, not merely flagged.
        //
        //    This is the shape neither chain reaches: the redirect lands inside
        //    a directory another account can write, and that directory is in
        //    neither the typed spelling nor the resolved one. Reporting "this is
        //    a reparse point" refused it while naming nobody, and nothing tested
        //    that clause -- disabling it left the suite green.
        let mid = base.join("mid");
        std::fs::create_dir(&mid).unwrap();
        assert!(
            icacls(
                &mid,
                &["/grant".to_owned(), "*S-1-5-11:(OI)(CI)M".to_owned()]
            ),
            "this case needs icacls to grant Modify on the middle directory"
        );
        let far = base.join("far");
        std::fs::create_dir(&far).unwrap();
        let hop = mid.join("hop");
        assert!(
            Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&hop)
                .arg(&far)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false),
            "this case needs a directory junction"
        );
        let outer = base.join("outer");
        assert!(
            Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&outer)
                .arg(&hop)
                .output()
                .map(|out| out.status.success())
                .unwrap_or(false),
            "this case needs a second directory junction"
        );
        let nested = outer.join("state");
        std::fs::create_dir(&nested).unwrap();
        let verdict = swappable_components(&nested).unwrap();
        assert!(
            verdict.iter().any(|component| component
                .principals
                .iter()
                .any(|who| who.contains("S-1-5-11"))),
            "a redirect held in a directory another account can write was not \
             traced to that account: {verdict:?}"
        );

        let _ = Command::new("cmd")
            .args(["/C", "rmdir"])
            .arg(&outer)
            .output();
        let _ = Command::new("cmd").args(["/C", "rmdir"]).arg(&hop).output();
        let _ = Command::new("cmd")
            .args(["/C", "rmdir"])
            .arg(&owned_link)
            .output();

        // 5. A volume root is not a false positive. It carries a DELETE grant
        //    that means nothing, because no volume root can be renamed.
        let root = std::path::Path::new("C:\\");
        let found = swappable_components(root).unwrap();
        assert!(
            found.iter().all(|c| c.path != root),
            "the volume root itself was reported: {found:?}"
        );

        let _ = Command::new("cmd")
            .args(["/C", "rmdir"])
            .arg(&link)
            .output();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A directory the engine makes on Unix is owner-only from the instant it
    /// exists, and one it finds is left alone.
    ///
    /// `create_dir` then `set_permissions` would pass the first half of this and
    /// still be wrong: between the two calls the directory carries whatever the
    /// parent allowed, and a handle taken in that window outlives the repair.
    /// The mode goes to `mkdir(2)` instead, so there is no interval.
    ///
    /// **On the umask.** A request to run this under 002 and 000 rests on a
    /// premise worth stating: `mkdir(2)` intersects the mode with the umask, so
    /// a umask can only take permission bits away. `0o700` therefore cannot come
    /// out group- or other-writable under any umask at all -- 000 included, and
    /// 000 is the worst case. Changing this process's mask to show that would
    /// need `umask(2)`, and this crate forbids `unsafe` off Windows, which is
    /// the right trade: the property is a consequence of how `mkdir` is
    /// specified, not of what the mask happens to be.
    ///
    /// **Default ACLs are the case that does not follow from the mode**, and it
    /// has its own test below. A parent carrying one changes `mkdir`'s rules:
    /// the umask is ignored and the default entries seed the new directory.
    #[cfg(unix)]
    #[test]
    fn a_directory_we_make_is_owner_only_and_one_we_find_is_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("umask");
        std::fs::create_dir_all(&root).unwrap();

        let made = root.join("made");
        assert!(
            create_protected_directory(&made).unwrap(),
            "not created here"
        );
        assert_eq!(
            std::fs::metadata(&made).unwrap().permissions().mode() & 0o777,
            0o700,
            "a directory this call made is not owner-only"
        );
        assert!(
            foreign_writers(&made).unwrap().is_empty(),
            "a directory this call made is writable by somebody else"
        );

        // One that was already there keeps what it had. The engine reports such
        // a directory rather than narrowing it: changing an operator's
        // permissions unasked is the surprise we decline to cause.
        let found = root.join("found");
        std::fs::create_dir(&found).unwrap();
        std::fs::set_permissions(&found, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            !create_protected_directory(&found).unwrap(),
            "an existing directory was reported as created"
        );
        assert_eq!(
            std::fs::metadata(&found).unwrap().permissions().mode() & 0o777,
            0o775,
            "a directory we found was quietly narrowed"
        );
        assert!(
            !foreign_writers(&found).unwrap().is_empty(),
            "a group-writable directory we found was called clean"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A default ACL on the parent leaves nobody else with an effective right to
    /// our directory -- checked by trying it, not by reading it.
    ///
    /// The reasoning that Unix has no inherited permissions is too absolute. A
    /// POSIX default ACL is inheritance: `mkdir` under a parent that carries one
    /// ignores the umask and seeds the new directory from those entries, so a
    /// named user can arrive with an entry no mode argument mentions.
    /// `foreign_writers` reads `st_mode`, where a named entry does not appear.
    ///
    /// **An entry is not a permission.** A named entry is intersected with the
    /// mask, and `0o700` leaves the mask empty, so an inherited `rwx` can be
    /// present and grant nothing. Reporting the presence of `w` as a bypass
    /// would be reporting the wrong thing. So this asks three separate
    /// questions: what the entry says, what the mask leaves of it, and -- the
    /// one that settles it -- whether an untrusted identity can actually write.
    ///
    /// Linux only. macOS has a different ACL system and **is not covered by
    /// this verdict**; nothing here says anything about it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_default_acl_on_the_parent_grants_nobody_an_effective_right() {
        use std::process::Command;
        let root = scratch("defacl");
        std::fs::create_dir_all(&root).unwrap();
        // The parent must be reachable, or the access attempt below fails for
        // the wrong reason -- a denial at the parent, not at our directory.
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        let granted = Command::new("setfacl")
            .args(["-d", "-m", "u:nobody:rwx"])
            .arg(&root)
            .output()
            .expect(
                "this case needs setfacl; without it default-ACL inheritance is                  uncovered rather than covered",
            );
        assert!(
            granted.status.success(),
            "setfacl refused: {}",
            String::from_utf8_lossy(&granted.stderr)
        );

        let made = root.join("made");
        assert!(create_protected_directory(&made).unwrap());
        let acl = String::from_utf8_lossy(
            &Command::new("getfacl")
                .arg("-p")
                .arg(&made)
                .output()
                .expect("getfacl runs")
                .stdout,
        )
        .to_string();

        // 1. The mode bits, which is all `foreign_writers` can see.
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&made).unwrap().permissions().mode() & 0o077,
            0,
            "the mode bits let somebody else in:
{acl}"
        );

        // 2. What the mask leaves of any inherited entry. `getfacl` prints
        //    `#effective:` when the mask reduces one, and the effective set is
        //    what the kernel uses. An entry showing `rwx` with an effective of
        //    `---` grants nothing, and is not a finding.
        for line in acl.lines() {
            let line = line.trim();
            if !line.starts_with("user:nobody:") {
                continue;
            }
            let effective = match line.split_once("#effective:") {
                Some((_, after)) => after.trim(),
                None => line.rsplit(':').next().unwrap_or("").trim(),
            };
            assert!(
                !effective.contains('w'),
                "an inherited entry keeps an effective write after the mask:
{acl}"
            );
        }

        // 3. The question the first two only approximate: can that identity
        //    write? Asked of the kernel, as that identity, through a helper that
        //    knows nothing about any of this.
        let attempt = Command::new("sudo")
            .args(["-n", "-u", "nobody", "test", "-w"])
            .arg(&made)
            .status()
            .expect(
                "this case needs sudo to attempt access as another identity;                  without it the effective-permission claim is unverified",
            );
        assert!(
            !attempt.success(),
            "another identity can write a directory we made under a default ACL:
{acl}"
        );
        // And the control: the same identity can reach the parent, so the
        // refusal above is about our directory rather than about the path.
        let reachable = Command::new("sudo")
            .args(["-n", "-u", "nobody", "test", "-x"])
            .arg(&root)
            .status()
            .expect("sudo runs");
        assert!(
            reachable.success(),
            "the parent is unreachable, so the refusal proves nothing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// What Unix reports about a directory somebody else may write.    /// What Unix reports about a directory somebody else may write.
    ///
    /// This answered "nobody" until a review pointed out it was reasoning about
    /// a directory we create while the caller was asking about one it found --
    /// so a parts directory another account had already made, world-writable,
    /// was adopted on Unix where the same case was refused on Windows.
    ///
    /// Built with real modes, and each case differs from the clean one by
    /// exactly the bit under test.
    #[cfg(unix)]
    #[test]
    fn a_stranger_may_write_a_unix_directory_is_reported() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "fhd-unix-acl-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();

        // One we made ourselves, the way the engine makes it.
        let ours = base.join("ours");
        assert!(create_protected_directory(&ours).unwrap());
        assert!(
            foreign_writers(&ours).unwrap().is_empty(),
            "a directory this account just created with mode 0700 was called exposed"
        );

        // Group write.
        let grouped = base.join("grouped");
        create_protected_directory(&grouped).unwrap();
        std::fs::set_permissions(&grouped, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            !foreign_writers(&grouped).unwrap().is_empty(),
            "a group-writable directory was called clean"
        );

        // World write. The sticky bit narrows deletion, not writing, so it is
        // set here too and must not make this pass.
        let open = base.join("open");
        create_protected_directory(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(
            !foreign_writers(&open).unwrap().is_empty(),
            "a world-writable directory was called clean, sticky bit or not"
        );

        // And a path that is not there is an error, not a clean answer.
        assert!(foreign_writers(&base.join("absent")).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A directory under the temporary tree, named for this process and moment.
    #[cfg(unix)]
    fn scratch(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "fhd-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// A handle knows which object it holds, even after its name is taken.
    ///
    /// This is the measurement the publication contract turns on. A file is
    /// opened, its name is renamed away, and another file is put at that name.
    /// Linking by name delivers the impostor; the handle still identifies the
    /// original, and `same_object` says so.
    ///
    /// It is the detection half. Preventing it means linking from the handle,
    /// which `SetFileInformationByHandle` has no class for -- `FileLinkInfo` is
    /// an NT-level class -- so that remains an open decision rather than
    /// something this function quietly implies.
    #[cfg(windows)]
    #[test]
    fn a_handle_identifies_its_object_after_the_name_is_taken() {
        use std::fs;
        let base = std::env::temp_dir().join(format!(
            "fhd-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let name = base.join("subject.bin");
        fs::write(&name, b"ours").unwrap();
        let held = fs::File::open(&name).unwrap();

        // Same handle, same path, same object: the control, so a comparison
        // that always answered false could not pass this.
        assert!(
            same_object(&held, &fs::File::open(&name).unwrap()).unwrap(),
            "two handles on one file were called different objects"
        );

        // The name is taken over. The handle survives it on NTFS.
        fs::rename(&name, base.join("aside.bin")).unwrap();
        fs::write(&name, b"theirs").unwrap();
        let impostor = fs::File::open(&name).unwrap();
        assert!(
            !same_object(&held, &impostor).unwrap(),
            "a file planted at the name was called the same object"
        );

        // And what the name now leads to really is the other bytes, so this is
        // the substitution rather than an artefact of the check.
        assert_eq!(fs::read(&name).unwrap(), b"theirs");
        assert_eq!(fs::read(base.join("aside.bin")).unwrap(), b"ours");

        drop(held);
        drop(impostor);
        let _ = fs::remove_dir_all(&base);
    }

    /// Linking from a handle publishes the file that was held, not the file the
    /// name now leads to -- and it refuses a name already taken.
    ///
    /// This is the acceptance measurement for the publication contract, run
    /// here rather than quoted. `hard_link` is in the same test as the control:
    /// given the same takeover, it delivers the impostor. If both delivered the
    /// same bytes this would be proving nothing, so the two are compared.
    #[cfg(windows)]
    #[test]
    fn a_link_from_a_handle_carries_the_held_file_and_never_replaces() {
        use std::ffi::OsStr;
        use std::fs;
        let base = std::env::temp_dir().join(format!(
            "fhd-ntlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&base).unwrap();
        let source = base.join("source.bin");
        fs::write(&source, b"ours").unwrap();
        let held = fs::File::open(&source).unwrap();

        // The takeover: the name now leads somewhere else.
        fs::rename(&source, base.join("aside.bin")).unwrap();
        fs::write(&source, b"theirs").unwrap();

        // What a path-resolving link does with it, as the control.
        let by_name = base.join("by-name.bin");
        fs::hard_link(&source, &by_name).unwrap();
        assert_eq!(
            fs::read(&by_name).unwrap(),
            b"theirs",
            "the control did not reproduce the substitution, so the comparison \
             below would prove nothing"
        );

        // What a handle-resolving link does with it.
        let folder = open_directory(&base).unwrap();
        let by_handle = base.join("by-handle.bin");
        link_into_directory(&held, &folder, OsStr::new("by-handle.bin"))
            .expect("the handle link succeeds");
        assert_eq!(
            fs::read(&by_handle).unwrap(),
            b"ours",
            "the handle link delivered the file the name led to"
        );
        assert!(
            same_object(&held, &fs::File::open(&by_handle).unwrap()).unwrap(),
            "the published name is not the object that was held"
        );

        // And it never replaces: an occupied name is refused, and what was
        // there is untouched.
        let occupied = base.join("occupied.bin");
        fs::write(&occupied, b"somebody else").unwrap();
        let refused = link_into_directory(&held, &folder, OsStr::new("occupied.bin")).unwrap_err();
        assert_eq!(
            refused.kind(),
            std::io::ErrorKind::AlreadyExists,
            "an occupied name was refused for the wrong reason: {refused}"
        );
        assert_eq!(fs::read(&occupied).unwrap(), b"somebody else");

        // A name that is not one component is refused rather than resolved,
        // because resolving it is what this call exists to avoid.
        for escape in ["sub\\deep.bin", "..\\up.bin", r"C:\absolute.bin"] {
            let refused = link_into_directory(&held, &folder, OsStr::new(escape)).unwrap_err();
            assert_eq!(
                refused.kind(),
                std::io::ErrorKind::InvalidInput,
                "{escape} was not refused as a name"
            );
        }
        drop(folder);

        drop(held);
        let _ = fs::remove_dir_all(&base);
    }

    /// What an owner means, decided rather than assumed.
    ///
    /// Creating a directory owned by another account needs a privilege a test
    /// cannot assume, so the rule is split from the system call and checked here.
    /// **This does not show that a real foreign-owned directory is refused** --
    /// that needs a second account and is tracked as its own verification item.
    /// What it shows is that the rule says the right thing when it is asked.
    #[test]
    fn the_owner_rule_is_decided_not_assumed() {
        let us = "S-1-5-21-1-2-3-1001";
        assert_eq!(judge_owner(Some(us), us), OwnerVerdict::Trusted);
        // An administrator can take ownership regardless, and the system reads
        // everything; naming either a finding would be noise.
        assert_eq!(judge_owner(Some("S-1-5-18"), us), OwnerVerdict::Trusted);
        assert_eq!(judge_owner(Some("S-1-5-32-544"), us), OwnerVerdict::Trusted);
        // Anybody else owns WRITE_DAC on it whatever the access list says.
        assert_eq!(
            judge_owner(Some("S-1-5-21-1-2-3-1002"), us),
            OwnerVerdict::Foreign
        );
        assert_eq!(judge_owner(Some("S-1-1-0"), us), OwnerVerdict::Foreign);
        // No owner is refused, not assumed to be ours.
        assert_eq!(judge_owner(None, us), OwnerVerdict::Missing);
    }

    /// A directory made under a parent that hands out write access to others is
    /// exposed until it is given permissions of its own, and clean afterwards.
    ///
    /// `%LOCALAPPDATA%\Temp` is the real case, not a contrived one: on this
    /// machine it grants write access to three packaged-application principals,
    /// and anything created inside inherits them. So the check finds a fresh
    /// directory there exposed, and `protect_new_directory` is what clears it.
    #[cfg(windows)]
    #[test]
    fn a_new_directory_is_exposed_by_what_it_inherits_until_it_is_protected() {
        let base = std::env::temp_dir().join(format!(
            "fhd-protect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let inherited = foreign_writers(&base).unwrap();

        protect_new_directory(&base).unwrap();
        assert!(
            foreign_writers(&base).unwrap().is_empty(),
            "stated permissions still let someone else write: {:?}",
            foreign_writers(&base).unwrap()
        );

        // And what the engine creates inside it inherits the stated list, so the
        // database and the part files do not each need their own call.
        let child = base.join("parts");
        std::fs::create_dir(&child).unwrap();
        assert!(foreign_writers(&child).unwrap().is_empty());

        // Recorded rather than asserted: a machine whose temp directory is
        // already owner-only would see nothing here, and that is not a failure.
        // The assertion that matters is that protection clears whatever was there.
        println!("inherited foreign writers before protection: {inherited:?}");
        let _ = std::fs::remove_dir_all(&base);
    }

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
