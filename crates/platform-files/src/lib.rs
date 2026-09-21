//! Minimal native free-space query. Values are advisory, never reservations.
use std::{io, path::Path};
#[cfg(windows)]
pub fn available_space(path: &Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    wide.push(0);
    let mut available = 0;
    // SAFETY: wide is terminated and remains live; available is writable u64;
    // the optional total counters are documented nullable output parameters.
    let ok = unsafe {
        windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(available)
    }
}
#[cfg(unix)]
pub fn available_space(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::ErrorKind::InvalidInput)?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: path is a live terminated string and stat points to writable
    // correctly aligned storage. Read it only after a successful native call.
    if unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful statvfs initialized every field of this native struct.
    let stat = unsafe { stat.assume_init() };
    u64::try_from(u128::from(stat.f_bavail) * u128::from(stat.f_frsize))
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
#[cfg(not(any(windows, unix)))]
pub fn available_space(_: &Path) -> io::Result<u64> {
    Err(io::ErrorKind::Unsupported.into())
}
#[cfg(test)]
mod tests {
    #[test]
    fn queries_existing_volume_and_rejects_missing_path() {
        assert!(super::available_space(&std::env::temp_dir()).is_ok());
        assert!(
            super::available_space(&std::env::temp_dir().join("fhd-absent-space-path/child"))
                .is_err()
        );
    }
}
