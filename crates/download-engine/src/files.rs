use sha2::{Digest, Sha256};
// Destination export: no overwrite, bounded copies, private caller-owned folders.
use crate::{storage_error, Error};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use transfer_store::{Status, Store};
#[derive(Clone, Copy, Debug)]
pub enum Conflict {
    Reject,
    Rename,
    Skip,
}
#[derive(Debug, PartialEq, Eq)]
pub enum ExportResult {
    Published(PathBuf),
    Skipped(PathBuf),
}
pub fn validate_name(name: &str) -> Result<(), Error> {
    let stem = name.split('.').next().unwrap_or("").to_ascii_lowercase();
    let device = matches!(
        stem.as_str(),
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
    ) || ["com", "lpt"].iter().any(|p| {
        stem.strip_prefix(p).is_some_and(|s| {
            matches!(
                s,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    if name.is_empty()
        || name.len() > 200
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name.contains(['/', '\\', ':', '<', '>', '"', '|', '?', '*'])
        || name.chars().any(char::is_control)
        || device
    {
        Err(Error::InvalidOptions)
    } else {
        Ok(())
    }
}
fn private_directory(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute() {
        return Err(Error::InvalidOptions);
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|e| Error::StorageIo(e.kind()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(Error::InvalidOptions);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(Error::InvalidOptions);
            }
        }
    }
    path.canonicalize().map_err(|e| Error::StorageIo(e.kind()))
}
/// Checks capacity at this instant only. Concurrent writers and quotas may change it.
pub fn check_space(directory: &Path, bytes: u64, reserve: u64) -> Result<u64, Error> {
    let directory = private_directory(directory)?;
    let available =
        platform_files::available_space(&directory).map_err(|e| Error::StorageIo(e.kind()))?;
    let required = bytes.checked_add(reserve).ok_or(Error::SizeLimit)?;
    if available < required {
        return Err(Error::InsufficientSpace);
    }
    Ok(available)
}

pub(crate) async fn before_transfer(directory: PathBuf, bytes: u64) -> Result<(), Error> {
    tokio::task::spawn_blocking(move || check_space(&directory, bytes, 1024 * 1024).map(|_| ()))
        .await
        .map_err(|_| Error::WorkerFailed)?
}
struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
/// Blocking operation: call on a blocking worker, not the async runtime thread.
/// The source remains recoverable. Only this invocation's temporary file is removed.
/// Caller owns and trusts both directory trees (no hostile concurrent path changes).
pub fn export_completed(
    job: &Path,
    destination: &Path,
    name: &str,
    conflict: Conflict,
) -> Result<ExportResult, Error> {
    validate_name(name)?;
    let destination = private_directory(destination)?;
    let mut store = Store::open(job).map_err(storage_error)?;
    if store.status() != Status::Published {
        return Err(Error::InvalidTransition);
    }
    let source = store.finalize().map_err(storage_error)?;
    let desired = destination.join(name);
    if fs::symlink_metadata(&desired).is_ok() {
        match conflict {
            Conflict::Reject => return Err(Error::DestinationConflict),
            Conflict::Skip => return Ok(ExportResult::Skipped(desired)),
            Conflict::Rename => {}
        }
    }
    check_space(&destination, store.identity().total, 1024 * 1024)?;
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let mut tries = 0;
    let (temporary, mut output) = loop {
        tries += 1;
        if tries > 1000 {
            return Err(Error::DestinationConflict);
        }
        let path = destination.join(format!(
            ".fhd-export-{}-{}.tmp",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => break (Temporary(path), file),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(Error::StorageIo(e.kind())),
        }
    };
    let mut input = File::open(&source).map_err(|e| Error::StorageIo(e.kind()))?;
    let expected = store.verified_sha256();
    let mut digest = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|e| Error::StorageIo(e.kind()))?;
        if n == 0 {
            break;
        }
        copied = copied.checked_add(n as u64).ok_or(Error::SizeLimit)?;
        if copied > store.identity().total {
            return Err(Error::StoredDataCorrupt);
        }
        digest.update(&buffer[..n]);
        output
            .write_all(&buffer[..n])
            .map_err(|e| Error::StorageIo(e.kind()))?;
    }
    if digest.finalize().as_slice() != expected || copied != store.identity().total {
        return Err(Error::StoredDataCorrupt);
    }
    output.sync_all().map_err(|e| Error::StorageIo(e.kind()))?;
    drop(output);
    for suffix in 0..=1000 {
        let path = if suffix == 0 {
            desired.clone()
        } else {
            let p = Path::new(name);
            let stem = p
                .file_stem()
                .and_then(|x| x.to_str())
                .ok_or(Error::InvalidOptions)?;
            let ext = p
                .extension()
                .and_then(|x| x.to_str())
                .map(|x| format!(".{x}"))
                .unwrap_or_default();
            destination.join(format!("{stem} ({suffix}){ext}"))
        };
        match fs::hard_link(&temporary.0, &path) {
            Ok(()) => {
                #[cfg(unix)]
                File::open(&destination)
                    .and_then(|f| f.sync_all())
                    .map_err(|e| Error::StorageIo(e.kind()))?;
                return Ok(ExportResult::Published(path));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => match conflict {
                Conflict::Rename => continue,
                Conflict::Skip => return Ok(ExportResult::Skipped(path)),
                Conflict::Reject => return Err(Error::DestinationConflict),
            },
            Err(e) => return Err(Error::StorageIo(e.kind())),
        }
    }
    Err(Error::DestinationConflict)
}
