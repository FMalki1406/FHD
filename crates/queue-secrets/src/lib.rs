//! Windows user-scoped data protection. No plaintext fallback on other platforms.
//!
//! **`unsafe` is banned here and permitted at one named place.** This crate used to
//! declare no restriction at all, so its four native calls needed no allowance to be
//! written -- which is why an attribute-based gate could not see them and why they sat
//! outside the rule that `fhd-platform` is the only crate that may use `unsafe`. The
//! calls stay here, where the DPAPI contract they depend on is: moving them to
//! `fhd-platform` would move the code without reviewing it. What is here instead is a
//! ban with one exception, on the one function that makes the calls, so the exception
//! is named in `tools/check-unsafe.mjs` and changing that function's signature is a
//! change the gate reports.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
const MAX_INPUT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    UnsupportedPlatform,
    InvalidSize,
    ProtectionFailed,
}

pub fn protect(input: &[u8]) -> Result<Vec<u8>, Error> {
    transform(input, true)
}

pub fn unprotect(input: &[u8]) -> Result<Vec<u8>, Error> {
    transform(input, false)
}

#[cfg(not(windows))]
fn transform(_: &[u8], _: bool) -> Result<Vec<u8>, Error> {
    Err(Error::UnsupportedPlatform)
}

/// The one place in this crate where `unsafe` is permitted.
///
/// Four native calls, each reviewed and each with its own `SAFETY` note below:
/// `CryptProtectData`/`CryptUnprotectData` on a bounded owned buffer; `LocalSize` and
/// the wipe it bounds; `LocalFree`; and the copy out of the blob, which happens only
/// after success, a non-null pointer and a length inside `MAX_INPUT`.
#[cfg(windows)]
#[allow(unsafe_code)]
fn transform(input: &[u8], encrypt: bool) -> Result<Vec<u8>, Error> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
        System::Memory::LocalSize,
    };
    if input.is_empty() || input.len() > MAX_INPUT {
        return Err(Error::InvalidSize);
    }
    // A private owned input avoids casting the caller's immutable allocation to a
    // mutable pointer. Native calls are synchronous and do not retain this buffer.
    let mut source = zeroize::Zeroizing::new(input.to_vec());
    let data = CRYPT_INTEGER_BLOB {
        cbData: source.len() as u32,
        pbData: source.as_mut_ptr(),
    };
    struct Output(CRYPT_INTEGER_BLOB);
    impl Drop for Output {
        /// Wipes the blob and frees it, on every path out of `transform`.
        ///
        /// **The length comes from the allocator, not from `cbData`.** It used to be
        /// `from_raw_parts_mut(pbData, cbData)`, and a security review pointed out what
        /// that costs: this runs on the failure path and while unwinding too, and on
        /// those paths nothing has checked `cbData` -- the success path's own guard
        /// refuses a `cbData` of zero or one above `MAX_INPUT`, so the code already
        /// treats that field as needing a check before it is believed. A failed
        /// `CryptProtectData` is not documented to leave the out-blob untouched, so a
        /// length written there by a call that failed could have sent this `zeroize`
        /// past the end of the allocation: a wipe intended to protect a secret,
        /// writing wherever a failed call happened to leave a number.
        ///
        /// `LocalSize` asks the allocator how long its own allocation is, which is the
        /// one number that cannot be wrong about it, and returns zero for a handle it
        /// does not recognise. So the wipe is bounded by the allocation on every path
        /// -- including the ones that made the old bound unsafe -- and it still covers
        /// what it was for: on `unprotect` this buffer holds the plaintext.
        fn drop(&mut self) {
            if self.0.pbData.is_null() {
                return;
            }
            // SAFETY: a non-null `pbData` from DPAPI is a `LocalAlloc` handle, which is
            // what this asks about. It reads nothing through the pointer.
            let allocated = unsafe { LocalSize(self.0.pbData.cast()) };
            if allocated > 0 {
                // SAFETY: the allocation is this struct's alone -- no other reference
                // to it exists, and `transform` copies out of it before dropping -- and
                // `allocated` is its length by the allocator's own account.
                unsafe {
                    use zeroize::Zeroize;
                    std::slice::from_raw_parts_mut(self.0.pbData, allocated).zeroize();
                }
            }
            // SAFETY: DPAPI documents its output as `LocalAlloc`ated and released with
            // `LocalFree`, and this is the only release of it.
            unsafe {
                LocalFree(self.0.pbData.cast());
            }
        }
    }
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    });
    // SAFETY: valid bounded buffers/structs remain live through the synchronous
    // call. Optional arguments are null. DPAPI allocates output with LocalAlloc;
    // it is copied only after success and always released using LocalFree below.
    let success = unsafe {
        if encrypt {
            CryptProtectData(
                &data,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &data,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    };
    if success == 0
        || output.0.pbData.is_null()
        || output.0.cbData == 0
        || output.0.cbData as usize > MAX_INPUT
    {
        Err(Error::ProtectionFailed)
    } else {
        // SAFETY: successful DPAPI call gives cbData initialized bytes valid until
        // LocalFree; the returned Rust vector owns its independent allocation.
        Ok(
            unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }
                .to_vec(),
        )
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_rejects_tamper_and_does_not_contain_plaintext() {
        let secret = b"https://example.test/?token=PRIVATE_QUEUE_SECRET";
        let encrypted = protect(secret).unwrap();
        assert!(!encrypted.windows(secret.len()).any(|part| part == secret));
        assert_eq!(unprotect(&encrypted).unwrap(), secret);
        let mut changed = encrypted;
        let end = changed.len() - 1;
        changed[end] ^= 0xff;
        assert!(unprotect(&changed).is_err());
        assert_eq!(protect(&[]), Err(Error::InvalidSize));
    }
}

#[cfg(all(test, not(windows)))]
mod unsupported_tests {
    use super::*;

    #[test]
    fn unsupported_platform_never_returns_plaintext_or_fake_ciphertext() {
        assert_eq!(
            protect(b"private credential"),
            Err(Error::UnsupportedPlatform)
        );
        assert_eq!(
            unprotect(b"pretend ciphertext"),
            Err(Error::UnsupportedPlatform)
        );
    }
}
