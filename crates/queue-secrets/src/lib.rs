//! Windows user-scoped data protection. No plaintext fallback on other platforms.
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

#[cfg(windows)]
fn transform(input: &[u8], encrypt: bool) -> Result<Vec<u8>, Error> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
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
        fn drop(&mut self) {
            if !self.0.pbData.is_null() {
                // SAFETY: DPAPI owns this valid LocalAlloc allocation. Its reported
                // size is trusted OS metadata, not an untrusted serialized value.
                // Wipe before freeing, including early errors and unwinding paths.
                unsafe {
                    use zeroize::Zeroize;
                    std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                    LocalFree(self.0.pbData.cast());
                }
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
