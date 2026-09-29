//! Windows user-scoped data protection. No plaintext fallback on other platforms.
//!
//! **`unsafe` is banned here and permitted at named places.** This crate used to declare
//! no restriction at all, so its native calls needed no allowance to be written -- which is
//! why an attribute-based gate could not see them and why they sat outside the rule that
//! `fhd-platform` is the only crate that may use `unsafe`. The calls stay here, where the
//! DPAPI contract they depend on is: moving them to `fhd-platform` would move the code
//! without reviewing it. What is here instead is a ban with three exceptions -- `transform`,
//! `wipe_and_release`, and the tests' one wrapper around it -- each named in
//! `tools/check-unsafe.mjs` by its signature, so changing one is a change the gate reports.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
const MAX_INPUT: usize = 64 * 1024 * 1024;

// `cbData` is a `u32`, and the input's length is cast into it. The cast is lossless only
// while the guard above it cannot admit a length that a `u32` cannot hold, so that is
// checked here rather than trusted: if `MAX_INPUT` ever grows past `u32::MAX`, this fails
// to compile instead of silently encrypting a truncated prefix of the caller's secret.
#[cfg(windows)]
const _: () = assert!(MAX_INPUT <= u32::MAX as usize);

/// How far above `MAX_INPUT` a DPAPI block may legitimately measure.
///
/// The output of `CryptProtectData` is longer than its input -- a header, the key
/// identifier and a MAC -- and `LocalSize` then reports the allocator's rounded block
/// rather than what was asked for. Measured on this machine: 278 bytes of ciphertext in a
/// 304-byte block for a 48-byte input. A megabyte is far more than that overhead and far
/// less than a number that could only be wrong, which is all this bound has to be.
#[cfg(windows)]
const OVERHEAD: usize = 1024 * 1024;

/// How many blocks the guard has released, counted only in a test build.
///
/// **This is the smallest instrumentation that makes the wiring a fact rather than a
/// reading.** Two rounds of review found the same gap: the wipe's own bound is measured,
/// but nothing asserted that `transform` is connected to it at all. An engineering review
/// then measured a `mem::forget` of the guard on the success path passing every test --
/// which in production leaks the DPAPI block un-wiped, and on `unprotect` that block holds
/// the plaintext. The same counter also settles the other half, which the previous round
/// recorded as reviewed-but-unmeasurable: whether a *failed* call touches the pointer. It
/// costs three lines, no `unsafe`, and nothing at all in a release build.
#[cfg(all(test, windows))]
pub(crate) static RELEASES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

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

/// Wipes a DPAPI output block, then releases it -- with the allocator's two calls passed
/// in, so that the bound on the wipe is something a test can watch.
///
/// **Nothing here forms a slice.** `LocalSize` reports the size of the *block*, which
/// Microsoft documents may exceed the size that was asked for, so the bytes past what
/// DPAPI wrote are of unknown initialisation. `slice::from_raw_parts_mut` requires every
/// element of the slice to be initialised, so building a `&mut [u8]` across the block
/// would be undefined behaviour however carefully the length had been obtained. A
/// security review named this; the version before it formed exactly that slice.
///
/// **The volatile write is the guarantee, not the fence.** A plain store into memory that
/// is about to be released is a store nothing can observe, and a compiler may drop it --
/// the review measured that in emitted assembly, which is also why the comment that
/// credited the fence with keeping the wipe alive is gone. `write_volatile` may not be
/// elided. The fence stays as belt and braces and claims nothing.
///
/// **A size of zero releases nothing.** Zero is what `LocalSize` is documented to return
/// when it fails, and handing that same pointer to `LocalFree` next would be asking the
/// allocator to release something it has just declined to measure. The old code wiped
/// nothing in that case and freed anyway. What a zero is *not* is a safe answer for a
/// pointer that is not an allocation at all -- see the safety section.
///
/// **A size above the bound is refused rather than trusted.** The reason the bound moved
/// off `cbData` is that nothing checks that field on the failure path; a length taken from
/// the allocator is better, but it is still a number this code did not compute. So it is
/// bounded the same way `cbData` is: `MAX_INPUT` plus room for DPAPI's own overhead and the
/// allocator's rounding. Past that, nothing is written and nothing is freed -- the block is
/// leaked deliberately, because writing into memory this function cannot vouch for is worse
/// than leaking it. A security review asked for the bound; the leak is the price.
///
/// # Safety
///
/// This is `unsafe` because both of its arguments are memory-safety preconditions, and a
/// safe signature hid that from every control in this crate: a call needed no `unsafe`, so
/// `#![deny(unsafe_code)]` did not reach it, `tools/check-unsafe.mjs` did not count it, and
/// the approved signature recorded there ratified a caller-chosen write length. Both
/// reviews of the previous version arrived at this independently.
///
/// The caller must guarantee that:
///
///   * `size` reports a length that `block` is valid for writes over, for the whole of it,
///     and that `free` releases exactly `block`;
///   * nothing else holds a reference into that block while this runs;
///   * `size` may be called with a non-null `block` only where asking the allocator about
///     that pointer is itself defined. This one is not theoretical: `LocalSize` on a
///     pointer that is not a `LocalAlloc` handle does not return zero -- a review measured
///     it terminating the process with `STATUS_HEAP_CORRUPTION` for a freed handle and for
///     a stack address, and returning a plausible size for an unrelated heap block. So
///     the zero check below is a guard on a *documented failure*, not a validity test; the
///     only thing that makes `Output`'s pointer safe to ask about is DPAPI's contract, and
///     that is written where the call site is.
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe fn wipe_and_release(
    block: *mut u8,
    size: impl FnOnce(*mut u8) -> usize,
    free: impl FnOnce(*mut u8),
) {
    if block.is_null() {
        return;
    }
    let allocated = size(block);
    if allocated == 0 || allocated > MAX_INPUT + OVERHEAD {
        return;
    }
    for offset in 0..allocated {
        // SAFETY: the block belongs to the caller alone -- `Output` owns it, no other
        // reference to it exists, and `transform` has copied out of it before this runs --
        // and `allocated` is its length by the allocator's own account, so every address
        // here lies inside that one allocation and is valid for a write of one byte. That
        // the allocator's reported length is writable throughout is an inference from the
        // `LocalAlloc`/`LocalSize` contract rather than a sentence Microsoft writes; it is
        // the same inference that passing the pointer to `LocalFree` already rests on.
        // `u8` needs no alignment beyond one, and a volatile write needs no initialised
        // value under it.
        unsafe { block.add(offset).write_volatile(0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    free(block);
}

/// The function that makes the native calls, approved here by its signature.
///
/// Three uses of `unsafe` in this function, each with its own `SAFETY` note:
/// `CryptProtectData`/`CryptUnprotectData` on a bounded owned buffer; the copy out of the
/// blob, which happens only after success, a non-null pointer and a length inside
/// `MAX_INPUT`; and the call to `wipe_and_release`, whose two closures make the `LocalSize`
/// and `LocalFree` calls and whose own `unsafe` performs the wipe.
///
/// **What DPAPI protects, and what it does not.** `CRYPTPROTECT_UI_FORBIDDEN` with no
/// entropy and no flags binds the ciphertext to this user on this machine: any process
/// running as the same user can call `unprotect` on it. It keeps the queue's credentials
/// out of a file readable by another account or copied off the machine; it is not a
/// defence against code already running as the user.
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
        /// Wipes the blob and frees it, on every path out of `transform` that took one.
        ///
        /// **The length comes from the allocator, not from `cbData`.** It used to be
        /// `from_raw_parts_mut(pbData, cbData)`, and a security review pointed out what
        /// that costs. The reason it gave -- that this also ran on the failure path and
        /// while unwinding, where nothing had checked `cbData` -- **no longer applies**,
        /// because this type is now built only after a successful call and there is no
        /// unwind window; an engineering review caught the justification outliving its
        /// case. The bound stays where it is on a reason that does hold: the checks right
        /// after the guard is built reject a `cbData` of zero or one above `MAX_INPUT`, so
        /// this code does not believe that field without checking it, and a wipe bounded
        /// by it would be a wipe bounded by an unchecked number. Nobody should read the
        /// lapsed reason and conclude `cbData` may be used again.
        ///
        /// `LocalSize` asks the allocator how long its own allocation is, which is a
        /// better number than one a failed call left in a struct, and `wipe_and_release`
        /// then refuses a zero and anything above `MAX_INPUT + OVERHEAD`. So the wipe is
        /// bounded on every path -- including the ones that made the old bound unsafe --
        /// and it still covers what it was for: on `unprotect` this buffer holds the
        /// plaintext.
        ///
        /// **This type exists only where DPAPI has reported success.** It used to wrap the
        /// blob before the call, so the allocator was asked about `pbData` on the failure
        /// path too -- and a review was right to refuse that: a measurement that one
        /// particular failure leaves the pointer null is not a guarantee about every
        /// failure, and this crate's own comments say that asking `LocalSize` about a
        /// pointer that is not a handle can end the process. So the guard is constructed
        /// from the blob only after the call returns non-zero, which is the one state in
        /// which the pointer is DPAPI's to measure and release. On failure nothing here
        /// runs, because there is nothing here.
        ///
        /// What that costs is written where the decision is, at the failure path below: if
        /// a failing call ever did allocate, that block is leaked and not wiped -- and on
        /// `unprotect` what it would hold is the **decrypted queue credential**, kept
        /// allocated for the life of the process rather than freed, which is where a
        /// minidump or a hibernation file would find it. Leaking memory this code cannot
        /// vouch for is still the lesser harm, and naming what is leaked is the point.
        ///
        /// The two allocator calls are passed to `wipe_and_release` instead of being made
        /// here, which is what lets a test report a size and check that the wipe stops
        /// there and that a zero frees nothing.
        fn drop(&mut self) {
            // Counted so that one test can assert the success path reaches here exactly
            // once and the failure path never does. Test builds only.
            #[cfg(test)]
            RELEASES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // SAFETY: `LocalSize` reports the length of the block `pbData` points at, and
            // `LocalFree` releases exactly that pointer, which is how DPAPI documents the
            // output of a call that succeeded; this is its only release, and this type is
            // only ever built from such a call. No reference into the block is live -- the
            // copy out of it in `transform` is finished before `Output` is dropped.
            unsafe {
                wipe_and_release(
                    self.0.pbData,
                    |block| LocalSize(block.cast()),
                    |block| {
                        LocalFree(block.cast());
                    },
                );
            }
        }
    }
    // A plain blob, not the guard: until the call reports success, nothing here is known to
    // be an allocation, and the guard's whole job is to release one.
    let mut blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    // SAFETY: valid bounded buffers/structs remain live through the synchronous
    // call. Optional arguments are null. DPAPI allocates output with LocalAlloc;
    // it is copied only after success and released through the guard built below.
    let success = unsafe {
        if encrypt {
            CryptProtectData(
                &data,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut blob,
            )
        } else {
            CryptUnprotectData(
                &data,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut blob,
            )
        }
    };
    if success == 0 {
        // **The failure path touches nothing.** Not `LocalSize`, not `LocalFree`, not the
        // pointer. A review refused the previous version for a reason that holds: the
        // measurement that a failed `CryptUnprotectData` leaves `pbData` null covers the
        // failure that was measured, not every failure -- and if `pbData` were ever left
        // pointing at something that is not a `LocalAlloc` handle, asking the allocator
        // about it can end the process, as the note on `wipe_and_release` records from
        // measurement. **The cost, stated rather than hidden:** should a failing call ever
        // allocate, that block leaks un-wiped. Microsoft documents no such allocation; and a
        // write into memory this code cannot vouch for is worse than a leak.
        //
        // **And this is where anyone would learn that the assumption had changed.** A
        // security review pushed nine malformed inputs through `unprotect` -- garbage of two
        // sizes, truncations, a flipped first, middle and last byte, a one-byte input, an
        // extended one -- and every failing case left `pbData` null and `cbData` zero. That
        // is eight arrangeable failures, not the one this record used to claim, and still
        // nothing about the failures a test cannot arrange: no master key, an LSASS call
        // that fails, an allocation that does not happen. The assertion touches no
        // allocator, costs nothing in a release build, and turns a one-off measurement into
        // something a debug run or a field report can contradict. Without it a non-null
        // pointer after a failure looks exactly like the ordinary case and nobody finds out.
        debug_assert!(
            blob.pbData.is_null(),
            "a failed DPAPI call left a non-null out-blob, which this code is written not to touch",
        );
        return Err(Error::ProtectionFailed);
    }
    // Success. Only now is this pointer DPAPI's allocation, and only now does the guard that
    // wipes and frees it exist.
    //
    // **The guard is built before the checks below on purpose.** Those checks reject a
    // success whose blob is null, empty or longer than `MAX_INPUT` -- and a block DPAPI
    // allocated still has to be wiped and released when they do. Moving this line below them
    // leaks it, which no test can see; the line is load-bearing and quiet about it, so this
    // paragraph is its guard rail. `std::mem::take` leaves `blob` null because
    // `CRYPT_INTEGER_BLOB` is `Copy`: without it the raw pointer stays live and nameable
    // beside the guard that owns it, and a later `Output(blob)` would be a double free that
    // compiles clean. Both reviews found that independently.
    let output = Output(std::mem::take(&mut blob));
    if output.0.pbData.is_null() || output.0.cbData == 0 || output.0.cbData as usize > MAX_INPUT {
        return Err(Error::ProtectionFailed);
    }
    // SAFETY: successful DPAPI call gives cbData initialized bytes valid until
    // LocalFree; the returned Rust vector owns its independent allocation.
    Ok(unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// The one place the tests may call the wipe, with its precondition discharged here.
    ///
    /// SAFETY: every caller below passes either a null pointer or the pointer of a live
    /// local `Vec<u8>` together with a size no larger than that vector's length, and holds
    /// no reference into it across the call. `free` never releases anything -- it counts.
    #[allow(unsafe_code)]
    fn wipe(block: *mut u8, size: impl FnOnce(*mut u8) -> usize, free: impl FnOnce(*mut u8)) {
        unsafe { wipe_and_release(block, size, free) };
    }

    /// The two tests that call `protect`/`unprotect` take this, because one of them counts
    /// releases and the harness runs tests in parallel in one process.
    static SERIALIZED: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A successful call releases its block exactly once, and a failed one releases nothing.
    ///
    /// **This is the wiring, which nothing measured until now.** Two rounds of review found
    /// the same hole from opposite sides: the wipe's bound is measured through an injected
    /// seam, so a `mem::forget` of the guard on the success path -- every DPAPI block leaked
    /// un-wiped, holding the plaintext on `unprotect` -- passed all five tests; and the
    /// failure path's promise not to touch the pointer was recorded as
    /// reviewed-but-unmeasurable, because the failure a test can arrange leaves the pointer
    /// null and both shapes then look the same. One counter in the guard answers both: the
    /// success path must reach it, the failure path must not.
    #[test]
    fn a_successful_call_releases_its_block_once_and_a_failed_one_never() {
        use std::sync::atomic::Ordering::Relaxed;
        let _order = SERIALIZED.lock().unwrap_or_else(|held| held.into_inner());
        let before = RELEASES.load(Relaxed);
        let secret = b"https://example.test/?token=PRIVATE_QUEUE_SECRET";
        let encrypted = protect(secret).unwrap();
        assert_eq!(
            RELEASES.load(Relaxed),
            before + 1,
            "protect did not release the block DPAPI gave it"
        );
        assert_eq!(unprotect(&encrypted).unwrap(), secret);
        assert_eq!(
            RELEASES.load(Relaxed),
            before + 2,
            "unprotect did not release the block that held the plaintext"
        );

        // And a failure takes no pointer at all: no guard exists on that path.
        let mut tampered = encrypted;
        let end = tampered.len() - 1;
        tampered[end] ^= 0xff;
        assert!(unprotect(&tampered).is_err());
        assert_eq!(
            RELEASES.load(Relaxed),
            before + 2,
            "a failed call handed its out-blob to the allocator"
        );

        // A refused input never reaches the call, so it releases nothing either.
        assert_eq!(protect(&[]), Err(Error::InvalidSize));
        assert_eq!(
            RELEASES.load(Relaxed),
            before + 2,
            "a refused input released something"
        );
    }

    #[test]
    fn roundtrip_rejects_tamper_and_does_not_contain_plaintext() {
        let _order = SERIALIZED.lock().unwrap_or_else(|held| held.into_inner());
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

    /// The wipe stops at the size it was told, and the bytes after it are untouched.
    ///
    /// This is the claim that could not be tested while the wipe read its length out of
    /// the blob and called the allocator itself: showing the danger would have meant
    /// making DPAPI fail *and* leave a non-null pointer with a false length behind, which
    /// no test can arrange. With the two calls passed in, the bound is a number this test
    /// chooses -- so the guard region below is the measurement, and the record that called
    /// this fix "reviewed but not coverable" was wrong about that.
    #[test]
    fn the_wipe_covers_the_reported_size_and_no_more() {
        // **Two sizes, because one size proves one point.** The first version measured the
        // bound at 16 only, and an engineering review pointed out that any cap above 16 --
        // a mutation writing `allocated.min(4096)`, say -- was invisible to it. The second
        // case is past that cap and past a page.
        for (length, reported) in [(64_usize, 16_usize), (12_000, 8_192)] {
            let mut block = vec![0xab_u8; length];
            let pointer = block.as_mut_ptr();
            let asked = std::cell::Cell::new(0_usize);
            let freed = std::cell::Cell::new(0_usize);
            wipe(
                pointer,
                |given| {
                    // The pointer the allocator is asked about is the one it was given. A
                    // shifted one would measure, wipe and free somebody else's memory, and
                    // until this assertion only a heap corruption crash said so.
                    assert_eq!(given, pointer, "the size was asked about another pointer");
                    asked.set(asked.get() + 1);
                    reported
                },
                |given| {
                    assert_eq!(given, pointer, "another pointer was released");
                    freed.set(freed.get() + 1);
                },
            );
            assert!(
                block[..reported].iter().all(|byte| *byte == 0),
                "the reported bytes are not wiped at {reported} of {length}"
            );
            assert!(
                block[reported..].iter().all(|byte| *byte == 0xab),
                "the wipe ran past the reported size at {reported} of {length}"
            );
            assert_eq!(
                (asked.get(), freed.get()),
                (1, 1),
                "at {reported} of {length}"
            );
        }
    }

    /// A size the allocator could not honestly report is refused, and nothing is freed.
    ///
    /// `LocalSize` is not a validity test -- a review measured it returning a plausible size
    /// for an unrelated heap block -- so a number far above anything this crate can produce
    /// is treated as one that cannot be trusted to bound a write.
    #[test]
    fn a_size_above_the_bound_is_refused() {
        let mut block = vec![0xab_u8; 32];
        let pointer = block.as_mut_ptr();
        let freed = std::cell::Cell::new(0_usize);
        wipe(
            pointer,
            |_| MAX_INPUT + OVERHEAD + 1,
            |_| freed.set(freed.get() + 1),
        );
        assert!(
            block.iter().all(|byte| *byte == 0xab),
            "a block measured beyond the bound was written to"
        );
        assert_eq!(
            freed.get(),
            0,
            "a block measured beyond the bound was released"
        );
    }

    /// A size of zero is the allocator denying the handle: nothing is wiped, nothing freed.
    #[test]
    fn a_reported_size_of_zero_wipes_nothing_and_releases_nothing() {
        let mut block = vec![0xab_u8; 16];
        let pointer = block.as_mut_ptr();
        let freed = std::cell::Cell::new(0_usize);
        wipe(pointer, |_| 0, |_| freed.set(freed.get() + 1));
        assert!(
            block.iter().all(|byte| *byte == 0xab),
            "a block the allocator does not know was written to"
        );
        assert_eq!(
            freed.get(),
            0,
            "a pointer the allocator has just denied owning was passed to it to free"
        );
    }

    /// A null blob is neither measured nor freed.
    ///
    /// It used to be described as what `transform` holds before the call and after a failed
    /// one; neither is true now, since the guard is built only from a successful call. What
    /// reaches it today is a *success* whose blob is null -- which the checks then refuse,
    /// after the guard has been built over it. So the case is still live, and an engineering
    /// review was right that its stated motivation had lapsed.
    ///
    /// The size reported here is zero on purpose. A non-zero one would also fail if the
    /// null check were dropped, but it would fail by writing through null and taking the
    /// test process down with it; this way the same mutation fails on an assertion.
    #[test]
    fn a_null_block_is_not_measured_or_released() {
        let asked = std::cell::Cell::new(0_usize);
        let freed = std::cell::Cell::new(0_usize);
        wipe(
            std::ptr::null_mut(),
            |_| {
                asked.set(asked.get() + 1);
                0
            },
            |_| freed.set(freed.get() + 1),
        );
        assert_eq!((asked.get(), freed.get()), (0, 0), "a null blob was used");
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
