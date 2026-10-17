//! Overwriting secret bytes with zeros.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrites every byte with zero.
///
/// A plain loop of volatile writes, so the compiler cannot drop the writes as
/// dead stores, followed by a fence so they are not moved past the free.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference to a `u8`.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}
