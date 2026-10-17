//! Plain WebAssembly exports for the worker (`../web/reveal-worker.js`).
//!
//! There is no bindings generator: the worker instantiates the module with
//! `WebAssembly.instantiate`, copies bytes in through [`ghost_alloc`], and
//! reads results back from linear memory. One session lives in the module at
//! a time. Every function that can fail returns 0 on success and a non-zero
//! code otherwise; [`ghost_error_ptr`] and [`ghost_error_len`] then give the
//! message.
//!
//! A WebAssembly module runs on one thread, so the `static mut` state below
//! is never touched concurrently.

#![allow(static_mut_refs)]

use super::{Session, encode_reveal, record_fields, verify};
use ghost_proofs::{CoinReveal, Proof};

static mut SESSION: Option<Session> = None;
static mut LAST: Option<(CoinReveal, Proof)> = None;
static mut REVEAL: Vec<u8> = Vec::new();
static mut FIELDS: String = String::new();
static mut ERROR: String = String::new();

fn fail(message: String) -> u32 {
    unsafe { ERROR = message };
    1
}

/// Allocate `len` bytes the worker may write into; freed with
/// [`ghost_free`].
#[unsafe(no_mangle)]
pub extern "C" fn ghost_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len);
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Free a buffer from [`ghost_alloc`].
///
/// # Safety
/// `ptr` and `len` must come from one [`ghost_alloc`] call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_free(ptr: *mut u8, len: usize) {
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len) });
}

/// Draw the session's witness from `seed` (not timed). `same_key` is 0 or 1.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_session(seed: u32, same_key: u32) -> u32 {
    let session = Session::new(seed, same_key != 0);
    match record_fields(&session) {
        Ok(fields) => unsafe {
            FIELDS = fields;
            SESSION = Some(session);
            LAST = None;
            0
        },
        Err(e) => fail(e.to_string()),
    }
}

/// Prove the session's reveal with the 32 bytes of zero-knowledge randomness
/// at `zk_ptr`. This call is what the worker times.
///
/// # Safety
/// `zk_ptr` must point at 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ghost_prove(zk_ptr: *const u8) -> u32 {
    let zk: [u8; 32] = unsafe { core::slice::from_raw_parts(zk_ptr, 32) }.try_into().expect("32 bytes");
    let Some(session) = (unsafe { SESSION.as_ref() }) else {
        return fail(String::from("no session"));
    };
    match session.prove(zk) {
        Ok((tx, proof)) => unsafe {
            REVEAL = encode_reveal(&tx);
            LAST = Some((tx, proof));
            0
        },
        Err(e) => fail(e.to_string()),
    }
}

/// Verify the last proof in the worker. 0 when it verifies.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_verify() -> u32 {
    match unsafe { LAST.as_ref() } {
        Some((tx, proof)) => match verify(tx, proof) {
            Ok(()) => 0,
            Err(e) => fail(e.to_string()),
        },
        None => fail(String::from("no proof")),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_proof_ptr() -> *const u8 {
    unsafe { LAST.as_ref().map_or(core::ptr::null(), |(_, p)| p.as_bytes().as_ptr()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_proof_len() -> usize {
    unsafe { LAST.as_ref().map_or(0, |(_, p)| p.as_bytes().len()) }
}

/// The public fields of the last reveal, as `encode_reveal` writes them.
#[unsafe(no_mangle)]
pub extern "C" fn ghost_reveal_ptr() -> *const u8 {
    unsafe { REVEAL.as_ptr() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_reveal_len() -> usize {
    unsafe { REVEAL.len() }
}

/// The configuration fields of a result record (JSON, UTF-8).
#[unsafe(no_mangle)]
pub extern "C" fn ghost_fields_ptr() -> *const u8 {
    unsafe { FIELDS.as_ptr() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_fields_len() -> usize {
    unsafe { FIELDS.len() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_error_ptr() -> *const u8 {
    unsafe { ERROR.as_ptr() }
}

#[unsafe(no_mangle)]
pub extern "C" fn ghost_error_len() -> usize {
    unsafe { ERROR.len() }
}
