//! WebAssembly exports, called from the benchmark worker.
//!
//! The worker builds a [`BenchInstance`] (security gate, witness and public
//! inputs; not timed), then times [`BenchInstance::prove`] with
//! `performance.now()` around the call, and [`BenchInstance::verify`] the
//! same way. Zero-knowledge randomness is passed in from
//! `crypto.getRandomValues` on every run; it is never seeded.

use ghost_bench::{HashCandidate, Instance};
use wasm_bindgen::prelude::*;

/// Library revision compiled into this module.
#[wasm_bindgen(js_name = libraryRevision)]
pub fn library_revision() -> String {
    ghost_bench::PLONKY3_REVISION.to_string()
}

#[wasm_bindgen]
pub struct BenchInstance {
    inner: Instance,
}

fn seed32(bytes: &[u8]) -> Result<[u8; 32], JsError> {
    bytes
        .try_into()
        .map_err(|_| JsError::new("the zero-knowledge seed must be 32 bytes"))
}

#[wasm_bindgen]
impl BenchInstance {
    /// Run the security gate for `candidate` ("a"/"poseidon2" or
    /// "b"/"keccak") at blowup `2^log_blowup`, and draw the witness from
    /// `witness_seed`. Throws when the configuration is refused.
    #[wasm_bindgen(constructor)]
    pub fn new(
        candidate: &str,
        log_blowup: u32,
        witness_seed: u32,
        same_key: bool,
    ) -> Result<BenchInstance, JsError> {
        let candidate = HashCandidate::parse(candidate)
            .ok_or_else(|| JsError::new("unknown hash candidate"))?;
        let inner = Instance::new(candidate, log_blowup as usize, u64::from(witness_seed), same_key)
            .map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { inner })
    }

    /// Prove; returns the proof bytes (serde with postcard, public inputs
    /// excluded).
    pub fn prove(&self, zk_seed: &[u8]) -> Result<Vec<u8>, JsError> {
        self.inner
            .prove(seed32(zk_seed)?)
            .map_err(|e| JsError::new(&e.to_string()))
    }

    /// Verify a proof against this statement's public inputs.
    pub fn verify(&self, proof: &[u8]) -> bool {
        self.inner.verify(proof).is_ok()
    }

    #[wasm_bindgen(js_name = publicInputsBytes)]
    pub fn public_inputs_bytes(&self) -> u32 {
        self.inner.public_inputs_bytes() as u32
    }

    /// The configuration fields of a result record, as JSON.
    #[wasm_bindgen(js_name = recordFields)]
    pub fn record_fields(&self) -> String {
        self.inner.record_fields().render()
    }
}
