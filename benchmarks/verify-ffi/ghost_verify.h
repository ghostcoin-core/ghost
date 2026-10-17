/* C interface to the benchmark verifier (benchmarks/verify-ffi/src/lib.rs). */
#ifndef GHOST_VERIFY_H
#define GHOST_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define GHOST_VERIFY_ACCEPTED 0
#define GHOST_VERIFY_REJECTED 1
#define GHOST_VERIFY_MALFORMED_PROOF 2
#define GHOST_VERIFY_MALFORMED_PUBLIC_INPUTS 3
#define GHOST_VERIFY_BAD_CONFIGURATION 4
#define GHOST_VERIFY_BAD_ARGUMENT 5
#define GHOST_VERIFY_PANICKED 6

/* candidate: 0 is Poseidon2, 1 is Keccak-256. log_blowup: 1, 2 or 3. */
int32_t ghost_verify(uint32_t candidate, uint32_t log_blowup,
                     const uint32_t *public_inputs, size_t public_inputs_len,
                     const uint8_t *proof, size_t proof_len);

#endif
