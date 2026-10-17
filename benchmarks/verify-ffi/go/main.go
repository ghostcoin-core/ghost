//go:build linux || darwin

// Command verifyffi calls the Rust verifier through cgo, the way the Go node
// would, and prints the time of each call and the peak resident memory of
// the process. It reads the fixture written by
// `ghost-bench-verify --fixture DIR`.
//
//	go run . -fixture DIR [-blowup N] [-runs N]
//
// The static library must be built first, from benchmarks/:
//
//	cargo build --release -p ghost-verify-ffi --features parallel
package main

/*
#cgo CFLAGS: -I${SRCDIR}/..
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libghost_verify_ffi.a
#cgo linux LDFLAGS: -lm -ldl -lpthread
#cgo darwin LDFLAGS: -framework CoreFoundation -framework Security
#include "ghost_verify.h"
*/
import "C"

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"time"
	"unsafe"
)

const keccak = 1

func verify(blowup uint32, pis []uint32, proof []byte) int32 {
	var pisPtr *C.uint32_t
	if len(pis) > 0 {
		pisPtr = (*C.uint32_t)(unsafe.Pointer(&pis[0]))
	}
	var proofPtr *C.uint8_t
	if len(proof) > 0 {
		proofPtr = (*C.uint8_t)(unsafe.Pointer(&proof[0]))
	}
	return int32(C.ghost_verify(keccak, C.uint32_t(blowup), pisPtr, C.size_t(len(pis)), proofPtr, C.size_t(len(proof))))
}

// peakKiB is the peak resident memory of the process, Rust heap included.
func peakKiB() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return -1
	}
	if runtime.GOOS == "darwin" {
		return int64(ru.Maxrss) / 1024
	}
	return int64(ru.Maxrss)
}

func main() {
	fixture := flag.String("fixture", "", "directory with proof.bin and public_inputs.bin")
	blowup := flag.Uint("blowup", 3, "log2 of the blowup the fixture was proven with")
	runs := flag.Int("runs", 10, "calls per case")
	flag.Parse()
	if *fixture == "" || *runs < 1 {
		flag.Usage()
		os.Exit(2)
	}
	proof, err := os.ReadFile(filepath.Join(*fixture, "proof.bin"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	raw, err := os.ReadFile(filepath.Join(*fixture, "public_inputs.bin"))
	if err != nil || len(raw)%4 != 0 {
		fmt.Fprintln(os.Stderr, "public_inputs.bin: unreadable or not whole u32 values")
		os.Exit(1)
	}
	pis := make([]uint32, len(raw)/4)
	for i := range pis {
		pis[i] = binary.LittleEndian.Uint32(raw[4*i:])
	}

	wrong := append([]uint32(nil), pis...)
	wrong[0] ^= 1
	altered := append([]byte(nil), proof...)
	altered[len(altered)-2] ^= 1

	cases := []struct {
		name   string
		pis    []uint32
		proof  []byte
		accept bool
	}{
		{"valid", pis, proof, true},
		{"wrong public input", wrong, proof, false},
		{"truncated by one byte", pis, proof[:len(proof)-1], false},
		{"altered at the end", pis, altered, false},
		{"empty", pis, nil, false},
	}

	fmt.Printf("%s %s/%s, %d runs per case\n\n", runtime.Version(), runtime.GOOS, runtime.GOARCH, *runs)
	fmt.Println("| Case | Status | Median (ms) | Largest (ms) |")
	fmt.Println("|---|---|---|---|")
	wrongOutcomes := 0
	for _, c := range cases {
		times := make([]float64, 0, *runs)
		var status int32
		for i := 0; i < *runs; i++ {
			start := time.Now()
			status = verify(uint32(*blowup), c.pis, c.proof)
			times = append(times, float64(time.Since(start).Nanoseconds())/1e6)
		}
		sort.Float64s(times)
		if (status == C.GHOST_VERIFY_ACCEPTED) != c.accept || status == C.GHOST_VERIFY_PANICKED {
			wrongOutcomes++
		}
		fmt.Printf("| %s | %d | %.2f | %.2f |\n", c.name, status, times[len(times)/2], times[len(times)-1])
	}
	fmt.Printf("\nProcess peak resident memory: %d KiB\n", peakKiB())
	if wrongOutcomes > 0 {
		fmt.Fprintf(os.Stderr, "%d case(s) gave the wrong outcome\n", wrongOutcomes)
		os.Exit(1)
	}
}
