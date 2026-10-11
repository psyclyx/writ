# Benchmarks

## SLH-DSA-SHAKE-128s (`writ-slhdsa`)

Measured 2026-10-11.

| operation                  | writ-slhdsa | RustCrypto `slh-dsa` 0.2.0-rc.5 |
| -------------------------- | ----------: | ------------------------------: |
| keygen (`keygen_internal`) |     79.1 ms |                        162.2 ms |
| sign (pure, hedged)        |    601.8 ms |                          1.24 s |
| `sign_internal`            |    601.2 ms |                          1.24 s |
| verify (pure)              |     0.56 ms |                         1.15 ms |

`sign` includes writ's self-verification of the signature before release
(< 0.1% of the cost); RustCrypto's `try_sign_with_context` does not
self-verify. Both produce byte-identical signatures (checked by the bench).

**Method.** `cargo run --release -p writ-slhdsa --example bench 21`
(`crates/writ-slhdsa/examples/bench.rs`). Default release profile
(opt-level 3, no LTO, no `target-cpu`). Single-threaded, wall clock
(`std::time::Instant`); one warm-up run, then the median of 21 runs for
keygen/sign and 420 runs for verify. Fixed keys, a 64-byte message and a
13-byte context. Results were stable to within ~1% across repeated runs.

**Machine.** AMD Ryzen 9 5950X 16-Core Processor (32 threads), cpufreq
governor `performance`. `Linux sigil 7.0.14-zen1 #1-NixOS ZEN SMP
PREEMPT_DYNAMIC x86_64 GNU/Linux`. rustc 1.98.1 (48a229cea 2026-09-01),
cargo 1.98.0.

**Notes.** Signing costs about 2.2 million Keccak-f[1600] permutations
(~270 ns each with the portable `libcrux-sha3` backend); nearly all of it is
WOTS+ chains in the 7 hypertree layers. writ-slhdsa computes each XMSS
tree's root and authentication path in one pass and streams `T_l` inputs
into the XOF; it does not use SIMD (4-way AVX2 Keccak would be the next
step if signing speed ever matters).
