# Benchmarks

## SLH-DSA-SHAKE-128s (`writ-slhdsa`)

Measured 2026-10-19.

| operation                  | writ-slhdsa | RustCrypto `slh-dsa` 0.2.0-rc.5 |
| -------------------------- | ----------: | ------------------------------: |
| keygen (`keygen_internal`) |     81.8 ms |                        166.1 ms |
| sign (pure, hedged)        |    620.7 ms |                          1.26 s |
| `sign_internal`            |    620.0 ms |                          1.27 s |
| verify (pure)              |     0.58 ms |                         1.18 ms |

`sign` and `sign_internal` include writ's self-verification of the signature
before release (< 0.1% of the cost) and the stack scrub; RustCrypto's
`try_sign_with_context` does neither. Both produce byte-identical signatures
(checked by the bench). The 2026-10-11 measurement was about 3% faster
(601.8 ms sign); the difference is within what the machine's state accounts
for.

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

## libwrit: leaf suite and verification

Measured 2026-10-11 on the same machine and toolchain as above, with
`cargo run --release -p libwrit --example bench`
(`crates/libwrit/examples/bench.rs`): one warm-up, then the median of 11–1001
runs depending on cost. Stable to within a few percent across runs.

| operation                                                            |   median |
| -------------------------------------------------------------------- | -------: |
| root key derivation (seed → SLH-DSA keys)                            |  79.4 ms |
| leaf key derivation (seed → ML-DSA-65 + Ed25519)                     |  65.7 µs |
| leaf sign (composite, with self-check)                               | 280.7 µs |
| leaf verify (both components, strict Ed25519)                        |  99.5 µs |
| check, 3-grant chain, cold (decode bundle, verify 3 logs + 3 grants) |  3.52 ms |
| check, same chain, signatures cached                                 |  48.6 µs |

**Notes.** A cold check is dominated by six SLH-DSA verifications (~0.56 ms
each). After that, `Material` caches signature results by (body, signer,
signature bytes), and a check costs a lookup and a short search, as DESIGN §7
intends. Leaf signing derives the ML-DSA key from the seed on every call (so
only the seed is held in memory) and verifies its own output; together these
make up more than half of its cost.
