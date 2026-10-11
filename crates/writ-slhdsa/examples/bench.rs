//! Timing for keygen / sign / verify, ours vs RustCrypto `slh-dsa`.
//!
//! Run: `cargo run --release -p writ-slhdsa --example bench [sign_runs]`.
//! Reports the median wall-clock time of each operation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::hint::black_box;
use std::time::{Duration, Instant};

use slh_dsa::Shake128s;

fn median(mut f: impl FnMut(), runs: usize) -> Duration {
    f(); // warm-up
    let mut times: Vec<Duration> = (0..runs)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    times.sort();
    times[runs / 2]
}

fn main() {
    let runs: usize = std::env::args()
        .nth(1)
        .map_or(11, |s| s.parse().expect("run count"));
    let verify_runs = runs * 20;
    let (sk_seed, sk_prf, pk_seed, addrnd) = ([1u8; 16], [2u8; 16], [3u8; 16], [4u8; 16]);
    let msg = [0x5au8; 64];
    let ctx = b"writ/v1/bench";

    let sk = writ_slhdsa::keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    let vk = sk.verifying_key();
    let sig = writ_slhdsa::sign(&sk, &msg, ctx, &addrnd).unwrap();
    let theirs = slh_dsa::SigningKey::<Shake128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
    let their_vk: &slh_dsa::VerifyingKey<Shake128s> = theirs.as_ref();
    let their_sig = theirs
        .try_sign_with_context(&msg, ctx, Some(&addrnd))
        .unwrap();
    assert_eq!(sig.as_slice(), their_sig.to_bytes().as_slice());

    let rows = [
        (
            "keygen",
            median(
                || {
                    black_box(writ_slhdsa::keygen_internal(
                        black_box(&sk_seed),
                        &sk_prf,
                        &pk_seed,
                    ));
                },
                runs,
            ),
            median(
                || {
                    black_box(slh_dsa::SigningKey::<Shake128s>::slh_keygen_internal(
                        black_box(&sk_seed),
                        &sk_prf,
                        &pk_seed,
                    ));
                },
                runs,
            ),
        ),
        (
            "sign (incl. self-verify)",
            median(
                || {
                    black_box(writ_slhdsa::sign(&sk, black_box(&msg), ctx, &addrnd).unwrap());
                },
                runs,
            ),
            median(
                || {
                    black_box(
                        theirs
                            .try_sign_with_context(black_box(&msg), ctx, Some(&addrnd))
                            .unwrap(),
                    );
                },
                runs,
            ),
        ),
        (
            "sign_internal",
            median(
                || {
                    black_box(writ_slhdsa::sign_internal(&sk, black_box(&msg), &addrnd));
                },
                runs,
            ),
            median(
                || {
                    black_box(theirs.slh_sign_internal(&[black_box(&msg)], Some(&addrnd)));
                },
                runs,
            ),
        ),
        (
            "verify",
            median(
                || assert!(writ_slhdsa::verify(&vk, black_box(&msg), ctx, &sig)),
                verify_runs,
            ),
            median(
                || {
                    assert!(
                        their_vk
                            .try_verify_with_context(black_box(&msg), ctx, &their_sig)
                            .is_ok()
                    );
                },
                verify_runs,
            ),
        ),
    ];

    println!("SLH-DSA-SHAKE-128s, median of {runs} runs ({verify_runs} for verify)");
    println!(
        "{:<26} {:>14} {:>14}",
        "operation", "writ-slhdsa", "slh-dsa"
    );
    for (name, ours, theirs) in rows {
        println!("{name:<26} {ours:>14.2?} {theirs:>14.2?}");
    }
}
