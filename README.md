# writ

Signed statements about keys: _who is who_ (names) and _who may do what_
(grants), with delegation that can only narrow, optional expiry, revocation, and
key rotation that keeps your identity.

What age is to PGP, writ aims to be to X.509: one post-quantum suite, no
negotiation, plain files, a pure library, and a CLI that composes with pipes
(and with age, for keys at rest).

- Identities are SLH-DSA-SHAKE-128s (hash-based) key logs with pre-rotation:
  the id never changes, the keys can.
- Leaf keys (ML-DSA-65 + Ed25519, both must verify) are the fast path, always
  time-bounded.
- Names are local (SPKI/SDSI): `me alice` is whoever _you_ said alice is.
- Tags are paths: holding `(ssh)` covers `(ssh nas)`.

## A tour

```sh
writ init me --next-out - | age -p > me-next.key.age   # cold key encrypted from birth
writ init alice --next-out alice-next.key

writ name  -i me alice alice >> bundle.writ             # "my alice is that id"
writ grant -i me 'me alice' '(ssh nas)' >> bundle.writ  # alice, as I name her, may ssh to nas

writ check --as me alice '(ssh nas)' < bundle.writ
# allowed: alice holds (ssh nas)
#   root     me (writ1…)
#   name     3fa2c1d0e8a1b2c3  me's alice is alice
#   grant    9d1e5a07c3f4b21e  me → alice (ssh nas)
#   until    no expiry
```

Delegate, narrow, expire, revoke:

```sh
writ grant  -i me 'me alice' '(zuko)' --delegate --expires 90d >> bundle.writ
writ grant  -i alice bob '(zuko home)' >> bundle.writ   # alice passes on part of it
writ revoke -i me 9d1e5a                                # by hash prefix
writ export -i me > me.writ                             # my log, live statements, revocations
```

Leaf keys and signatures:

```sh
writ leaf   -i me '(release)' --out build.key >> bundle.writ    # 24 h, fast to verify
writ sign   --leaf build.key --context example/release/v1 app.tar > app.tar.sig
writ verify --as me --tag '(release)' --context example/release/v1 app.tar app.tar.sig < bundle.writ
```

Rotation, with the next key kept offline (and age-encrypted):

```sh
writ rotate -i me --next-key <(age -d me-next.key.age) --next-out - | age -p > me-next2.key.age
```

Rotation keeps every live statement automatically; anything a thief signs
with your old key is dead to every verifier that sees the rotation. Use
`--state DIR` on verifying commands to remember rotations and the clock floor
between runs, and `writ prove` to hand a verifier only the statements it needs.

Every command has `--help`; exit status is 0 for yes, 1 for no, 2 for errors.

## Documents

- [DESIGN.md](DESIGN.md) — what writ is and why; §17 lists open findings.
- [SPEC.md](SPEC.md) — the byte-level specification.
- [vectors/](vectors/README.md) — test vectors (NIST ACVP, Ed25519 edge cases,
  writ's own).
- [BENCHMARKS.md](BENCHMARKS.md) — SLH-DSA timings.

## Layout

```
crates/writ-sexp     canonical s-expressions, readable form, strict armor
crates/writ-slhdsa   SLH-DSA-SHAKE-128s (FIPS 205), on libcrux-sha3
crates/libwrit       the library: model, suites, logs, verification, issuing
crates/writ-tool     the `writ` binary
```

## Development

`direnv allow` (or `nix-shell -A shell`), then `cargo nextest run --workspace`,
`treefmt`. Vectors regenerate with
`WRIT_REGENERATE_VECTORS=1 cargo test -p libwrit --test vectors`.
