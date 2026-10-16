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
writ init bob --next-out bob-next.key
writ grant  -i me 'me alice' '(zuko)' --delegate --expires 90d | tee zuko.writ >> bundle.writ
writ grant  -i alice bob '(zuko home)' >> bundle.writ   # alice passes on part of it
writ export -i alice >> bundle.writ                     # alice's log, so her grant can be checked
writ check  --as me bob '(zuko home)' < bundle.writ     # allowed

writ revoke -i me zuko.writ >> bundle.writ              # or by the hash prefix grant printed
writ check  --as me bob '(zuko home)' < bundle.writ     # denied: revoked
writ export -i me > me.writ                             # my log, live statements, revocations
```

Signatures, by an identity that may sign releases:

```sh
writ init release --next-out release-next.key
writ grant  -i me release '(release)' >> bundle.writ
writ export -i release >> bundle.writ
writ sign   -i release --context example/release/v1 app.tar > app.tar.sig
writ verify --as me --tag '(release)' --context example/release/v1 app.tar app.tar.sig < bundle.writ
```

Leaf keys are fast and last at most 24 hours. A signature by a leaf key
verifies only while the leaf key's grant is live, so use them for things that
are signed again often, like a status file:

```sh
writ leaf   -i me '(status)' --out ci.key >> bundle.writ
writ sign   --leaf ci.key --context example/status/v1 status.json > status.json.sig
writ verify --as me --tag '(status)' --context example/status/v1 status.json status.json.sig < bundle.writ
```

Rotation, with the next key kept offline (and age-encrypted). The next key
can serve again, so a routine rotation only makes a fresh current key:

```sh
writ rotate -i me --next-key <(age -d me-next.key.age) --same-next
```

To replace the next key too, encrypt the new one to an age recipient
(`--next-out - | age -r age1… > me-next2.key.age`), so that only one age
asks for a passphrase at a time.

Rotation keeps every live statement automatically; anything a thief signs
with your old key is dead to every verifier that sees the rotation. Use
`--state DIR` on verifying commands to remember rotations and the clock floor
between runs, and `writ prove` to hand a verifier only the statements it needs.

Every command has `-h` (short) and `--help` (long) help and a man page
(`man writ`, `man writ-grant`, ...); exit status is 0 for yes, 1 for no, 2 for
errors. `writ completions bash|zsh|fish` prints a completion script; the nix
package installs the man pages and completions for you. Color follows
`--color`, `NO_COLOR` and `CLICOLOR_FORCE`.

## Documents

- [DESIGN.md](DESIGN.md) — what writ is and why; §16 records the decisions made
  during implementation.
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
`WRIT_REGENERATE_VECTORS=1 cargo test -p libwrit --test vectors`, and the man
pages (generated from `crates/writ-tool/src/specs.rs`, like `--help` and the
completions) with `WRIT_REGENERATE_MAN=1 cargo test -p writ-tool man`.
