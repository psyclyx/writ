# writ

writ makes and checks signed statements about keys: names (who is who) and
grants (who may do what). A grant can be passed on, and each step can only
narrow what the one before it allowed. Statements can expire and can be
revoked. An identity can replace its keys without changing its id.

writ uses one fixed set of algorithms, with no options. It works on plain
files, and its commands read and write standard input and output, so they
combine with pipes and with age(1) for encrypting keys. The library, libwrit,
does no I/O: the caller passes in the time and the randomness.

## Concepts

- **Identity**: a short signed log of keys, with an id (`writ1…`) that never
  changes. The current key signs statements. The next key, kept offline,
  signs rotations, which replace the keys. Identity keys are
  SLH-DSA-SHAKE-128s (FIPS 205), whose security rests only on hash functions.
- **Statement**: a name, grant or revocation, signed by an identity. A leaf
  key can also sign grants.
- **Tag**: what a grant allows, a list of words from general to specific.
  Holding `(ssh)` includes `(ssh nas)`.
- **Name**: local to the identity that issues it. `me alice` is whoever `me`
  has named alice.
- **Leaf key**: a key without a log, for fast signing. It is ML-DSA-65 and
  Ed25519 together, and both signatures must verify. A grant to a leaf key
  lasts at most 24 hours.
- **Bundle**: a file of logs, statements and signatures, in any order.
  `cat a.writ b.writ > c.writ` makes a bundle.

To answer a question, writ starts from the identities you trust (`--as`,
usually your own) and looks for a chain of valid grants to the subject.

Secret keys are plaintext files with mode 0600, and writ never overwrites
them. Any key path can be `-` or `/dev/fd/N`, so keys can be encrypted with
age and never stored in plaintext.

## Tour

Create two identities. The next key goes to the path given with
`--next-out`; here `-` sends it to age:

```sh
writ init me --next-out - | age -p > me-next.key.age
writ init alice --next-out alice-next.key
```

Name an identity and grant a tag to the name:

```sh
writ name  -i me alice alice >> bundle.writ             # my name "alice" is the identity in ./alice
writ grant -i me 'me alice' '(ssh nas)' >> bundle.writ  # whoever I call alice may use (ssh nas)
writ check --as me alice '(ssh nas)' < bundle.writ
# allowed: alice holds (ssh nas)
#   root     me (writ1…)
#   name     1d2e1395d51373a6  me's alice is alice
#   grant    3b3d7b4875586d6c  me → alice (ssh nas)
#   until    no expiry
```

Pass on part of a grant, then revoke it:

```sh
writ init bob --next-out bob-next.key
writ grant  -i me 'me alice' '(zuko)' --delegate --expires 90d | tee zuko.writ >> bundle.writ
writ grant  -i alice bob '(zuko home)' >> bundle.writ   # alice passes on part of (zuko)
writ export -i alice >> bundle.writ                     # alice's log, to check what alice signs
writ check  --as me bob '(zuko home)' < bundle.writ
writ revoke -i me zuko.writ >> bundle.writ              # or the first digits of its hash
writ check  --as me bob '(zuko home)' < bundle.writ     # denied: revoked
```

`writ export -i me` prints an identity's log and valid statements, to give
to others.

Sign files with an identity. A signature stays valid while its signer holds
the tag. The context is a label for one kind of signature, so a signature
made for one purpose is not valid for another:

```sh
writ init release --next-out release-next.key
writ grant  -i me release '(release)' >> bundle.writ
writ export -i release >> bundle.writ
writ sign   -i release --context example/release/v1 app.tar > app.tar.sig
writ verify --as me --tag '(release)' --context example/release/v1 app.tar app.tar.sig < bundle.writ
```

A leaf key signs much faster than an identity key, and its signatures are
less than half the size. Its signatures verify only while its grant is valid, at most
24 hours, so use leaf keys for things that are signed again often:

```sh
writ leaf   -i me '(status)' --out ci.key >> bundle.writ
writ sign   --leaf ci.key --context example/status/v1 status.json > status.json.sig
writ verify --as me --tag '(status)' --context example/status/v1 status.json status.json.sig < bundle.writ
```

Rotation makes a new current key and keeps the id. It needs the next key,
which can stay the same (`--same-next`):

```sh
writ rotate -i me --next-key <(age -d me-next.key.age) --same-next
```

The rotation keeps the identity's statements and signatures that are still
valid, as listed in `me/issued.writ`. Statements signed with the old key and not kept stop
verifying wherever the rotation is seen; this is how you recover from a
stolen current key. To replace the next key as well, use `--next-out` instead
of `--same-next`, and encrypt the new key to an age recipient (`age -r`) so
that only one age command asks for a passphrase.

Verifiers learn about rotations and revocations only from the bundles they
are given. With `--state DIR`, `check`, `verify`, `resolve` and `prove`
remember the logs and revocations they have seen, so an older bundle cannot
undo a rotation or a revocation. They also never use a time earlier than the
newest statement seen from the identities they trust, so setting the clock
back does not make expired grants valid again. `writ prove` prints
only the statements needed for one answer, to give to a verifier instead of
a whole bundle.

## Usage

Every command has short help (`-h`), long help (`--help`) and a man page
(`man writ`, `man writ-grant`, …). The exit status is 0 for success or yes, 1
for no, and 2 for errors. `writ completions bash|zsh|fish` prints a
completion script; the nix package installs the man pages and completions.
Color follows `--color`, `NO_COLOR` and `CLICOLOR_FORCE`.

## Documents

- [DESIGN.md](DESIGN.md): what writ does and why. §16 lists the decisions
  made during implementation.
- [SPEC.md](SPEC.md): the byte-level specification.
- [vectors/](vectors/README.md): test vectors (NIST ACVP for SLH-DSA and
  ML-DSA, Ed25519 edge cases, and writ's own).
- [BENCHMARKS.md](BENCHMARKS.md): signing and verification timings.

## Layout

```
crates/writ-sexp     canonical s-expressions, readable form, armor
crates/writ-slhdsa   SLH-DSA-SHAKE-128s (FIPS 205)
crates/libwrit       the library: encoding, keys, logs, issuing, verification
crates/writ-tool     the writ command
fuzz/                fuzz targets for the decoders
```

## Development

`direnv allow` sets up the dev shell and the pre-commit hook, which runs
treefmt, clippy and `cargo audit`. Without direnv, use `nix-shell -A shell`
and `git config core.hooksPath hooks`.

```
cargo nextest run --workspace                                    # tests
treefmt                                                          # format
WRIT_REGENERATE_VECTORS=1 cargo test -p libwrit --test vectors   # vectors/
WRIT_REGENERATE_MAN=1 cargo test -p writ-tool man                # doc/man/
```

The man pages, `--help` and the completion scripts are all generated from
`crates/writ-tool/src/specs.rs`. Fuzzing is described in
[fuzz/README.md](fuzz/README.md).
