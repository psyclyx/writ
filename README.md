# writ

Signed statements about keys: _who is who_ (names) and _who may do what_
(grants), with delegation that can only narrow, optional expiry, revocation, and
key rotation that keeps your identity.

What age is to PGP, writ aims to be to X.509: one post-quantum suite, no negotiation, plain
files, a pure library, and a CLI that composes with pipes (and with age, for
keys at rest).

```
writ init me --next-out - | age -p > me-next.key.age
writ name  -i me alice writ1…
writ grant -i me 'me alice' '(ssh nas)'
writ check --as $(writ id me) <alice's key> '(ssh nas)' < bundle.writ
```

Status: design complete, implementation starting. See [DESIGN.md](DESIGN.md).

## Layout

```
crates/writ-sexp     canonical s-expressions + armor
crates/writ-slhdsa   SLH-DSA-SHAKE-128s
crates/libwrit       the library
crates/writ-tool     the `writ` binary
```

## Development

`direnv allow` (or `nix-shell -A shell`), then `cargo nextest run`, `treefmt`.
