# writ — agent guide

Read **DESIGN.md** first. It is authoritative for _what_ to build and _why_.
This file covers _how_ to work here.

## Ground rules

- **Design decisions are settled.** If something in DESIGN.md is wrong,
  ambiguous, or unimplementable, stop and ask rather than improvise. Once
  resolved, record it in DESIGN.md §16 (decisions log) or §17 (open questions).
- **Simple over easy.** Small crates, small modules, few concepts. Each piece
  should be understandable and testable alone. If something is getting
  complicated, that is a signal to stop and re-check the design, not to push
  through.
- **libwrit is pure**: no IO, no clock reads, no ambient randomness, no global
  state. Time and RNG are arguments. Only `writ-tool` touches the filesystem,
  the clock, or the OS RNG.
- **Untrusted input never panics.** All decoding is total and bounded (size,
  depth, counts). Workspace lints deny `unwrap`/`expect`/`panic`; `unsafe` is
  forbidden.
- **No negotiation, no options in the crypto.** One root suite, one leaf
  suite, as specified.

## Dependencies

Runtime dependencies are limited to this list. Ask before adding anything else.

| Crate             | Used by              | Notes                                                                                                                                    |
| ----------------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `libcrux-sha3`    | writ-slhdsa, libwrit | SHA3-256, SHAKE256                                                                                                                       |
| `libcrux-ml-dsa`  | libwrit              | ML-DSA-65 (leaf suite)                                                                                                                   |
| `libcrux-ed25519` | libwrit              | Ed25519 (leaf suite). Verify it can do strict verification (DESIGN §3.2); if not, wrap it with the missing checks. Report what you find. |
| `zeroize`         | writ-slhdsa, libwrit | wiping secret material (`unsafe` is forbidden here)                                                                                      |
| `getrandom`       | writ-tool only       | the OS RNG                                                                                                                               |

- Pin libcrux crates to exact versions (`=x.y.z`). They are pre-0.1.
- Allowed dev-dependencies: `proptest`, and RustCrypto `slh-dsa` and `ml-dsa`
  for differential testing only. Ask before adding others.
- Implement these ourselves: csexp, armor, bech32m, SLH-DSA, the composite
  construction, CLI argument parsing (keep it small and hand-written).

## Crypto discipline

- Every hash or signature input starts with a `writ/v1/<purpose>` label.
- Secret-dependent branches and memory indexing are bugs. In SLH-DSA, tree
  indices come from the (public) message digest; secret seeds only ever enter
  hash inputs.
- SLH-DSA signing is hedged (the caller supplies randomness) and verifies its
  own output before returning it.
- Wipe secret key material with `zeroize` when it is dropped.
- Every primitive and format has external test vectors where they exist, plus
  our own published vectors in `vectors/` where they don't.

## Milestones

Work in order. Each milestone ends with green tests, clippy clean, treefmt
clean, and a commit.

1. **writ-sexp**
   - Canonical csexp encode/decode. Reject non-canonical input. Enforce limits.
   - A readable-form parser for what humans type (tags, name paths). Readable
     display for `writ show`.
   - Strict armor (DESIGN §12).
   - Property tests: round-trips; canonical encoding is unique; every rejected
     input really is invalid.
2. **writ-slhdsa**
   - SLH-DSA-SHAKE-128s per FIPS 205: internal keygen/sign/verify, plus the
     pure external API with a context string.
   - Pass the NIST ACVP vectors for SLH-DSA-SHAKE-128s keyGen, sigGen and
     sigVer. Vendor the relevant subset under `vectors/acvp/` from
     `usnistgov/ACVP-Server` and note where it came from.
   - Differential tests against RustCrypto `slh-dsa`.
   - Record sign and verify timings in `BENCHMARKS.md` (machine, method,
     numbers).
3. **libwrit: encoding and model**
   - Types for every item in DESIGN §4–§8, with canonical csexp forms.
   - Labelled hashing; id derivation; statement hash = hash of the body only.
   - bech32m (BIP-350 vectors). Secret key file format. Seed → key derivation.
   - Start **SPEC.md**: the normative byte-level spec (C2SP style). It grows
     with each milestone.
4. **libwrit: suites**
   - Root suite: wraps writ-slhdsa.
   - Leaf suite: composite ML-DSA-65 + Ed25519 with domain separation; both
     signatures must verify.
   - Strict Ed25519, pinned by the vectors from `novifinancial/ed25519-speccheck`.
5. **libwrit: identity logs**
   - Inception and rotation; k-of-n authorities; `keep`; the per-id ratchet;
     equivocation evidence.
6. **libwrit: statements and verification**
   - Tags: intersection and ⊆.
   - Name resolution as a bounded fixpoint.
   - Revocation; chain validity (DESIGN §9.3); `check`/`resolve`/`verify`;
     proofs; `Floor`; resource limits; signature caching by hash.
   - Write a **brute-force reference verifier** (small, obviously correct,
     slow) and property-test the real verifier against it on generated material.
7. **writ-tool**
   - The CLI in DESIGN §14, including the age-composition properties: `-` and
     `/dev/fd/N` key paths; secrets can go to stdout; key files are created
     with mode 0600 and never overwritten. Issuance log; `keep` computed
     automatically on `rotate`.
   - End-to-end tests driving the binary.
8. **Spec and vectors**
   - Finish SPEC.md. Publish vectors in `vectors/` for every format and for
     chain-verification cases, including rejections.

## Workflow

- Dev shell: `direnv allow` (or `nix-shell -A shell`).
- Test: `cargo nextest run --workspace`. Lint: `cargo clippy --workspace
--all-targets -- -D warnings`. Format: `treefmt`.
- The pre-commit hook runs treefmt and clippy. Don't bypass it.
- Commit at milestone boundaries (or smaller), with messages that say what
  and why.

## Out of scope

Encryption (use age), networking or transport, agents and hardware keys,
X.509 interop, stateful signatures, algorithm negotiation. The `Signer` trait
leaves room for agents later — don't build them now.
