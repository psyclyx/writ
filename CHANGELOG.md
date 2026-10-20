# Changelog

## 0.1.0 (unreleased)

First release. DESIGN.md says what writ does and why; SPEC.md is the
byte-level specification; DESIGN.md §16 records every decision made during
implementation and the review findings that led to them.

- Identities as signed logs with pre-rotation and k-of-n authorities
  (SLH-DSA-SHAKE-128s); leaf keys (ML-DSA-65 + Ed25519 composite) with a 24
  hour ceiling.
- Statements: names, grants with up to 16 tags and delegation, revocations;
  data signatures with a context; channel binding.
- Verification as a pure library: chains, name resolution, revocation,
  rotation `keep` lists, equivocation evidence, resource limits, proofs, a
  clock floor.
- Published revocation records with a freshness rule; `--fetch` over http
  and https in the CLI only.
- The `writ` command: identities as directories of plain files, secret keys
  that compose with age, `--state` for the ratchet and floor, man pages and
  shell completions.
- Test vectors: NIST ACVP for SLH-DSA-SHAKE-128s and ML-DSA-65, the
  ed25519-speccheck edge cases, BIP-350, and writ's own for every format and
  for chain verification.
