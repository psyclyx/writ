# Test vectors

Everything here is checked by `cargo test`. Files we generate are regenerated
with `WRIT_REGENERATE_VECTORS=1 cargo test -p libwrit --test vectors`;
generation is deterministic (a fixed, non-cryptographic RNG stands in for
signing randomness), so regenerating changes nothing unless the format did.

## External

| directory            | source                                                                                      | checked by                         |
| -------------------- | ------------------------------------------------------------------------------------------- | ---------------------------------- |
| `acvp/`              | NIST ACVP SLH-DSA-SHAKE-128s keyGen/sigGen/sigVer (see `acvp/README.md`)                    | `crates/writ-slhdsa/tests/acvp.rs` |
| `ed25519-speccheck/` | `novifinancial/ed25519-speccheck` `cases.json` @ `65519336fda78a3d016e947df6d82848aca0c9da` | `libwrit` `keys::tests`            |

BIP-350 bech32m vectors are inline in `crates/libwrit/src/bech32.rs`.

## writ's own (SPEC.md)

Text files are blocks of `key = value` lines separated by blank lines; `#`
lines are comments. Hex is lower case.

- `keys/derivation.txt` — seed → secret key line, SLH-DSA public key, ML-DSA-65
  verification key, Ed25519 public key, leaf id (SPEC §4, §5.1).
- `items/rejections.txt` — mutations of a valid statement item that decoders
  MUST reject (SPEC §3, §5); the first case is the valid original.
- `chains/world.writ` — a bundle exercising every rule: names, delegation,
  narrowing, expiry, revocation, future issue, leaf keys, an opaque key, a
  rotation with `keep`, and an equivocating identity.
- `chains/items.txt` — each item in `world.writ`: kind, hash (and id for
  inceptions), encoded length, and the label the cases use.
- `chains/cases.txt` — queries against `world.writ` from the root `me`, with
  the expected answer: for allowed, the chain (statement labels in order),
  effective tag and expiry; for denied, the reason and each rejected
  candidate with its reason kind.
- `chains/signature.writ`, `chains/signature.txt` — a leaf-signed data
  signature and its expected verification results.

Reason kinds: `malformed`, `log`, `unknown-event`, `not-kept`,
`unknown-leaf` (the leaf key is not in the material), `bad-signature`, `suite`, `revoked`, `not-yet-valid`, `expired`,
`max-validity`, `leaf-ceiling`, `covers` (reaches the subject with too narrow
a tag), `outside-issuer` (grants outside what its issuer holds).
