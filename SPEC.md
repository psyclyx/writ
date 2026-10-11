# writ v1 — specification

This document specifies writ v1 at the byte level: the cryptographic
constructions, every encoded item, and the rules a verifier applies. DESIGN.md
explains _why_; this document says _exactly what_. The reference
implementation is `libwrit` in this repository; test vectors are in
[`vectors/`](vectors/README.md).

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in
RFC 2119.

## 1. Notation

- `‖` is byte-string concatenation. `0x00` is a single zero byte.
- `"text"` denotes the ASCII bytes of `text`, without terminator.
- `SHA3-256(x)` and `SHAKE256(x, L)` are from FIPS 202; the latter outputs
  `L` bytes.
- `[a..b)` is a half-open range.
- Times are unsigned 64-bit counts of seconds since 1970-01-01T00:00:00Z,
  ignoring leap seconds.

## 2. Labelled hashing and signing

Every hash and signature input in writ is labelled:

```
msg(label, data)  = label ‖ 0x00 ‖ data
H(label, data)    = SHA3-256(msg(label, data))
```

The labels are:

| label                               | use                                                     |
| ----------------------------------- | ------------------------------------------------------- |
| `writ/v1/id`                        | identity id: `H(·, canonical(inception body))`          |
| `writ/v1/event`                     | event hash (`prev`); message signed for log events      |
| `writ/v1/authority`                 | authority hash (`next` commitments)                     |
| `writ/v1/stmt`                      | statement hash; message signed for statements           |
| `writ/v1/sig`                       | data-signature hash; message signed for data signatures |
| `writ/v1/data`                      | hash of signed application data                         |
| `writ/v1/fingerprint`               | display fingerprints of leaf keys (not normative)       |
| `writ/v1/root/slh-dsa-shake-128s`   | root suite: SLH-DSA context string                      |
| `writ/v1/leaf/mldsa65-ed25519`      | leaf suite: composite prefix and ML-DSA context string  |
| `writ/v1/keygen/slh-dsa-shake-128s` | root key derivation                                     |
| `writ/v1/keygen/mldsa65-ed25519`    | leaf key derivation                                     |

No label is a prefix of another, and the `0x00` terminator makes
`msg(label, data)` unambiguous regardless.

For a body `B` (an event, statement or data signature, §5) with label `L`:

```
hash(B)    = H(L, canonical(B))
message(B) = msg(L, canonical(B))
```

Signatures are over `message(B)`. They are attachments: a body's hash does not
cover its signatures, so signature malleability cannot change an item's
identity.

## 3. Encoding

### 3.1 Canonical S-expressions

Everything hashed or signed is a canonical S-expression (Rivest csexp):

```
sexp  = atom / list
atom  = length ":" bytes        ; length: decimal, "0" or no leading zero
list  = "(" *sexp ")"
```

There are no display hints, no whitespace, no other bytes. Decoders MUST reject
any other input, including leading zeros in lengths and trailing bytes.
Decoders MUST bound their input; libwrit accepts at most 4 MiB per bundle,
nesting depth 32, and 2^18 nodes.

Within items, numbers are atoms holding canonical unsigned decimal: `0` or
`[1-9][0-9]*`, at most 2^64 − 1. A field written `(name X)` is a list whose
first atom is `name`. Optional fields are either present or absent, in the
order given; fields never repeat unless stated.

A decoder MUST reject an item that does not re-encode to exactly its input.

### 3.2 Armor

Items travel as armored text, one block per item:

```
-----BEGIN WRIT-----
<standard padded base64 (RFC 4648 §4) of canonical(item)>
-----END WRIT-----
```

- Every base64 line is exactly 64 characters, except the last, which has 1 to 64. Base64 MUST be canonical (correct padding, zero trailing bits).
- Lines end in LF; CRLF is also accepted. There are no headers.
- Between and around blocks only whitespace (space, tab, CR, LF) may appear.
  Anything else MUST be rejected.

A **bundle** is any number of blocks, in any order, so concatenating armored
files yields a bundle. A bundle MAY instead be the binary concatenation of
canonical items; a decoder distinguishes the two by whether the first
non-whitespace bytes are `-----BEGIN WRIT-----`.

### 3.3 Text forms (informative)

- **ids**: bech32m (BIP-350) with human-readable part `writ` over the 32-byte
  id, e.g. `writ1…` (63 characters). Case-insensitive; mixed case is rejected.
- **secret key files**: one line per seed, bech32m with human-readable part
  `writ-secret-key-` over the 32-byte seed, upper-cased:
  `WRIT-SECRET-KEY-1…`. Readers SHOULD ignore blank lines and lines starting
  with `#`.
- **readable form**: for display and for what humans type (tags, name paths),
  writ uses tokens, `"quoted strings"`, `#hex#` and `|base64|` atoms, as in
  `(zuko home "a b")`. It is never hashed or signed.

## 4. Suites

### 4.1 Root suite: `slh-dsa-shake-128s`

SLH-DSA-SHAKE-128s from FIPS 205, used through the pure (non-prehash) external
interface (FIPS 205 Algorithms 22 and 24) with context string
`"writ/v1/root/slh-dsa-shake-128s"`.

- Public key: 32 bytes (PK.seed ‖ PK.root). Signature: 7856 bytes.
- Signing MUST be hedged: `addrnd` is 16 fresh random bytes.
- A signer MUST verify its own signature before releasing it.
- Key derivation from a 32-byte seed `s`:
  `SHAKE256(msg("writ/v1/keygen/slh-dsa-shake-128s", s), 48)` is split into
  SK.seed ‖ SK.prf ‖ PK.seed (16 bytes each), then
  `slh_keygen_internal(SK.seed, SK.prf, PK.seed)` (FIPS 205 Algorithm 18).

### 4.2 Leaf suite: `mldsa65-ed25519`

A composite of ML-DSA-65 (FIPS 204) and Ed25519 (RFC 8032) over the same
message. For an item message `m`:

```
M'  = msg("writ/v1/leaf/mldsa65-ed25519", m)
sig = ML-DSA-65.Sign(sk_ml, M', ctx = "writ/v1/leaf/mldsa65-ed25519")   ; 3309 bytes, hedged
    ‖ Ed25519.Sign(sk_ed, M')                                            ; 64 bytes
```

- Public key: the ML-DSA-65 verification key (1952 bytes) and the Ed25519
  public key (32 bytes). Signature: 3373 bytes.
- Verification MUST check both components, and MUST fail if either fails.
- ML-DSA-65 signing is hedged (FIPS 204 Algorithm 2 with fresh `rnd`).
- Ed25519 verification MUST be strict: the cofactorless equation
  `[S]B = R + [k]A`; A, R and S canonically encoded (y < p; x = 0 only with
  the sign bit clear; S < L); A and R not of small order. The edge cases of
  `ed25519-speccheck` (vectors/ed25519-speccheck) pin this: only case 3
  verifies.
- Signers SHOULD verify the composite signature before releasing it.
- Key derivation from a 32-byte seed `s`:
  `SHAKE256(msg("writ/v1/keygen/mldsa65-ed25519", s), 64)` is split into
  ξ ‖ e (32 bytes each); the ML-DSA-65 key pair is `ML-DSA.KeyGen_internal(ξ)`
  (FIPS 204 Algorithm 6) and `e` is the Ed25519 secret key.

Because the label names the suite, neither component signature is valid for
any other writ purpose.

## 5. Items

Every encoded item is:

```
item = "(" "writ/v1" body *sig ")"
sig  = "(" "sig" index bytes ")"        ; index: decimal 0–15
```

Signatures MUST be in strictly increasing index order. Events, statements and
data signatures MUST have at least one signature; key and authority items MUST
have none. `index` is the position of the signing key in the signer's
authority (§5.2), and 0 for leaf keys. The signature length MUST be 7856 for
identity signers and 3373 for leaf signers.

### 5.1 Keys

```
rootkey = "(" "slh-dsa-shake-128s" pk ")"           ; pk: 32 bytes
leafkey = "(" "mldsa65-ed25519" mlpk edpk ")"       ; 1952 bytes, 32 bytes
```

A **key item** `(writ/v1 rootkey)` or `(writ/v1 leafkey)` names a public key in
a file.

### 5.2 Authorities

```
authority = "(" "authority" k 1*16rootkey ")"
```

`k` is a decimal threshold, 1 ≤ k ≤ number of keys. Keys MUST be distinct and
sorted by strictly increasing public-key bytes. `hash = H("writ/v1/authority",
canonical(authority))`. An authority item `(writ/v1 authority)` records an
identity's pending next authority.

### 5.3 Log events

```
inception = "(" "inception" authority "(" "next" hash ")" [ "(" "max-validity" secs ")" ] ")"
rotation  = "(" "rotation" "(" "id" id ")" "(" "n" n ")" "(" "prev" hash ")"
                authority "(" "next" hash ")" [ "(" "max-validity" secs ")" ]
                "(" "keep" *hash ")" ")"
```

- `id`, `hash`: 32 bytes. `n` ≥ 1. `secs` ≥ 1.
- `keep` hashes MUST be strictly increasing (bytewise).
- An event's signature indices MUST be less than its own authority's key count.
- The **id** of an identity is `H("writ/v1/id", canonical(inception))`.
- The **hash** of an event is `H("writ/v1/event", canonical(event))`.

### 5.4 Statements

```
statement = name / grant / revoke
issuer    = "(" "issuer" id event ")" / "(" "issuer" leafkey ")"
common    = issuer "(" "issued" time ")" [ "(" "expires" time ")" ] [ "(" "note" text ")" ]
name      = "(" "name"   common label subject ")"
grant     = "(" "grant"  common subject tag [ "(" "delegate" ")" ] ")"
revoke    = "(" "revoke" common "(" "target" hash ")" ")"
subject   = "(" "id" id ")" / leafkey / "(" "key" type keybytes ")" / "(" "name" id 1*16label ")"
tag       = "(" "tag" *32atom ")"
```

- `label` and tag atoms: 1–255 bytes. `text`: UTF-8, at most 1024 bytes,
  display-only. `type`: 1–64 bytes of readable-token characters (ASCII graphic
  except `( ) " # | ' ; \ [ ] { }`). `keybytes`: 1–16384 bytes.
- The statement **hash** is `H("writ/v1/stmt", canonical(statement))`.

A statement is **well-formed** when:

1. if `expires` is present, `expires > issued`;
2. a leaf issuer issues only grants, without `(delegate)`;
3. a grant to an opaque key (`(key …)`) has no `(delegate)`;
4. a grant to a leaf key has `expires` with `expires − issued ≤ 86400`;
5. a revocation has no `expires`.

Ill-formed statements decode (so they can be displayed) but are never valid.

### 5.5 Data signatures

```
signature = "(" "signature" issuer "(" "issued" time ")" "(" "context" context ")" "(" "data" hash ")" ")"
```

`context` is 1–255 bytes chosen by the application. `data` is
`H("writ/v1/data", data)`. The signature **hash** is
`H("writ/v1/sig", canonical(signature))`.

## 6. Identity logs

An identity's log is valid when:

1. Event 0 is an inception whose hash under `writ/v1/id` is the id, signed by
   at least `k` distinct keys of its own authority (a signature counts if its
   index names an authority key and it verifies under that key).
2. For each `n ≥ 1`, consider every rotation in the material with `id` and `n`
   whose authority hashes to event `n − 1`'s `next` and which is signed by `k`
   distinct keys of that authority. Rotations failing these checks are
   ignored: anyone can make them.
   - None: the log ends at `n − 1`.
   - Two or more with different hashes: **equivocation**. The identity is
     compromised and every query that depends on it MUST fail. The prefix
     `0..n−1` plus the two events is self-contained evidence.
   - Exactly one, with `prev` equal to the hash of event `n − 1`: it is event
     `n`. With any other `prev`: the log is **broken** and unusable.

The **head** is the last event. A verifier SHOULD persist the logs it accepts
and add them to future material, so it never accepts an older head (and
equivocation, once seen, stays seen).

## 7. Validity of a statement

A statement with hash `h` is **valid at time `now`** under policy `P` when:

1. It is well-formed (§5.4).
2. If the issuer is an identity `(id, e)`:
   - the identity's log is valid (§6), with head `H`;
   - `e ≤ H`;
   - if `e = H`: the root suite is accepted by `P`, and the statement is signed
     by `k` distinct keys of event `e`'s authority;
   - if `e < H`: `h` is in event `H`'s `keep` list (signatures are not
     checked: the rotation endorses the statement by hash);
   - if event `e` sets `max-validity` = `mv` and the statement is not a
     revocation: `expires` is present and `expires − issued ≤ mv`;
   - if the statement is not a revocation: no valid revocation by `id` targets
     `h` (a revocation's own validity is checked by these rules, without
     this revocation step — revocations cannot be revoked).
3. If the issuer is a leaf key: the leaf suite is accepted by `P`, and a
   signature with index 0 verifies under the key.
4. `issued ≤ now + P.skew`.
5. If `expires` is present: `now < expires`.
6. If it is a grant to a leaf key: `expires − issued ≤ min(P.leaf_ceiling, 86400)`.

A data signature by `(id, e)` is valid under rule 2 (without the
`max-validity` check: data signatures do not expire) and rule 4, with `h` its
signature hash; by a leaf key, under rules 3 and 4.

## 8. Names

Names are local: `(name B n₁ … n_k)` is whoever `B` calls `n₁`, then whoever
they call `n₂`, and so on. Resolution is a bounded fixpoint. With `D` the
policy's maximum name depth:

```
M₀(X, n)  = ∅
M_d(X, n) = ⋃ { denote_{d−1}(s) : s a valid name statement by X with label n }

denote_e(id / leafkey / opaque key) = { that subject }
denote_e((name B n₁ … n_k))          = resolve_e(B, n₁ … n_k)

resolve_e(B, n₁)          = M_e(B, n₁)
resolve_e(B, n₁ n₂ … n_k) = ⋃ { resolve_e(Y, n₂ … n_k) : Y ∈ M_e(B, n₁), Y an id }
```

The members of a name path, and the holders a grant subject denotes, are
`resolve_D` / `denote_D`. Cycles terminate because `d` decreases.

## 9. Tags

A tag is a sequence of atoms, general to specific. `a ⊆ b` iff `b` is a prefix
of `a` (atoms compare as whole byte strings). `∩(a, b)` is the longer of `a`
and `b` if one is a prefix of the other, and undefined otherwise. The empty tag
`()` is everything.

## 10. Chains

Given roots `R`, material, policy `P` and time `now`, a subject `S` (an id, a
leaf key, or an opaque key) **holds** tag `T` when:

- `S` is a root whose log is valid; or
- there is a chain of grants `g₁ … g_L`, `1 ≤ L ≤ P.max_chain`, such that:
  1. `g₁` is issued by a root whose log is valid;
  2. every `gᵢ` is valid at `now` (§7);
  3. for `i < L`: `gᵢ` has `(delegate)`, and the issuer of `gᵢ₊₁` (an id, at
     any event, or a leaf key) is in `denote_D(subject(gᵢ))`;
  4. `S ∈ denote_D(subject(g_L))`;
  5. `E = ∩(tag(g₁), …, tag(g_L))` is defined, and `T ⊆ E`.

If `S` is an id whose log equivocates, the answer is no. A verifier SHOULD
report equivocation it encountered when no chain exists.

A **proof** is the logs of every identity involved, the grants of one chain,
and the name statements that put each holder in each subject. Its effective
tag is `E`; its effective expiry is the minimum `expires` of its statements.
The reference verifier finds a shortest chain by breadth-first search over
(holder, effective tag), checking signatures only for statements on candidate
paths.

A data signature `σ` over data `d` in context `c` is **good for `T`** when
`σ.context = c`, `σ.data = H("writ/v1/data", d)`, `σ` is valid (§7), and its
signer holds `T`.

## 11. Policy

| parameter        | default        | meaning                                |
| ---------------- | -------------- | -------------------------------------- |
| suites           | both v1 suites | accepted suites                        |
| `leaf_ceiling`   | 86400 s        | longest accepted leaf grant (≤ 86400)  |
| `skew`           | 300 s          | tolerance for `issued` in the future   |
| `max_chain`      | 16             | most grants in a chain                 |
| `max_name_depth` | 8              | `D` in §8                              |
| `max_statements` | 10000          | distinct statements examined per query |

## 12. Time

The library never reads a clock. The **floor** is the newest `issued` of a
statement by one of the verifier's roots whose signatures verify (or that is
kept) under the event and keep conditions of §7 rule 2, capped at the wall clock plus `skew`, and never below the build-time
floor (libwrit: 2026-10-11T00:00:00Z). The time used is
`now = max(wall clock, floor + monotonic time since the floor was set)`.
Moving the clock back cannot go below the floor; moving it forward only
expires things early.

## 13. Files (informative)

The `writ` tool keeps an identity in a directory:

```
DIR/log.writ       the identity log, armored events
DIR/issued.writ    everything the identity issued: statements and data signatures
DIR/next.writ      the pending next authority (an authority item; public)
DIR/current.key    the current secret key(s), mode 0600, unless kept elsewhere
```

and verifier state (`--state DIR`) as:

```
DIR/floor           the clock floor, decimal seconds
DIR/logs/ID.writ    every log event seen for identity ID
```

On rotation, the tool's `keep` is every statement and data signature in
`issued.writ` that is still valid (or valid later), except revocations and
grants to leaf keys.
