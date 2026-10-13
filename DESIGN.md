# writ — design

Status: implemented (v0.1); SPEC.md is the normative byte-level spec. Decisions
made during implementation are in §16. A standalone project; zuko (a p2p
networking system) is its first consumer, but writ knows nothing about zuko.

writ is a small, opinionated tool and library for signed statements about keys:
_who is who_ (names) and _who may do what_ (grants), with delegation, narrowing,
optional expiry, revocation, and key rotation that preserves identity. It is to
X.509 roughly what age is to PGP: one suite, no negotiation, simple files, a
library that is a pure function, and a CLI that composes with pipes.

It is a modern take on SPKI/SDSI (RFC 2693): local names, no global root,
authority flows only from the roots the verifier chose.

---

## 1. Goals and non-goals

**Goals**

- Usable as a personal CA with plain files: issue a cert today, have it stay
  good until the math breaks, your key file leaks, or you revoke it. No forced
  maintenance.
- Hierarchical trust without central authority: "my devices" vs "my friends'
  devices" vs "my org" vs "anyone" are all just chains from _my_ identity.
- Safe not to know or trust everyone: delegation can only narrow.
- Post-quantum from day one, with long-lived identities on the most conservative
  assumption available.
- A fast path for high-volume or size-sensitive use, with a bounded blast radius
  if its algorithm is secretly broken.
- Key rotation and suite migration without changing identity.
- Simple enough to implement, verify, and change: few concepts, each small.

**Non-goals**

- Not a PKI: no CAs, no global namespace, no discovery.
- No transport or freshness: how statements and revocations travel is the
  application's job. The library is pure.
- Not a policy language: tags + narrowing is the ceiling.
- No encryption (use age), no algorithm negotiation, no stateful signatures, no
  X.509 interop.

---

## 2. Concepts at a glance

```
identity log   inception, rotation                 (who an identity's keys are, over time)
statements     name, grant, revoke                 (assertions by an issuer)
signatures     over arbitrary data, with context   (for apps: records, files, releases)
tag            flat path of atoms                  (what a grant authorizes)
leaf key       bare fast-suite key, time-bounded   (the fast path)
```

Verification: given _who I am_ (roots), a pile of material (logs, statements,
revocations), and _now_, answer "does subject S hold tag T?" or "who does name
path N refer to?", returning the proof.

---

## 3. Cryptography

### 3.1 Suites and roles

| Role                            | Suite                             | Why                                                                                                                                                                                                                                           |
| ------------------------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Root** (identity authorities) | `slh-dsa-shake-128s` (FIPS 205)   | Security rests only on hash functions — the most conservative assumption available — for the one thing we never want to replace. 32-byte public keys. Large (7856 B), slow-to-make signatures are fine at human signing rates and are cached. |
| **Leaf** (fast path)            | `mldsa65-ed25519` composite       | ML-DSA-65 (FIPS 204) and Ed25519 over the same domain-separated message; **both** must verify. Fast to sign and verify, ~3.4 KB. Less conservative than root, so always time-bounded and structurally limited (§7).                           |
| Hash                            | SHA3-256; SHAKE256 for derivation | Keccak only — same family SLH-DSA already uses.                                                                                                                                                                                               |

There is exactly one root suite and one leaf suite in v1. A suite is named by an
identifier carried in every key, so a future version can add or retire suites
without negotiation (§10).

Rejected: FN-DSA (draft, floating-point sampling), pure ML-DSA for roots
(single young assumption), SLH-DSA+Ed25519 composite at the root (adds nothing —
Ed25519 already assumes hash security), WOTS+ one-time keys for rotation (a reuse
is a silent total compromise; stateful signatures don't belong in a human tool).

### 3.2 Construction rules

- Every hashed or signed input begins with a domain-separation label of the form
  `writ/v1/<purpose>`.
- SLH-DSA signing uses the hedged variant (fresh randomness) and **verifies its
  own signature before releasing it** (fault-attack mitigation).
- Composite leaf signatures: the label binds the suite and role, so a component
  signature cannot be stripped out and presented as a single-algorithm one. ML-DSA
  uses the FIPS 204 context string.
- Ed25519 verification is **strict**: cofactorless RFC 8032 equation, canonical
  encodings of A, R and S required, small-order A and R rejected. Pinned by the
  edge-case vectors from Chalkias et al., "Taming the many EdDSAs". We have no
  legacy signatures to be permissive toward, and caching removes any need for
  batch verification, so ZIP-215's permissive/cofactored rules buy nothing. If
  the imported implementation doesn't expose exactly this, wrap it with the
  missing checks rather than switch semantics.
- Key generation is deterministic from a 32-byte seed via SHAKE256 with a label,
  so a secret key file is one seed.

### 3.3 Implementation sources

- Imported (arithmetic, side channels): `libcrux-sha3`, `libcrux-ml-dsa`,
  `libcrux-ed25519`. Formally verified in large part; pre-0.1 and not
  independently audited for the PQ parts — pin exact versions.
- Implemented here: SLH-DSA on top of `libcrux-sha3` (pure hashing, no field
  arithmetic), the composite construction, canonical encoding, bech32m.
- Homework for what we implement: written spec with test vectors; NIST ACVP
  vectors for SLH-DSA; differential tests against RustCrypto `slh-dsa`
  (dev-dependency only); fuzzing; property tests.

---

## 4. Identity

An identity is **a short log of key events**, not a key. Its id never changes;
its keys can.

### 4.1 Authority

```
authority = (k, [root-suite public key, ...])      ; k-of-n, plain multiple signatures
```

1-of-1 is the common case. k-of-n covers org roots (two signers) and social
recovery (e.g. 2 of {my cold key, a friend's key, a safe-deposit key}). No
threshold cryptography — just k separate signatures.

**k must be more than half of n** (`2k > n`). Any two groups of k holders then
share a holder, so two different events signed at one position always mean
that some holder signed both (§4.4). The cost: "either of my two backups, held
by different people" is not expressible; one person can still keep one key in
two places.

### 4.2 Inception

```
inception = { authority, next: H(next authority), max-validity? }
id        = SHA3-256("writ/v1/id" ‖ canonical(inception))
```

Signed by k of `authority` (proof of possession). `next` commits to the hash of
the authority allowed to perform the first rotation — the **pre-rotation**
commitment. The _current_ key is warm (used for everyday signing); the _next_
key is cold (kept offline, used only to rotate).

### 4.3 Rotation

```
rotation_n = { id, n, prev: H(event_{n-1}),
               revealed,                   ; must hash to event_{n-1}.next
               authority,                  ; the new current (warm) authority
               next: H(next authority),    ; may equal H(revealed)
               max-validity?,
               keep: [statement hash, ...] }
```

Signed by k of the **revealed** next authority, which signs rotations and
nothing else. The rotation names a new current `authority` for statements. Only
the cold keys can extend the log, so a thief holding the warm key cannot
rotate, loosen policy, or fork.

Because cold keys never sign statements, they can stay cold: `next` may commit
to the same authority again. A recovery set held by friends or kept in a safe
then serves for many rotations, and routine rotations need only its
threshold, while everyday signing stays with the warm key.

**`keep` is always an explicit list.** After rotation _n_, a statement issued
under an earlier event is valid only if its hash is in the latest rotation's
`keep` list. Kept statements are endorsed by hash — their original signatures no
longer need checking, which is what allows a retired suite's verify code to be
deleted. The CLI computes `keep` from its issuance log as: issued − revoked −
expired − leaf delegations. Rotation thereby also garbage-collects.

(There is no `keep: all`. A rotation that keeps everything retires nothing: a
thief with the old warm key could keep signing under the old event number,
since timestamps are signer-chosen.)

### 4.4 Ratchets and equivocation

- Verifiers persist the highest event number seen per id and never accept an
  older log head.
- Two different validly signed events with the same `(id, n)` are **evidence**
  that the next authority was compromised: because `2k > n` (§4.1), some
  holder signed both. The identity is treated as
  compromised: every query involving it fails until the verifier intervenes.
  The library exposes the evidence as a value so applications can gossip it.

### 4.5 Policy

One optional field, `max-validity`, set at inception and changeable only by
rotation. Unset (the default) means statements may be indefinite. When set,
every statement signed by this identity must carry `expires` with
`expires − issued ≤ max-validity`, and verifiers enforce `issued ≤ now + skew`.

What this bounds is the life of each statement: material an identity issued
ages out unless it is re-issued, so verifiers that stop hearing from the
identity eventually stop trusting what they hold. It does **not** bound a thief
who holds the warm key: `issued` is chosen by the signer, so the thief can keep
issuing fresh statements, toward any verifier that hasn't seen the rotation.
Only the rotation reaching the verifier ends that (§10, §16).

---

## 5. Statements

### 5.1 Common shape

```
statement = { kind, issuer, issued, expires?, note?, ...kind fields }
signed    = { statement, signatures }
hash      = SHA3-256("writ/v1/stmt" ‖ canonical(statement))   ; body only
```

- `issuer` is `(id, event n)` for identities, or a leaf key.
- `issued`: seconds since the Unix epoch, signer-asserted.
- `expires`: optional; absent means indefinite (subject to §4.5 and §7).
- `note`: optional UTF-8, signed, display-only. writ never interprets it.
- Statement identity is the hash of the body. Signatures are attachments, so
  signature malleability cannot mint a "different" statement.

### 5.2 Subjects

```
subject = id
        | key (type, bytes)            ; writ leaf key, or opaque app key ("xwing", "ssh-ed25519", ...)
        | name path (id name name ...) ; SDSI compound name
```

writ never verifies signatures by opaque keys; it only answers whether they are
authorized. Applications decide what they accept.

### 5.3 Kinds

```
name    { name: atom, subject }                 ; "in my namespace, <name> refers to <subject>"
grant   { subject, tag, delegate: bool }         ; "<subject> holds <tag>"
revoke  { target: statement hash }               ; issuer revokes one of its own statements
```

- **name**: one name may bind several subjects (a group). Names are local to
  their issuer: `me alice` is whoever _I_ said alice is.
- **grant**: `delegate` (default false) says whether the subject may issue
  further grants under this one. `delegate: true` on an opaque key is rejected
  (opaque keys can't sign statements).
- **revoke**: only the issuer of a statement can revoke it. Revocations
  accumulate and don't depend on order. Revocations are themselves irrevocable — re-issue
  instead. A revocation signed under an old event that is not in `keep` is
  dropped (so a thief's denial-of-service revocations are undone by rotation).

### 5.4 Delegation by naming

A grant to a compound name delegates _naming_ authority: granting
`(me alice devices)` lets alice decide who her devices are, and anyone she names
inherits the grant. This is SDSI working as intended; the subject makes it
explicit, and the CLI calls it out when issuing such a grant.

---

## 6. Tags

```
tag = (atom ...)          ; flat path; atoms are byte strings, compared whole
()                        ; everything

a ⊆ b   iff  b is a prefix of a
∩(a, b) = the longer of the two if one is a prefix of the other, else ∅
```

- `(zuko home relay) ⊆ (zuko home) ⊆ (zuko) ⊆ ()`.
- Atoms compare whole: `(zuko home)` is not a prefix of `(zuko homework)`.
- No wildcards, sets, or ranges. Unions are multiple grants. Order elements
  general → specific (`(ssh <host>)`, not `(<host> ssh)`).
- IP-style prefixes are nibble paths, e.g. `(zuko route f d 1 2 3 4)`;
  list-prefix narrowing gives containment. Non-nibble-aligned prefixes are not
  expressible.
- Cost: one hierarchy per namespace; truly orthogonal dimensions take separate
  grants.

---

## 7. Leaf keys (the fast path)

A leaf key is a bare `mldsa65-ed25519` public key with no log. It exists only as
the subject of a grant from an identity.

- A grant to a leaf key **must** carry `expires`, with
  `expires − issued ≤ 24 hours` (the leaf ceiling: a protocol constant; verifiers
  may lower it). Renewal is a root-suite signature per leaf per day — trivial for
  a daemon holding its device identity's warm key. Anything that needs a longer
  life should be a regular identity; only speed and size differ.
- A leaf key may issue grants only with `delegate: false`, and may sign data.
  It may not issue names or revocations.
- Leaf keys never rotate; they expire and are reissued (daemons do this
  automatically).

Typical uses: an application's operational signing key (e.g. zuko locator
records via `sign`), or a service issuing high volumes of short-lived,
non-delegable grants.

Independently of leaf keys, verified statements are immutable values, so
verifiers cache "hash H verified" — after the first check, a chain costs a
lookup.

---

## 8. Signing data

```
signature = { signer: (id, event n) | leaf key, issued, context, H(data), signatures }
```

`context` is an application-chosen label (e.g. `zuko/locator/v1`) for domain
separation. Verification = signature valid **and** signer holds the required tag
via a chain from the verifier's roots. This gives applications (zuko records,
release signing, file signing) one primitive instead of a bespoke one each.

---

## 9. Verification

### 9.1 Inputs

- **Roots**: usually just _me_. Trusting another root for a scope is a grant I
  issue (e.g. grant `org-root` `(org)` with `delegate: true`), so there is no
  separate root configuration.
- **Material**: identity logs, signed statements, revocations — any pile; order
  irrelevant.
- **Now**: supplied by the caller (see §9.4).
- **Policy**: accepted suites per role (default: both v1 suites), leaf ceiling,
  clock skew tolerance, resource limits (max chain length 16, max name depth 8,
  max statements examined).

### 9.2 Queries

- `check(subject, tag)` → proof or denial with reason.
- `resolve(name path)` → subjects, each with proof.
- `verify(signature, data, context, tag)` → proof or denial.

A **proof** is the minimal set of log events and statements that justifies the
answer. It is a value: it can be logged, explained, or shipped to another
verifier (`writ prove`). Presenting only the proof — not your whole pile — is
also the privacy discipline (§11).

### 9.3 Validity of a chain

A chain from a root to the subject is valid at time _now_ iff:

1. Every issuer's log verifies, is not equivocating, and is at least as new as
   the persisted head for that id.
2. Every statement is either signed by k of the authority current at its event,
   under an accepted suite, or — if issued under an earlier event — listed in the
   latest rotation's `keep`.
3. No statement is revoked by a valid revocation in the material.
4. For every statement: `issued ≤ now + skew`; if `expires` is present,
   `now < expires`; issuer `max-validity` and leaf rules (§7) hold.
5. Every non-final grant has `delegate: true`.
6. Names in subjects resolve (the name statements used are part of the proof).
7. Effective tag = ∩ of all grant tags; must be non-empty and ⊇ the queried tag.
   Effective expiry = min of all expiries. One rule — intersection — for both;
   a child broader than its parent is clamped, not rejected.

Name resolution is a fixpoint over the material with a visited set; cycles
terminate, depth is bounded.

To bound adversarial input, the verifier finds candidate paths structurally first
and checks signatures only along them; signature results are cached by hash.

### 9.4 Time

The library never reads a clock. It provides a small `Floor` value for callers
that need clock-attack resistance (anything using expiries or leaf keys):

- The floor is the newest `issued` seen on a valid statement from the verifier's
  own roots, capped at local wall clock + skew.
- `now = max(wall clock, floor + monotonic time elapsed since the floor was set)`.
- Rolling the clock back can't go below the floor; freezing it can't stop
  monotonic time. Pushing the clock forward only expires things early (denial of service,
  never forgery).
- The caller persists the floor (the zuko daemon does; the CLI uses the wall clock
  unless given `--floor FILE`).
- A fresh verifier seeds its floor from the build-time floor shipped in the binary
  plus the newest statement from its own roots it has seen. There is no separate
  time-witness protocol: in practice a new device is enrolled by a fresh grant
  from its owner, and that grant's `issued` is the witness. Residual risk (a
  fresh, partitioned verifier with a hostile clock and no recent statement from
  its roots) is documented in §10.

---

## 10. Threats, blast radius, upgrades

| Scenario                                                       | Bound                                                                                                                                                                                                                                                                 |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Secret break of the leaf suite                                 | Forgery limited in scope to the tags of leaf grants (which can't be delegated, and which the identity's next rotation drops), for as long as leaf grants keep being issued; each one lasts at most the ceiling. Clock rollback or freezing is countered by the floor. |
| Public break of the leaf suite                                 | Zero once verifiers drop the suite (software default). Leaves reissue under the new suite; no identity changes.                                                                                                                                                       |
| Warm key stolen                                                | The thief signs as you until verifiers see your rotation. After that, only statements in `keep` survive. Verifiers that never see the rotation stay exposed; `max-validity` does not change that (§4.5).                                                              |
| Cold key lost                                                  | Recover via k-of-n next authority, if configured.                                                                                                                                                                                                                     |
| Cold key (or ≥ k of it) stolen                                 | Identity lost; conflicting rotations are detectable evidence.                                                                                                                                                                                                         |
| Fresh verifier, no persisted floor, hostile clock, partitioned | Expired leaf grants back to the floor (build-time, or newest own-root statement) are usable again. Accepted residual risk; enrollment grants keep it small in practice.                                                                                               |
| SLH-DSA structure broken, SHAKE intact                         | Root forgery; rotation races would be detectable as equivocation. Accepted as very unlikely.                                                                                                                                                                          |
| SHAKE broken                                                   | Total. Re-key the world. Accepted.                                                                                                                                                                                                                                    |

**Upgrade paths**

- Routine key rotation: rotate; `keep` is computed automatically; id unchanged.
- Root suite migration: rotate to an authority in the new suite. Kept statements
  stay valid by hash endorsement; the old suite's verify code can then be
  removed.
- Leaf suite migration: verifiers drop the old suite; leaf keys reissue.
- Format evolution: every encoded item carries a version; v1 means exactly this
  document. No negotiation.

---

## 11. Privacy

Statements are public assertions. Name statements in particular reveal social
structure ("who are alice's friends"). Applications should hand verifiers only the
minimal proof for the question being asked (`writ prove`), not their whole
statement set.

---

## 12. Encoding

- **Canonical S-expressions** (Rivest csexp) for everything signed or hashed:
  canonical by construction, ~100-line parser, trees map directly onto tags.
  Non-canonical input is rejected.
- A readable form for display (`writ show`).
- **ids**: bech32m with prefix, e.g. `writ1…` (32 bytes → ~60 chars, typo-checked).
- **Secret key files**: one 32-byte seed in bech32m (`WRIT-SECRET-KEY-1…`), one
  line, **plaintext**. Encryption at rest is out of scope and composes with age
  (§14). Leaf and root public keys are long; they live in files and bundles, not
  on the command line.
- **Bundles**: concatenations of items (log events, statements, signatures).
  Order irrelevant.
- **Armor**: a strict PEM subset, following age's rules. One block per item:
  `-----BEGIN WRIT-----`, standard padded base64 in 64-column lines, no headers,
  `-----END WRIT-----`; anything else is rejected. Because a bundle is just
  concatenated blocks, `cat a.writ b.writ > bundle.writ` composes. The library
  works on canonical bytes; armor is a small separate module.

---

## 13. Library API (sketch)

Pure: no IO, no clock, no ambient randomness (signing takes an RNG and a
`Signer`, so agents and hardware can be added later).

```rust
// material
struct Material;            // indexed pile of logs, statements, revocations
impl Material { fn add(&mut self, item: Item) -> Result<(), DecodeError>; }

// verification
struct Verifier<'a> { roots: &'a [Id], material: &'a Material, policy: &'a Policy }
impl Verifier<'_> {
    fn check(&self, subject: &Subject, tag: &Tag, now: Time) -> Result<Proof, Denial>;
    fn resolve(&self, name: &NamePath, now: Time) -> Result<Vec<(Subject, Proof)>, Denial>;
    fn verify(&self, sig: &Signature, data_hash: &Hash, ctx: &str, tag: &Tag, now: Time)
        -> Result<Proof, Denial>;
}

// issuing
trait Signer { fn sign(&self, msg: &[u8], rng: &mut dyn Rng) -> SigBytes; }
fn issue(stmt: Statement, signers: &[&dyn Signer], rng: &mut dyn Rng) -> Signed;
fn incept(authority: Authority, next: &Authority, ...) -> (Id, Event);
fn rotate(log: &Log, revealed: Authority, next: &Authority, keep: Vec<Hash>, ...) -> Event;

// helpers
struct Floor;               // §9.4
fn equivocation(a: &Event, b: &Event) -> Option<Evidence>;
fn tag_intersect(a: &Tag, b: &Tag) -> Option<Tag>;
```

---

## 14. CLI (sketch)

An identity is a directory of **public state**: the log and the issuance log.
Secret keys are separate one-line files; `--key` defaults to `DIR/current.key`.

```
writ init DIR --next-out PATH [--k K --n N]
                                     create identity; prints id. Current key → DIR/current.key;
                                     next (cold) key(s) → PATH, which must be chosen explicitly
writ id DIR                          print id
writ name   -i DIR NAME SUBJECT      [--expires DUR] [--note TEXT]
writ grant  -i DIR SUBJECT TAG       [--delegate] [--expires DUR] [--note TEXT]
writ revoke -i DIR HASH
writ leaf   -i DIR TAG --expires DUR create a leaf key + its grant
writ rotate -i DIR --next-key PATH... --next-out PATH
                                     reveal the cold key(s); keep list computed from issuance log
writ sign   -i DIR --context C FILE  > FILE.sig
writ verify --as ID --tag TAG --context C FILE FILE.sig  < bundle
writ check  --as ID SUBJECT TAG       < bundle
writ resolve --as ID NAMEPATH         < bundle
writ prove  --as ID SUBJECT TAG       < bundle > proof     minimal disclosure
writ show                             < bundle             readable form
```

**Secret keys at rest** are out of scope; writ is built to compose with age:

- Key paths accept `-` (stdin) and any readable path, including `/dev/fd/N`;
  writ never requires a regular file or memory-maps keys.
- Commands that emit secrets (`init --next-out -`, `leaf`, `rotate --next-out -`)
  can write them to stdout, so they never touch disk in plaintext.
- Plaintext key files writ creates get mode 0600; writ never overwrites a key.

```
writ init me --next-out - | age -p > me-next.key.age      # cold key: encrypted from birth
age -e -r age1pq1… me/current.key > me/current.key.age && rm me/current.key
writ grant -i me --key <(age -d me/current.key.age) 'me friends' '(zuko home)'
writ rotate -i me --next-key <(age -d me-next.key.age) --next-out - | age -p > me-next2.key.age
```

With age's hybrid post-quantum recipients, keys at rest match writ's PQ posture.

---

## 15. Crates

```
writ-sexp     canonical s-expressions + armor; no deps
writ-slhdsa   SLH-DSA-SHAKE-128s only, on libcrux-sha3
libwrit       model, suites, verification, issuing (libcrux-sha3, -ml-dsa, -ed25519)
writ-tool     the `writ` binary (+ getrandom)
```

The tool stays `writ`. On crates.io, `writ` (a markdown editor) and
`writ-core`/`writ-cli` (an unrelated project) are taken; the four names above
were free as of 2026-10-11. `writ-slhdsa` deliberately implements one parameter
set — a general SLH-DSA crate would invite all twelve.

Testing: ACVP + differential for SLH-DSA; round-trip and canonical-form fuzzing
for csexp; algebraic property tests for tags (commutative, associative,
idempotent, consistent with ⊆); chain semantics checked against a brute-force
reference implementation; published test vectors for every format.

---

## 16. Decisions log

- PQ from day one; stack suites by role: root SLH-DSA, leaf ML-DSA-65+Ed25519.
- Identity = log with pre-rotation; id stable across rotations and suite
  migrations.
- k-of-n authorities in v1.
- Indefinite validity allowed (default); time supported but optional. Leaf
  grants are always time-bounded.
- Revocation via issuer-signed `revoke`; rotation `keep` is an explicit list.
- Tags are flat paths; no wildcards, sets, or ranges. Intersection is the single
  narrowing rule for tags and time.
- `delegate` is a boolean, default false.
- Opaque app keys may be subjects; writ doesn't interpret them.
- No JSON or freeform claims; `note` is display-only.
- Secret keys are plaintext by default; encryption at rest composes with age and
  is out of scope.
- Leaf ceiling 24 hours.
- Ed25519: strict RFC 8032 verification, pinned by edge-case vectors.
- Fresh verifiers: build-time floor + own-root statements; no witness protocol.
- Armor: strict PEM subset (age rules), one block per item.
- Crates: `writ-sexp`, `writ-slhdsa`, `libwrit`, `writ-tool` (binary `writ`).
- Rejected: X.509; JSON claims; tag wildcards/sets/ranges; WOTS+ rotation keys;
  KERI witnesses; warm-key policy tightening; `keep: all`; not-before.

### Recorded during implementation (2026-10-11)

Gaps in the draft, resolved the obvious way; SPEC.md is normative.

- **Labels are terminated**: every hash or signature input is
  `writ/v1/<purpose> ‖ 0x00 ‖ data`. Signed messages are the full canonical
  body, not its hash, so SLH-DSA's randomized message hashing protects against
  collisions in SHA3-256 as well.
- **SLH-DSA uses the FIPS 205 context string too**
  (`writ/v1/root/slh-dsa-shake-128s`), symmetric with ML-DSA.
- **Authorities list distinct keys, sorted**; a threshold counts distinct keys,
  so `(2, [K, K])` can't make one key count twice.
- **Data signatures follow the statement rule across rotation**: valid if made
  under the head event, or if their hash is in the head's `keep`; otherwise a
  thief with an old warm key could sign data under the old event forever. The
  signer can revoke a data signature by hash. The CLI records identity
  signatures in the issuance log so `rotate` keeps them.
- **Revocations never expire** and are exempt from `max-validity` (an expiring
  revocation would quietly un-revoke). They are also subject to the keep rule,
  as §5.3 says, which is harmless: a revoked statement is never kept.
- **Rotations are fail-closed only when signed by the committed authority**:
  rotations with another authority or bad signatures are ignored (anyone can
  make them); two different ones signed by the committed authority are
  equivocation; one signed but with the wrong `prev` breaks the log.
- **Equivocation semantics for queries**: a query about an equivocating id
  fails; chains through it are invalid, and if no other chain exists the
  denial carries the evidence.
- **Name depth is defined as derivation depth** of a Jacobi fixpoint (SPEC §8),
  so the bound is a property of the answer, not of search order.
- **The ratchet persists logs, not just head numbers**: a verifier adds the
  logs it has accepted to future material, which subsumes "never accept an
  older head" and keeps equivocation visible once seen. The CLI persists the
  logs of identities a question involved (roots, chain issuers, subjects,
  failed candidates' issuers, equivocators), not every identity in its input,
  so a bundle can't grow the state without bound.
- **CLI**: `--state DIR` (floor plus remembered logs) replaces `--floor FILE`;
  added `export`, `keygen`, `pubkey`, `--in`, `--at`, `sign --leaf`; `leaf`
  defaults to 24 h; the next authority's public keys live in `DIR/next.writ`
  so `rotate` can rebuild it for k-of-n; `rotate` replaces a plaintext
  `DIR/current.key` with the revealed key and deletes the retired one.
- **Default skew** is 300 s; resource limits as in SPEC §11.

### Resolved after implementation review (2026-10-12)

Four findings where the draft's claims didn't hold; decided as follows.

- **`max-validity` does not bound a warm-key thief.** `issued` is chosen by the
  signer, so a thief who holds the key keeps issuing fresh statements, and
  `issued ≤ now + skew` makes it a not-before, so even brief access to a
  signer allows a ladder of post-dated statements. A real bound needs
  something the thief can't sign (periodic checkpoints by the cold keys, or a
  freshness channel), which conflicts with "no forced maintenance".
  **Decision:** keep `max-validity` for what it does (statements age out unless
  re-issued) and say so; no new mechanism. §4.5 and §10 are reworded.
- **Equivocation is not evidence of compromise when `2k ≤ n`**: two disjoint
  honest groups could each rotate. **Decision:** every authority requires
  `2k > n`, enforced by encoders and decoders (§4.1).
- **The leaf-suite blast radius is bounded in scope, not time**, while leaf
  grants keep being renewed. **Decision:** reword §10; no mechanism change.
- **Rotation made the recovery quorum the signing authority**: the revealed
  next authority became the current one, so cold and recovery keys turned warm,
  and k-of-n recovery sets had to sign every statement. **Decision:** a
  rotation names the revealed next authority (which signs it) and a new current
  authority separately; `next` may commit to the same authority again (§4.3).
  CLI: `rotate` makes a fresh current key (`--key-out`, or in place of a retired
  `DIR/current.key`), `--same-next` keeps the next keys, and `--key-pub` /
  `--key-k` make a shared current authority.

## 17. Open questions

None blocking. Revisit after use: exact resource limits (§9.1) and the default
skew. Whether applications need a freshness primitive that bounds a warm-key
thief toward cut-off verifiers (see above) is a question for zuko, not for v1.
