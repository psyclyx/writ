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

| Role                            | Suite                                      | Why                                                                                                                                                                                                                                           |
| ------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Root** (identity authorities) | `slh-dsa-shake-128s` (FIPS 205)            | Security rests only on hash functions — the most conservative assumption available — for the one thing we never want to replace. 32-byte public keys. Large (7856 B), slow-to-make signatures are fine at human signing rates and are cached. |
| **Leaf** (fast path)            | `mldsa65-ed25519` composite                | ML-DSA-65 (FIPS 204) and Ed25519 over the same domain-separated message; **both** must verify. Fast to sign and verify, ~3.4 KB. Less conservative than root, so always time-bounded and structurally limited (§7).                           |
| Hash                            | SHA3-256; SHAKE256 for derivation and data | Keccak only — same family SLH-DSA already uses. Data hashes use SHAKE256 because libcrux absorbs it incrementally, so any file hashes in constant memory.                                                                                     |

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
  `libcrux-ed25519`. Ed25519 is translated from verified HACL\*; ML-DSA's
  arithmetic, NTT and serialization are verified, its other checks are not;
  `libcrux-sha3` is not verified yet. All are pre-0.1 and not independently
  audited — pin exact versions, and pin them with external vectors (§16).
- Implemented here: SLH-DSA on top of `libcrux-sha3` (pure hashing, no field
  arithmetic), the composite construction, canonical encoding, bech32m.
- Homework for what we implement: written spec with test vectors; NIST ACVP
  vectors for SLH-DSA; differential tests against RustCrypto `slh-dsa`
  (dev-dependency only); fuzzing (`fuzz/`); property tests. For what we
  import: ACVP vectors for ML-DSA-65, differential tests of it against
  RustCrypto `ml-dsa`, and advisory checks (`cargo audit`).

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
expired − names and grants for leaf keys, keeping only items whose signatures
verify (the log is a file, not a witness). Rotation thereby also
garbage-collects.

The log is part of every proof that involves the identity, so its size
matters. Each rotation adds about 8 KB (its SLH-DSA signature) plus 32 bytes
per kept item, and the kept items repeat in every rotation. Yearly rotations
with 100 live items come to about 110 KB after a decade; monthly ones with 500
reach about 1.4 MB in five years. So rotate for compromise or
suite migration rather than as a routine, and sign at high volume (releases,
records) from a separate identity that this one grants to, so this one's
`keep` stays short.

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

- `issuer` is `(id, event n)` for identities, or a leaf key's id (a hash of
  the key; the key itself travels in the grant to the leaf).
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
the subject of a grant (or name) from an identity.

- A grant to a leaf key, or a name for one, **must** carry `expires`, with
  `expires − issued ≤ 24 hours` (the leaf ceiling: a protocol constant; verifiers
  may lower it). Names count because a grant to a name reaches whatever it
  names. Renewal is a root-suite signature per leaf per day — trivial for a
  daemon holding its device identity's warm key. Anything that needs a longer
  life should be a regular identity; only speed and size differ.
- A leaf key may issue grants only with `delegate: false`, and may sign data.
  It may not issue names or revocations.
- Leaf keys never rotate; they expire and are reissued (daemons do this
  automatically).
- What a leaf issues names it by id, a 32-byte hash, not by its 1984-byte key:
  verifying needs the grant to the leaf anyway, and the grant carries the key.
  A leaf data signature is then about 3.6 KB rather than 5.6 KB.

Typical uses: an application's operational signing key (e.g. zuko locator
records via `sign`), or a service issuing high volumes of short-lived,
non-delegable grants.

Independently of leaf keys, verified statements are immutable values, so
verifiers cache "hash H verified" — after the first check, a chain costs a
lookup.

---

## 8. Signing data

```
signature = { signer: (id, event n) | leaf id, issued, context, H(data), signatures }
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
  max statements examined, max signatures checked).

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
- **Secret key files**: one 32-byte seed in bech32m (`WRIT-SECRET-KEY-1…`) per
  line, **plaintext**, after a `#` line saying what the key is and whose (e.g.
  `# writ current key for writ1… (event 0)`). Encryption at rest is out of scope and composes with age
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
writ init DIR --next-out PATH [--next-k K --next-n N]
                                     create identity; prints id. Current key → DIR/current.key;
                                     next (cold) key(s) → PATH, which must be chosen explicitly
writ id DIR                          print id
writ name   -i DIR NAME SUBJECT      [--expires DUR] [--note TEXT]
writ grant  -i DIR SUBJECT TAG       [--delegate] [--expires DUR] [--note TEXT]
writ revoke -i DIR HASH
writ leaf   -i DIR TAG --expires DUR create a leaf key + its grant
writ rotate -i DIR --next-key PATH... --next-out PATH [--key-out PATH]
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
  can write them to stdout or `/dev/fd/N` (opened for appending), so they never
  touch disk in plaintext.
- Plaintext key files writ creates get mode 0600; writ never overwrites a key,
  or any other file it writes.

```
writ init me --next-out - | age -p > me-next.key.age      # cold key: encrypted from birth
age -e -r age1pq1… me/current.key > me/current.key.age && rm me/current.key
writ grant -i me --key <(age -d me/current.key.age) 'me friends' '(zuko home)'
writ rotate -i me --next-key <(age -d me-next.key.age) --next-out - \
    --key-out >(age -e -r age1pq1… > me/current2.key.age) | age -p > me-next2.key.age
```

Once `me/current.key` is gone, `rotate` needs `--key-out` for the new current
key; here it goes to age through a second descriptor.

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

Testing: ACVP + differential for SLH-DSA; ACVP for ML-DSA-65; round-trip and
canonical-form fuzzing for csexp; algebraic property tests for tags (commutative, associative,
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

### Resolved after format audit (2026-10-13)

- **A name could carry a leaf key past the leaf ceiling.** The ceiling applied
  only to grants whose subject is a leaf key, so naming a leaf and granting to
  the name gave it an unexpiring grant that also survived rotation, defeating
  §7 and the leaf rows of §10. **Decision:** the ceiling applies to every
  statement whose subject is a leaf key, names included (SPEC §5.4 rule 4,
  §7 rule 6), and `rotate` drops them all. Naming leaves stays possible for a
  day at a time.
- **`rotate` must not trust `issued.writ`.** A kept hash is endorsed without
  its signatures being checked again, but the CLI kept data signatures from
  `issued.writ` without verifying them, so anyone who could write that file
  got arbitrary signatures endorsed by the next keys. **Decision:** `keep`
  takes only items by the identity that verify under SPEC §7. A thief holding
  the current key can still add validly signed statements to the file; the
  rotate help says to read it first after a theft.
- **Leaf-issued items name the leaf by id.** They carried the whole 1984-byte
  key, which the grant to the leaf already carries and a verifier needs anyway.
  **Decision:** the issuer is `(leaf <id>)`, with id
  `H("writ/v1/leaf-id", canonical(key))`; verifiers take the key from a
  statement about the leaf or a key item. The id replaces the old display
  fingerprint label, so fingerprints are now the start of the id. A leaf
  signature shrinks by about 2 KB. ML-DSA-65 stays: the other way to save
  space (ML-DSA-44) saves less and gives up margin.
- **Data hashes use SHAKE256.** The pinned libcrux exposes incremental SHAKE
  but not incremental SHA3-256, so `sign` and `verify` had to read whole files
  into memory. **Decision:** `D(data) = SHAKE256("writ/v1/data" ‖ 0x00 ‖ data,
32)`; same security as SHA3-256 and still Keccak only. Everything else stays
  SHA3-256.
- **Key files say what they hold**: a `# writ current key for writ1… (event 0)`
  line (or next, leaf, or a bare keygen key). Readers already skip `#` lines.
- **Log growth is documented, not redesigned.** Moving `keep` out of rotations
  would shrink the repeated lists but not the ~8 KB signature per rotation, at
  the cost of a new item kind. §4.3 gives the numbers and the advice instead.

### Resolved after second review (2026-10-16)

- **ML-DSA-65 is pinned by NIST ACVP vectors** (keyGen, sigGen, sigVer),
  run against the libcrux-ml-dsa calls the leaf suite makes: key generation
  from ξ, and external pure signing and verification with a context,
  deterministic and hedged. The repository had none, though §3.3 and the
  test-vector rule ask for them. A subset is vendored (27 cases, about 450
  KB); internal, external-mu and pre-hash groups are left out because writ
  doesn't use them. All pass, with and without libcrux's AVX2 code
  (`vectors/acvp/README.md`).
- **libcrux stays; no libsodium.** libcrux-ml-dsa had several advisories in
  2026, two of them high-severity bugs in its AVX2 code, which its build
  script enables on every x86_64 build. All are fixed at or below the pinned
  versions. libsodium has no ML-DSA, so libcrux would stay anyway; its
  Ed25519 is as strict as ours already is, and it would bring C, FFI and
  `unsafe`. **Decision:** keep the pins; guard them with the ACVP vectors
  (run with `LIBCRUX_DISABLE_SIMD256=1` too, from a clean build directory)
  and advisory checks on every bump.
- **Correction:** libcrux-sha3 0.0.11 does have incremental SHA3-256
  (`Sha3_256Hasher`), contrary to the 2026-10-13 entry. The SHAKE256 data
  hash stays: it is as strong, already specified, and pinned by vectors.
- **Verifier work is bounded by the policy, not by the material.** Three
  shapes of hostile material cost far more than `max_statements`: names
  that refer to each other repeatedly (derivations grew 16× per level;
  nine statements aborted the process), many incomparable tags through one
  holder (search nodes grew as tags × holders), and junk signatures or
  revocations (each verified, without limit). **Decision:** derivations are
  shared, not copied; the search drops nodes whose tag can no longer cover
  the query, since tags only lengthen; a new `max_signatures` limit counts
  signature checks, revocations count as statements, and a statement
  undecided when the limits run out is invalid, never "not revoked" (SPEC
  §11). Logs still cost one check per rotation candidate: work is linear in
  the material, which applications bound by size.
- **Leaf signatures verify only while the leaf's grant is live.** `verify`
  asks whether the signer holds the tag now; a leaf grant lasts at most a
  day. Checking "held it when signing" instead would need a time the signer
  can't choose, which writ doesn't have. **Decision:** no mechanism change.
  Leaf keys sign short-lived things (records re-signed as needed); releases
  and files are signed by an identity, whose data signatures last until
  revoked or dropped by a rotation. README and help say so.
- **Verifier state remembers revocations, and only what a question relied
  on.** Logs were persisted but revocations weren't, so a revocation seen
  once was forgotten when a later bundle left it out; and `writ prove`
  output is chosen by the prover, who can leave it out. Denials also saved
  the logs of the subject asked about, so the 2026-10-11 claim that a bundle
  can't grow the state didn't hold. **Decision:** state keeps each
  remembered identity's valid revocations with its log; denials save only
  issuers the search reached and equivocators; SPEC §10 says a proof is
  checked together with the verifier's state, never alone.
- **writ never signs what it can't read back.** A grant to an SSH key with
  a non-token type, or a rotation whose `keep` exceeded 4 MiB, was signed,
  then rejected by every reader, the tool included, which locked the
  identity's own directory. **Decision:** issuing checks the body against
  the decoder and the per-item limits before signing.
- **Wiping is best effort.** Secrets are wiped where they are held, but
  values Rust moves or spills to registers can't be reached without
  `unsafe`; `writ-slhdsa` scrubs its stack after signing as a backstop.
  Encrypt keys at rest (age) rather than rely on memory hygiene.
- **One rule for output paths.** `-`, `/dev/stdout` and `/dev/fd/1` are the
  inherited stdout; other `/dev/fd/N` are opened again for appending (writ
  can't duplicate a descriptor without `unsafe`, so a shared offset is not
  kept); any other path must not exist and is created with `O_EXCL`, which
  also refuses symlinks. Outputs are opened before anything is signed or
  recorded, and a created output that was never written is removed.
- **Keys never go inside an identity directory**, except the current key to
  `DIR/current.key`: a key there could replace, or be replaced by, the
  identity's own files. `init` locks DIR while it works.
- **`issued.writ` is updated under its own exclusive lock**; issuers still
  share `DIR/.lock`, which `rotate` takes exclusively.
- **A single-value option given twice is a usage error.**
- **Imported crypto is checked three ways** (approved 2026-10-18): ACVP
  vectors, differential tests of libcrux-ml-dsa against RustCrypto `ml-dsa`
  (dev-dependency only, as `slh-dsa` is for the root suite), and
  `cargo audit` in the pre-commit hook, offline against the local advisory
  database. The one accepted advisory (an unmaintained build-time
  proc-macro under libcrux) is in `.cargo/audit.toml` with its reason.
- **Decoders are fuzzed** with cargo-fuzz targets in `fuzz/`, outside the
  workspace, each checking a round-trip property. They run on stable Rust
  with the sanitizer off: the code has no `unsafe`, so AddressSanitizer
  would add little, and it needs nightly.

## 17. Open questions

None blocking. Revisit after use: exact resource limits (§9.1) and the default
skew. Whether applications need a freshness primitive that bounds a warm-key
thief toward cut-off verifiers (see above) is a question for zuko, not for v1.

## 18. Proposed: multi-tag grants, channel binding, a revocation server

**Status: proposal, not decided.** Nothing here is built. It widens the scope
set in §1 and in CLAUDE.md ("networking or transport" is out of scope), so it
needs the owner's sign-off; once settled, the decisions move to §16 and the
byte-level rules to SPEC.md. Numbers marked _(tune)_ are starting points.

### 18.1 Scope

- libwrit stays pure: no IO, no clock, no ambient randomness. The new pieces
  in it (§18.2–§18.5) are functions on values.
- Networking appears in two places only: a new crate, `writ-keyserver`, and
  two `writ` commands, `publish` and `fetch` (§18.6). Both speak plain
  HTTP/1.1; items carry their own signatures, so TLS adds privacy, not
  integrity (§18.5).
- Still out of scope: encryption (use age), key exchange and transport
  protocols, policy languages.

### 18.2 Grants with several tags

A grant may list up to 16 tags. It means exactly what the same number of
grants would, one per tag, with the same subject, `delegate`, expiry and
issuer; it has one hash, so one revocation or one `keep` entry covers all of
its tags.

```
grant = "(" "grant" common subject 1*16tag [ "(" "delegate" ")" ] ")"
```

- Tags are distinct and in strictly increasing order of their canonical
  encoding. A grant with one tag is encoded exactly as today, so existing
  grants and vectors keep their bytes.
- Issuing refuses a tag that another tag of the same grant already covers
  (`(ssh)` with `(ssh nas)`): it would mean nothing.
- Verification treats each tag as a separate grant sharing the signature; the
  chain search, intersection and the proof are unchanged, and a proof's step
  records which tag it used.
- Why: an identity-signed grant carries a 7856-byte signature, so five paths
  as five grants cost about 39 KB; as one grant, about 8 KB.

No conjunction ("holds X only if also Y"): proofs would become trees instead
of chains, and it is the policy language §1 rules out. An application that
needs "and" asks two questions and combines the answers. "Or" over subjects
already exists: a name may bind several subjects.

### 18.3 Channel binding

writ does not do key exchange. Applications use TLS 1.3, DTLS, QUIC or Noise,
and writ says whether the key at the other end may do what it asks. The step
applications get wrong is binding the two: checking the key the handshake
authenticated, not one the peer merely claims. libwrit provides that step and
nothing more.

- After the handshake, each side takes the channel's exporter value `E`, a
  secret unique to the session, at least 32 bytes (TLS: the exporter of RFC
  8446 §7.5 with label `EXPORTER-writ-channel`; Noise: the handshake hash).
- Each side makes a data signature (§8) with its leaf key: context
  `writ/v1/channel/<app>`, data `D(role ‖ E)`, where `role` is the byte 1
  for the side that started the handshake and 2 for the other, so a
  signature cannot be reflected back to its signer.
- The peer checks it with `Verifier::verify` and the tag it requires. `E`
  never repeats, so a signature cannot be replayed on another channel.
- Contexts starting with `writ/` are reserved for writ: `writ sign` and
  `sign_data` refuse them for application data, so a file signature can
  never pass as a channel binding or a keyserver answer.
- API: `channel::bind(E, role, app, signer, now, rng)` and
  `channel::check(sig, E, role, app, tag, verifier, now)`. About twenty lines
  on top of `sign_data` and `verify`.

### 18.4 Records

The keyserver, `--state` (§16) and an application gossiping items (zuko) all
keep the same thing per identity, so libwrit gets one pure type for it.

A **record** for id `X` holds:

- X's log (§6). If two different valid events share a position, the record
  holds the evidence instead (the prefix and both events) and accepts nothing
  more: X is compromised.
- X's revocations that are valid under the log's head (§7): signed by the
  head's authority, or kept by it.

Nothing else: no names, grants or data signatures. A record says only "these
keys" and "these statement hashes are dead", so it reveals nothing about
what X said or to whom.

`Record::accept(item, now) -> Accepted | Rejected(reason)`:

- an inception whose id is `X` starts the record;
- a rotation extends the log under §6, or yields evidence;
- a revocation by `X`, valid under the head and not already present, is
  added;
- everything else is rejected.

After a rotation, revocations issued under earlier events and not kept are
dropped. They no longer mean anything: §7 ignores them, and a statement they
revoked is not kept either (the tool never keeps revoked statements). So a
record shrinks at every rotation, and a thief's revocations made with a
stolen current key vanish with it.

### 18.5 Keyserver

A keyserver stores records and serves them. It is trusted for availability
and freshness only: every item is checked again by whoever reads it.

**Protocol** (HTTP/1.1; bodies are bundles, §12):

- `GET /v1/challenge`: the current proof-of-work challenge and prices.
- `POST /v1/items`: a bundle of items for one id, with header
  `Writ-Stamp: <challenge> <nonce>`. The reply is a **receipt**: a signed
  answer (below) listing the hashes accepted, so the uploader can later show
  that the server had them.
- `GET /v1/id/<writ1…>?nonce=<hex>`: the record, the server's log and the
  grant to its answer key, and a signed **answer**.

**Answers.** The server's identity grants a leaf key `(keyserver answer)`
for a day at a time; the leaf signs each answer as a data signature with
context `writ/v1/keyserver/answer` over `D(id ‖ nonce ‖ H(record))`, with
`issued` the server's time. A client that trusts the server (it pins the
server's id, or grants it `(keyserver answer)`) checks that the answer
verifies, that its nonce is the one sent and that `issued` is recent. Then:

- the record is what the server holds now, not a copy replayed by someone on
  the network path, which TLS would otherwise be needed for;
- a server that leaves out an item it gave a receipt for has signed evidence
  against itself.

What remains is privacy: on-path observers see which ids are fetched.
Operators who care put TLS in front with a proxy; nothing in writ changes.
A client may leave out the nonce to get a cached answer (at most a minute
old _(tune)_), which a CDN can serve.

**What spam can and cannot do.** Every item in X's record must be signed by
X's keys, so nobody else can add to it, crowd it out, or block X's own
upload. Two doors stay open, and the rest of this section is about pricing
them:

1. registering new ids: an inception costs its maker about 0.6 s of CPU and
   the server about 8 KB;
2. a thief with X's current key filling X's record with revocations: bounded
   by the per-id quota, and undone by X's rotation (§18.4).

**Order of checks** (cheapest first, so junk costs us the least): request
size (64 KiB _(tune)_) → bounded decode → stamp → structural checks (one id;
id known or an inception; a rotation's revealed authority matches the
commitment; a revocation names the head event or a kept hash) → signatures
(about 0.5 ms each) → `Record::accept` → store.

**Stamps.**
`stamp = SHAKE256(msg("writ/v1/keyserver/stamp", challenge ‖ H(body) ‖ nonce), 32)`
must start with at least `b` zero bits. Checking one costs one hash; making
one costs about `2^b` hashes, about 0.3 µs each on one core, so 20 bits take
about 0.3 s, 24 bits about 5 s, 28 bits about 80 s. The challenge is 32
random bytes, replaced every 5 minutes _(tune)_ (the previous one is still
accepted), so stamps cannot be computed in advance. `H(body)` ties a stamp to
one upload.

**Price.** `b = base + size + new + busy + load`, where:

| term   | value                                                                                                                                                              |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `base` | 16 _(tune)_                                                                                                                                                        |
| `size` | ⌈log2(KiB stored)⌉: work grows with bytes                                                                                                                          |
| `new`  | 4 for an inception of an unknown id: registration costs 16 times an update                                                                                         |
| `busy` | 1 for each update to this id in the last 7 days beyond the first 4 _(tune)_: frequent changes double in price                                                      |
| `load` | 0 to 40, recomputed each minute: +1 while accepted bytes over the last hour exceed the disk budget's hourly share, or the write queue is long; −1 while below half |

**Protected updates.** An id first seen at least 30 days ago with no update
in the last 7 days _(tune)_ pays `new = busy = 0` and `load` capped at 4: at
most about 23 bits, a few seconds on a laptop, however busy the server is.
This is the "my key was stolen, revoke now" case, and it is why an honest
user is never priced out. To abuse it an attacker must register ids 30 days
ahead at full price, and then gets one cheap update per id per week, within
the per-id quota.

**Limits.**

- Disk: a budget per day set by the operator, which drives `load`; a hard
  cap, above 90% of which registration closes and only updates to known ids
  are accepted; per id, at most 512 revocations _(tune)_ under the head.
- CPU: at most 4 connections per address _(tune)_, read timeouts, and a
  write queue ordered with protected updates first, then by work paid per
  byte. Reads are static files per id.
- Connection floods are for a reverse proxy; the server does not try to
  survive them alone.

**Limit of this design.** A stamp is a Keccak hash, which GPUs compute much
faster than CPUs. If that becomes the problem, a memory-hard stamp (Balloon
hashing over SHAKE256, implemented here, no new dependency) narrows the gap.

### 18.6 Client

- `writ publish -i DIR --server URL`: uploads DIR's log and the revocations
  valid under its head, paying the stamp; keeps the receipt in
  `DIR/receipts.writ`.
- `writ fetch --server URL --server-id ID ID...`: fetches records, checks the
  answers, and prints the items (or adds them to `--state`).
- A small hand-written HTTP/1.1 client on `std::net`: `http://` only, bounded
  reads, no new dependency.
- `writ init` and `writ rotate` remind the user to publish: an id published
  early becomes established (§18.5) before it is ever needed.

### 18.7 Crates and order of work

```
libwrit          + record (§18.4), stamp (§18.5), channel (§18.3); multi-tag grants (§18.2)
writ-keyserver   new: the server binary (HTTP, files on disk)
writ-tool        + publish, fetch; --state uses Record
```

1. Multi-tag grants: format, SPEC, vectors, CLI (`writ grant` takes several
   TAGs).
2. `Record`, and `--state` rebuilt on it.
3. Stamps and pricing (pure: the server passes in its counters).
4. `writ-keyserver`.
5. `writ publish` and `writ fetch`.
6. Channel binding.

### 18.8 Questions for the owner

- The HTTP server: hand-written on `std::net` (no dependency, but untrusted
  connections meet our own parser) or a small vetted crate. Either way it
  runs behind a reverse proxy in production.
- The _(tune)_ numbers.
- Whether `writ fetch` should also accept a record from standard input
  (`curl … | writ fetch --check`), for people who want TLS through curl.
