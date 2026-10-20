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
  maintenance (publishing revocation records, §18, is opt-in).
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
- No transport: how statements and revocations travel is the application's
  job. Freshness is opt-in per identity (§18). The library is pure; the one
  network operation, `--fetch`, is at the edge, in the CLI.
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
- SLH-DSA signing uses the hedged variant (fresh randomness) and verifies its
  own signature before releasing it. The check catches faults and bugs that
  make the signature invalid. It does not catch a fault in a tree node off
  the signed leaf's path: that yields a signature that is wrong but
  self-consistent, which verifies (the grafting attack of Castelnovi,
  Martinelli and Prest). Hedging is what bounds that case, by making a second
  signature on the same hypertree path unlikely (§16, 2026-10-19).
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
- No wildcards, sets, or ranges. Unions are several tags in one grant, or several grants (§18.2). Order elements
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
  It may not issue names or revocations. Every statement it issues carries
  `expires` within the same ceiling: what a stolen or forged leaf key says
  dies with the day, rather than lasting as long as the same key keeps
  being renewed with nothing able to revoke it (leaves cannot revoke, and
  an identity revokes only its own statements).
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
- Revocations, and what records list as revoked, count whatever the clock
  says: a revocation "from the future" can only deny, so a clock set back
  (above the floor, which only own-root statements raise) cannot bring back
  what any issuer revoked (§16, 2026-10-19).
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
| Leaf key stolen                                                | Forgery limited to the leaf's tags, non-delegable, each statement at most the ceiling. It ends when the owner stops renewing the grant to that key: at most a day after the theft is noticed, with no revocation needed.                                              |
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

### Decided 2026-10-18: revocation records, multi-tag grants, channel binding

Details in §18. In short:

- **Grants may list up to 16 tags**, meaning exactly what that many grants
  would; one hash, one signature. No conjunction: an application that needs
  "and" asks two questions.
- **No key exchange.** writ binds a channel made by TLS, DTLS, QUIC or Noise
  to a key it vouches for: each side signs the channel's exporter value with
  its leaf key. Contexts starting with `writ/` are reserved for writ.
- **Revocation is published, not served.** An identity may opt in, in its
  log, with `(publish (max-age D) url…)`: it signs a **record** (its head and
  everything it has revoked) at least every D, and puts it wherever it likes.
  Verifiers then need a fresh record from every issuer of a long-lived
  statement on a chain, except their own root when they bring its issuance
  log. A missing record fails closed after D; D is the owner's choice
  (minimum 1 hour, default 7 days).
- **No shared keyserver.** It would need spam pricing (an earlier draft used a
  load-priced proof of work); if one is built later, it serves the same files
  using a small vetted HTTP crate.
- **Networking at the edge only:** `--fetch` in writ-tool links libcurl,
  limited to http and https and to issuers on a candidate chain. libwrit stays
  pure. It does not depend on TLS certificates: on a certificate
  error it retries unverified, with a warning, since records are checked by
  their signatures.
- **Records under one head are combined:** freshness from the newest, revoked
  if any lists it, so a later record cannot un-revoke.
- **Losing a host or domain is an outage, never a forgery.** Recovery: other
  URLs, records handed over directly, restoring the host within D, or a
  rotation to new URLs (the next key, deliberately). `init` and `rotate` warn
  when every URL is on one host.
- **Names:** `record` for the item (it reads naturally: sign, staple, a fresh
  record), `publish` for the field, `max-age` for D (what it means to a
  verifier, and HTTP's word for it).

### Numbers set 2026-10-19

- **`--fetch`**: at most 5 redirects (http to https, then a CDN) and 16 MiB
  (ten times the 1.4 MB worst case of §4.3); connections get 10 s, a transfer
  under 1 KiB/s for 15 s stops, and none takes over 60 s, so a slow link can
  still fetch a large file while a stalled server fails fast.
- **Stale-record warning**: in the last fifth of max-age (1.4 days for the
  7-day default). Earlier would nag owners who renew every 6 days, which D
  allows.
- **`max_signatures`**: 2000, down from 10000. A real chain needs dozens of
  checks; 2000 cold SLH-DSA verifications take about 1.1 s, against about
  5.6 s before.
- **Unchanged**: skew 300 s (the usual tolerance, as in Kerberos),
  `max_chain` 16, `max_name_depth` 8, `max_statements` 10000, max-age at
  least 1 h and 7 days by default, at most 16 tags per grant and 4 URLs.

### Resolved after the pre-release review (2026-10-19)

- **The clock-floor witness is not bounded by `max_signatures`.** It shared
  a query's budget, scanning the root's statements in input order, so a
  bundle holding 2000 junk statements that named the root as issuer used it
  up before the real newest statement was checked, and the floor stayed
  put: the one limit that ran out in the permissive direction. Now it costs
  at most one check per root statement in the material, newest first (SPEC
  §12), like building a log.
- **Descriptor paths are exact.** `/dev/fd/N` and `/proc/self/fd/N` were
  recognised by prefix, so `/dev/fd/../../../path` was opened for appending
  without `O_EXCL`, mode 0600, or the "not inside DIR" check, and could put
  a plaintext key into an existing file, the identity's own log included.
  Only `/dev/fd/N` with N in plain digits is a descriptor; `/dev/stdin`,
  `/dev/fd/0` and `/proc/self/fd/0` count as standard input, so they can't
  be read twice either.
- **The empty tag is spelled `()`.** An empty string parsed as the tag that
  covers everything, so `writ grant … "$TAG"` with an unset variable granted
  everything. An empty string is not a tag.
- **In the readable form, every atom needs a delimiter**, quoted and hex
  atoms included, so `("ssh""nas")` is an error rather than two words; and
  characters that look like a space (no-break space and the other Unicode
  spaces) print as hex. What this guarantees is that a bare token is pure
  ASCII and anything else is quoted or hexed, so an ASCII name can never be
  impersonated by a non-ASCII atom; inside quoted atoms, lookalikes remain
  possible (§16, 2026-10-19).
- **`sign_pieces` in writ-slhdsa is `#[inline(never)]`**: the stack scrub
  wipes the frames below `sign`'s, so the WOTS+ and FORS secrets must stay
  in a frame of their own, whatever the inliner decides.
- Key derivation destructures fixed-size arrays, with no zero fallback; the
  `--fetch` budget truncates a batch instead of dropping it; `--fetch`
  documents that libcurl honours the proxy environment variables.

### Resolved after the security review (2026-10-19)

Five audits (one per crate, plus the verification core) and a read of the
whole. Three documented claims did not hold and are corrected above; the
rest are fixes in the glue around the cryptography, which was found sound.

- **A record endorsed other identities' revocations.** `records::sign` took
  every valid revocation in `issued.writ` without checking its issuer, so
  anyone who could write that file (DESIGN's own threat for it) could plant
  their log and a revocation of the owner's grant, and the owner's next
  `revoke`, `export --record` or `rotate` published a record revoking it, with
  no key of the owner involved and no way back until a rotation. **Decision:**
  a record lists only the identity's own revocations, and `issued.writ` is
  read as what the identity issued: anything else in it is ignored
  everywhere (keep, records, export, revocation lookup) and reported.
- **The clock-floor witness was still starved by `max_signatures`**, through
  junk signatures merged onto one copy of the root's newest statement rather
  than onto separate bodies. **Decision:** the witness is not budgeted at
  all; it verifies merged signatures until it finds `k` valid ones (one
  SLH-DSA check per junk signature, linear in the material, SPEC §12).
- **A clock set back un-revoked.** Rule 4 (`issued ≤ now + skew`) applied to
  revocations and to the revoking effect of records, and the floor rises only
  on own-root statements, so a verifier set back past a revocation accepted
  the revoked chain again; §9.4 listed only expired leaf grants as the
  rollback residual. **Decision:** revocations, and what a record lists, count
  whatever the clock says; a record's time matters only for freshness, which
  needs `now − D ≤ issued ≤ now + skew`. A consequence: `--at` in the past
  shows later revocations as in force, which is the safe reading.
- **Verify-after-sign does not stop the fault it was documented against.**
  A fault in an SLH-DSA tree node off the signed leaf's path leaves the auth
  path self-consistent, so the signature verifies and is released (confirmed
  by flipping a bit in a scratch copy); Genêt (TCHES 2023) shows the check
  is insufficient for exactly this. **Decision:** reword §3.2 rather than add
  redundant tree computation. Hedging bounds the attack, and a host where an
  attacker can induce faults in the signer can read the plaintext key file,
  so doubling signing cost buys little. The check stays for what it does
  catch.
- **Adding rotations was quadratic**: the one index in `Material` not keyed
  by hash re-hashed every candidate at `(id, n)` per insert. Now keyed by
  body hash; and records are indexed by `(issuer, revoked hash)` so the
  revocation check no longer scans every record per statement.
- **`--fetch` takes only the identity's log and records** from what a URL
  returns, so a host, or an active attacker on the path, puts nothing else
  into the material. The retry without certificate verification stays: any
  active attacker can force it by presenting a bad certificate, so https in a
  publish URL gives privacy against passive observers only, and records are
  public. URLs with a user name are refused at `init` and at fetch time.
  Loopback and private hosts stay allowed (local setups); an identity a root
  delegates to can thus make verifiers GET an internal URL, which is noted
  rather than prevented, since DNS makes a host check unreliable anyway.
- **`revoke TARGET`**: a file in the working directory named like a hash
  prefix no longer silently wins; if the argument is both, the file's item
  must have that prefix, else the error says to write `./TARGET`.
- **`rotate`** reports key files it wrote before a later step failed as
  void, and says the old next key still rotates; the staged current key is
  removed. Key counts are capped at 16 before anything is generated; writ's
  own files are read with the bundle bound; armor blocks are bounded before
  base64 decoding; writing to a closed stderr no longer panics after the
  work is done; `init` refuses a non-empty directory before creating `.lock`
  in it.
- **`sign_with_authority` is the documented raw entry point**: it applies
  the encoding rules and, for data signatures, the reserved-context rule
  (an identity never signs under `writ/`), and every signing path decodes
  the whole signed item before returning it. The typed functions apply the
  issuing rules.
- **Not changed, now documented in SPEC**: a subject whose own log is missing
  or broken still holds what valid chains grant it (only an equivocating
  subject is refused); log building costs one check per signature attached to
  a candidate, not per candidate; a kept statement keeps the `max-validity`
  of its issuing event; a presenter can staple a thief-signed record and so
  suppress the `--fetch` that would have found the owner's, which is the
  warm-key theft of §10 until rotation.

### Resolved after the second security review (2026-10-20)

Four audits (cryptography, encoding, the verification core, the CLI) and a
read of the whole. The cryptography and the verification core were found
sound: no hostile material produces a wrong answer, and no warm-key thief
outlasts the rotation. One design gap, one CLI defect, and small items.

- **A leaf key's own statements had no lifetime bound.** The ceiling applied
  to statements _about_ a leaf, not to statements _by_ one, so a grant
  issued by a stolen leaf key stayed valid for as long as the daemon kept
  renewing the grant to that same key, and nothing could revoke it: leaves
  cannot revoke, and an identity revokes only its own statements. §10 had no
  row for a stolen leaf key. **Decision:** every statement a leaf issues
  carries `expires` within the ceiling (SPEC §5.4 rule 4, §7 rule 6), so
  everything a leaf touches lasts at most a day; §7 and §10 say so. The
  chain vectors gain a leaf-issued grant without expiry, rejected.
- **`writ leaf --out` could put a key inside the identity directory.** It
  made the overwrite check but not the "no keys inside DIR" check that
  `init` and `rotate` make. A key at `DIR/current.key.new` was silently
  deleted by the next command, which took it for a stale rotation; one at
  `DIR/record.writ` broke `--as DIR` and was later replaced by the record
  writer. **Decision:** `leaf --out`, `leaf --grant-out` and `sign --out`
  refuse paths inside the identity directory.
- **Two spellings of one descriptor passed the distinct-output check**, so
  `--next-out /dev/fd/3 --key-out /proc/self/fd/3` wrote the cold and warm
  keys into one pipe. Outputs now compare by descriptor number as well.
- **Statements and records were memoized in one map.** Their labels differ,
  so their hashes cannot collide, but a lookup of the wrong kind would have
  cached "unknown" against the other, the permissive direction for a
  record. Unreachable through the indexes; now two maps, both counted
  against `max_statements`.
- **The speccheck vectors do not pin `y ≥ p` rejection**, contrary to SPEC
  §4.2: their non-canonical points encode `p − 1` with the sign bit set,
  which is also of small order. libcrux rejects `p` and `p + 1` encodings
  for A and R; libwrit's tests now pin that, and the SPEC says what the
  vectors cover.
- **A root's name could label another identity with an id lookalike**
  (`WRIT1…`, `leaf:…`), which explanations then printed in place of the id.
  Display only, and only a root could do it; labels now refuse both,
  case-insensitively.
- **`resolve` listed an equivocating identity as a member**, since
  denotation never consults the member's log. Chains through it already
  failed. **Decision:** members exclude it, and the evidence is the answer
  when nothing else remains (SPEC §10).
- **A record under an older event** is rejected with a reason of its own
  (`OutdatedRecord`) rather than one that said the log ended before it.
- **`rotate` refuses a symbolic link at `DIR/current.key`** when it would
  replace it: the rename would have replaced the link and left the retired
  key at its target, while the output said the old key no longer signed.
- **Every stderr write** goes through one function that ignores a closed
  descriptor; five `eprint!` calls remained after the last fix.
- **Not changed.** The signature budget is charged by the number of
  attached signatures before any is verified, so one junk-laden copy of a
  real grant can deny it: fail-closed, and the accepted bound (§16,
  2026-10-16). `--fetch` restricts protocols by checking each URL and
  redirect itself; the `curl` crate exposes no `CURLOPT_PROTOCOLS` without
  `unsafe`, and the check held against every redirect tried. After a crash
  left a staged key, two concurrent issuers both try to finish the install
  and one fails with a spurious error; availability only. State growth is
  bounded per query, not across queries, as §16 (2026-10-16) accepts.

## 17. Open questions

None blocking. The resource limits and the default skew were set on 2026-10-19
(§16); revisit them if real use runs into them. Whether applications need a freshness primitive that bounds a warm-key
thief toward cut-off verifiers (see above) is a question for zuko, not for v1.

The brute-force reference verifier shares `Log::build`, well-formedness and
threshold counting with the real one, and its generator makes only 1-of-1
authorities, at most one rotation per identity, no data signatures and no key
items; those paths rest on unit tests. Widening the generator is worthwhile
work that the 2026-10-19 review left open.

## 18. Multi-tag grants, channel binding, published revocations

**Status: decided 2026-10-18 (§16); built 2026-10-19.** The byte-level rules
are in SPEC.md (§5.3, §5.4, §5.6, §7, §10, §11, §14). Its numbers were set on
2026-10-19 (§16).

### 18.1 Scope

- libwrit stays pure: no IO, no clock, no ambient randomness. Everything new
  in it is a function on values.
- An identity may publish a signed record of its revocations wherever it
  likes, and verifiers can then require a recent one (§18.4–§18.6). The only
  networking is `--fetch` in the CLI, through libcurl (§18.7); anything else
  that delivers the file works as well.
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
- No tag of a grant may cover another (`(ssh)` with `(ssh nas)`): it would
  mean nothing. Decoders reject it, so a set of tags has one encoding and one
  meaning, and issuing refuses it.
- Verification treats each tag as a separate grant sharing the signature; the
  chain search, intersection and the proof are unchanged, and a proof's step
  records the tag it used. For any query, at most one tag of a grant can
  serve, so the search picks it and goes on as before.
- Built 2026-10-19: `Tags` in libwrit; `writ grant` and `writ leaf` take
  several TAGs; vectors in `chains/` and `items/rejections.txt`.
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
  never pass as a channel binding.
- API: `channel::bind(E, role, app, signer, now, rng)` and
  `channel::check(sig, E, role, app, tag, verifier, now)`. About twenty lines
  on top of `sign_data` and `verify`.

### 18.4 Records

A **record** is a new item, signed by an identity under its newest event,
that says: as of this time, my log's head is this event, and these are all
the statements and data signatures I have revoked.

```
record = "(" "record" issuer "(" "issued" time ")" "(" "head" hash ")" "(" "revoked" *hash ")" ")"
```

- `issuer` is `(X, n)` with `n` the head of X's log; `head` is that event's
  hash; `revoked` is sorted and distinct. Label `writ/v1/record`; signed by k
  of event n's authority (the current keys), like a statement.
- A record is valid when its issuer's log reaches `n` and no further (a
  record under an older event says nothing: the rotation after it may have
  changed everything), `head` matches, the signature verifies, and `issued ≤
now + skew`.
- Every hash a valid record lists is revoked, as if by a revocation statement.
  Revocation statements still work on their own; a record collects them.
- Records under the same head are combined, never ranked: freshness counts
  from the newest one, and a hash is revoked if any of them lists it. So a
  newer record that leaves something out (signed by a thief with the current
  key, or by a buggy job) cannot un-revoke what an older one listed.
- A record reveals only hashes: nothing about what was said, or to whom.
- `rotate` never keeps records: they belong to one event.

A thief with the current key can sign records too: records that leave out
the owner's later revocations, or that revoke good statements. The first only
works on verifiers that never see the owner's records, since records are
combined. Both stop counting at the owner's rotation, for every verifier that
sees it, as with every other theft of the current key (§10).

### 18.5 Publishing: `publish` in the log

An identity opts in by naming, in its log, how often it signs a new record
and where it puts it:

```
inception = "(" "inception" authority "(" "next" hash ")" [ max-validity ] [ publish ] ")"
rotation  = "(" "rotation" … [ max-validity ] [ publish ] "(" "keep" *hash ")" ")"
publish   = "(" "publish" "(" "max-age" secs ")" *4url ")"   ; url: 1–255 bytes, printable ASCII, no spaces
```

- `max-age` is D: verifiers refuse a record more than D seconds old, so the
  owner signs a new one at least that often. At least 3600; `writ init
--publish` defaults to 7 days, which a daily job can miss six times in a
  row before anything fails, and which matches an OCSP response's usual
  life.
- URLs are where to find the record. There may be none, if records travel
  some other way (stapled to proofs, gossip). Put them on different
  providers: if they all fail for longer than D, the identity's long-lived
  statements stop verifying (§18.8). `writ init --publish` and `writ rotate`
  warn when every URL is on the same host.
- As with `max-validity`, each event states its own `publish`, and the head's
  is the one in force; an event without it publishes nothing. Only a rotation
  can change it, so a thief with the current key cannot switch it off. Logs
  without the field keep their bytes.
- It is in the log, not in each statement: one place covers everything the
  identity signs, it costs one field rather than one per statement, and the
  current key cannot change it.

### 18.6 Freshness

A verifier answering a question at time `now` applies one more rule to every
statement or data signature `s` it uses (every grant on the chain, every name
statement used to reach a holder, and the signature in `verify`):

- If `s`'s issuer X has `publish` with max-age D at its head, and `s` lives
  longer than D (no `expires`, or `expires − issued > D`), then the material
  must hold a valid record by X with `issued ≥ now − D`, and no valid record
  by X under its head may list `s` (§18.4). Otherwise `s` is not valid, with the reason "no
  fresh record from X", and the denial lists X's URLs.
- If X does not publish, nothing changes: revocations count when they are in
  the material, as today.

Consequences:

- **Every issuer on the chain counts.** In me → alice → bob, the verifier
  needs my record (for my grant to alice, which is alice's authority) and
  alice's (for her grant to bob). If my record revokes my grant to alice,
  everything alice granted under it dies with it.
- **The verifier's own root is local.** A verifier that brings its root's
  own issuance log (`--as DIR`) already knows that root's revocations; that
  root needs no record. libwrit takes these ids as an argument
  (`Verifier::local`). A root given only by its id is treated like any other
  issuer.
- **Short-lived statements are exempt**, statement by statement: a
  revocation would take up to D to arrive anyway. Leaf grants (at most a
  day) rarely need a record; a 90-day grant from the same issuer does.
- **Delegation passes on dependence.** Bob's access through alice depends on
  alice's records staying fresh. If that matters to me, I grant to bob
  directly.
- A verifier that wants revocation checked for everyone may refuse chains
  through issuers that do not publish (`--require-records`). Not the
  default.

### 18.7 Getting records

Records are signed, so it does not matter who carries them. A host can
withhold a record but cannot forge one or make an old one look new; plain
HTTP, a CDN, a git repository or an email attachment all work, and https is
not needed for integrity.

- **The owner** signs and publishes, for example daily from cron:
  `writ export -i me --record | ssh web 'cat > www/writ/me.writ'`. The file
  holds the log and a new record. A rotation voids the current record at
  once (§18.4), so `writ rotate` signs a new record under the new event in
  the same step, and the file should be published straight after.
- **The presenter** may staple: `writ prove --fetch` gets a fresh record for
  every issuer on the chain and includes them in the proof, so the verifier
  needs no network.
- **The verifier** fills gaps: `check`, `verify`, `resolve` and `prove` take
  `--fetch`, which, for each issuer that needs a record and has none fresh
  in the material, fetches its URLs in turn, adds that issuer's log events
  and records from what comes back (nothing else: a host has no say in the
  rest of the material), and answers again.
- `--fetch` uses libcurl (the `curl` crate), in writ-tool only; libwrit
  stays pure and only lists what to fetch. Limits: `http` and `https` only,
  redirects included, so a hostile URL cannot read `file:` paths or use
  libcurl's other protocols; at most 5 redirects and 16 MiB per URL; a
  connection gets 10 seconds, a transfer stops if it moves under 1 KiB a
  second for 15 seconds, and one URL, redirects included, takes at most 60
  seconds.
- It fetches only for identities the search reached from the verifier's
  roots through valid statements: issuers of grants from reached holders,
  issuers of names under valid grants (the search checks a grant to a name
  path before reading the names), and a data signature's signer once it is
  known to hold the tag. At most 16 identities per command. So a bundle
  cannot make a verifier fetch URLs of its choosing.
- An identity's URLs are tried in turn until one gives a fresh record; a host
  serving an old or empty file does not stop the others from being tried.
- `--fetch` does not depend on TLS certificates. Records are checked by their
  signatures, so TLS adds only privacy. It verifies certificates as usual;
  on a certificate error (expired, wrong name, self-signed) it retries
  without verification and says so in a warning. An expired certificate on
  the owner's host then costs privacy against an active attacker, not
  revocation. Since any active attacker can present a bad certificate to
  force that retry, https in a publish URL protects against passive
  observers only; records are public, so that is the whole cost. URLs with
  a user name are refused.
- `--state` keeps, per remembered id, the log, the revocation statements
  valid under the head (§16), the newest valid record, and up to 15 older
  ones that list revocations the rest don't (§18.4 combines them), judged at
  the later of the clock and `--at`, so a record fetched once keeps serving
  until it is D old. Records are stored with only their verified
  signatures.
- `--as DIR` reads DIR/record.writ too, and `prove` attaches that root's
  newest record: the root needs none, but the proof's receiver does.
- Writing DIR/record.writ (`revoke`, `export --record`, `rotate`) holds the
  lock that guards issued.writ and reads that file afresh, so concurrent
  writers can't leave a revocation out.
- Answers say when a record a chain relies on is within a fifth of D of
  going stale, so a broken cron job is noticed before it fails.

### 18.8 Failure modes

- **A host goes down.** Nothing happens while any fresh copy reaches the
  verifier: from `--state`, from a stapled proof, from another URL. Records
  do not depend on any one place.
- **No fresh record reaches the verifier for longer than D.** Statements
  from that issuer that need one are refused. This is deliberate: the
  alternative, accepting when the check cannot be done ("soft fail"), lets
  anyone who can block the check disable revocation. D is the grace period,
  chosen per identity by its owner: short D revokes quickly and fails sooner
  in an outage; long D tolerates outages and revokes slowly; no `publish` at
  all depends on nothing.
- **The owner loses a host or domain** (an expired domain, a closed account,
  a lost or expired certificate). It is an outage, never a forgery: whoever
  holds the name next can serve nothing, or the owner's old records, and
  neither looks fresh. Recovery, cheapest first: the other URLs in the log;
  handing fresh records over directly (they are text: a bundle, an email, a
  proof stapled by a presenter); restoring the host within D; or rotating to
  new URLs. The last needs the next key, deliberately: if the current key
  could change the URLs, a thief could send verifiers to a host that serves
  records without the owner's revocations. The new URLs then spread with
  every proof, because proofs carry each issuer's log.
- **The owner stops signing** (a broken job, or gone for good). Their
  long-lived statements stop verifying after D. For an owner who is gone,
  that is the right outcome; for a broken job, the staleness warnings are the
  defence.
- **An attacker blocks every copy for longer than D.** That denies service to
  one identity's long-lived statements and forges nothing. An attacker who
  controls a verifier's network that thoroughly can block its application
  anyway.

### 18.9 A shared server: not proposed

A server many people upload to would add a place to publish for people
without a host. Its hard problem is spam. Every item in a record is signed by
its id's keys, so spam cannot touch an existing identity's files, but
registering new ids and frequent updates would need pricing: an earlier
draft (commit 1cdd395) priced writes with a proof of work that rises with
load, while keeping updates to established, quiet ids cheap. If built, it
serves the same files, with a small vetted HTTP crate (owner's choice,
2026-10-18).

### 18.10 Order of work

```
libwrit     multi-tag grants; channel binding; record item; publish; freshness rule
writ-tool   grant with several TAGs; init/rotate --publish --max-age;
            export --record; --fetch; --state keeps records; staleness warnings
```

1. Multi-tag grants: format, SPEC, vectors, `writ grant` with several TAGs.
2. Records and `publish`: format, the freshness rule, SPEC, vectors (fresh,
   stale, exempt, local root, three-issuer chains). Built 2026-10-19 in
   libwrit (`Publish`, `Record`, `sign_record`, `Verifier::with_local`,
   `Policy::require_records`); proofs carry the records they relied on.
3. The CLI: `--publish`/`--max-age`, `export --record`, `--fetch` (libcurl),
   `--state`, warnings. Built 2026-10-19: `init`, `rotate` and `revoke` write
   DIR/record.writ (the log and a new record); `export --record` renews it;
   query commands take `--fetch` and `--require-records`; `--state` keeps
   records; denials name the URLs; answers warn in the last fifth of max-age.
4. Channel binding. Built 2026-10-19: `libwrit::channel` (`bind`, `check`,
   `Role`); `sign_data` and `writ sign` refuse contexts starting with `writ/`;
   SPEC §14 and a vector in `chains/channel.*`.
