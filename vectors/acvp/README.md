# NIST ACVP vectors

Two sets, both from the same ACVP-Server commit:

- SLH-DSA-SHAKE-128s, for `crates/writ-slhdsa`, consumed by
  `crates/writ-slhdsa/tests/acvp.rs`.
- ML-DSA-65, for the libcrux-ml-dsa entry points the leaf suite calls,
  consumed by `crates/libwrit/tests/acvp_mldsa.rs`.

## Provenance

- Repository: <https://github.com/usnistgov/ACVP-Server>
- Commit: `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12), fetched
  from `raw.githubusercontent.com` (SLH-DSA on 2026-10-11, ML-DSA on
  2026-10-16).
- Source files (each `internalProjection.json`, which holds both prompts and
  expected results), with SHA-256 of the file as fetched:
  - `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json`
    `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920`
  - `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`
    `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba`
  - `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`
    `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792`
  - `gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json`
    `e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf`
  - `gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json`
    `72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22`
  - `gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json`
    `47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437`

## What was kept: SLH-DSA-SHAKE-128s

Only test groups with `parameterSet` = `SLH-DSA-SHAKE-128s`, and of those
every test case except the `preHash` groups (HashSLH-DSA, FIPS 205 Alg. 23/25,
is not implemented — writ uses only pure SLH-DSA).

| file                            | ACVP groups (tgId)                                                                                     | cases |
| ------------------------------- | ------------------------------------------------------------------------------------------------------ | ----: |
| `slh-dsa-shake-128s-keygen.txt` | 2                                                                                                      |    10 |
| `slh-dsa-shake-128s-siggen.txt` | 34 internal/deterministic, 70 internal/hedged, 25 external pure/deterministic, 61 external pure/hedged |    28 |
| `slh-dsa-shake-128s-sigver.txt` | 34 internal, 25 external pure                                                                          |    28 |

The external groups include empty, short and 255-byte contexts; sigVer covers
valid signatures, modified message, modified R / SIGFORS / SIGHT, and
signatures one byte too long or too short.

Dropped fields: `deferred` and `hashAlg` (always `none` in kept groups);
`sk` and `additionalRandomness` from sigVer cases (unused by verification).
Group-level `signatureInterface` and `deterministic` are copied into each case.
Nothing else was changed; hex is as in the source (upper case).

## What was kept: ML-DSA-65

Only groups with `parameterSet` = `ML-DSA-65` and, for sigGen and sigVer, the
external pure interface (`signatureInterface` = `external`, `preHash` =
`pure`), the only one writ uses. Dropped groups:

- internal interface (with and without `externalMu`): libcrux-ml-dsa exposes
  `sign_internal`/`verify_internal` only behind its `acvp` feature, and has no
  external-mu entry point;
- `preHash` (HashML-DSA): writ doesn't use it, and libcrux implements only
  the SHAKE128 pre-hash.

All ML-DSA-65 cases of the kept groups come to about 1.3 MB, so only a
subset of cases is kept (about 450 KB), chosen for short messages and the
edge cases:

| file                   | ACVP group (tgId)          | tcIds kept                                      | cases |
| ---------------------- | -------------------------- | ----------------------------------------------- | ----: |
| `ml-dsa-65-keygen.txt` | 2                          | 26–35 (first 10 of 25)                          |    10 |
| `ml-dsa-65-siggen.txt` | 3 deterministic, 15 hedged | 35, 39, 41, 44; 213, 214, 215, 216 (of 15 + 15) |     8 |
| `ml-dsa-65-sigver.txt` | 3                          | 31, 33, 34, 35, 38, 39, 42, 43, 44 (of 15)      |     9 |

The sigGen cases include a 1-byte message, an empty context and a 255-byte
context in each of the deterministic and hedged groups, and the 8192-byte
maximum message (deterministic). The sigVer cases are all three valid signatures and at least one of
each rejection the group has: modified message, modified z, modified hint,
modified commitment; they include an empty and a 255-byte context.

Dropped fields: `deferred` (always `false`) and `hashAlg` (always `none`);
`sk` from sigVer cases (unused by verification). Group-level `deterministic`
is copied into each sigGen case. Nothing else was changed; hex is as in the
source (upper case).

All kept cases pass against libcrux-ml-dsa 0.0.11, both with its AVX2 code
(the default on x86_64) and with it compiled out (`LIBCRUX_DISABLE_SIMD256=1`).
libcrux's build script doesn't declare that variable, so cargo won't rebuild
for it: use a fresh target directory (`CARGO_TARGET_DIR`).

## Format

Line-oriented text, one file per ACVP test type:

- Lines starting with `#` are comments.
- Blank lines separate test cases.
- Every other line is `key = value`; the value is the rest of the line after
  `=`, trimmed, and may be empty (an empty context).
- Byte strings are hex. Other values: `tgId`, `tcId` (decimal),
  `interface` (`internal` | `external`), `deterministic` and `testPassed`
  (`true` | `false`), `reason` (free text).

Keys per SLH-DSA file:

- keygen: `tgId tcId skSeed skPrf pkSeed sk pk`
- siggen: `tgId tcId interface deterministic sk pk message [context]
[additionalRandomness] signature` — `context` is present for `external`
  only; `additionalRandomness` (opt_rand) for hedged cases only; deterministic
  cases use opt_rand = PK.seed.
- sigver: `tgId tcId interface pk message [context] signature testPassed reason`

Keys per ML-DSA file (all external pure, so no `interface` key):

- keygen: `tgId tcId seed pk sk` — `seed` is ξ.
- siggen: `tgId tcId deterministic sk pk message context [rnd] signature` —
  `rnd` for hedged cases only; deterministic cases use rnd = 0^32.
- sigver: `tgId tcId pk message context signature testPassed reason`

## Regenerating

With `jq` (e.g. `nix-shell -p jq`), from the `internalProjection.json` files.
For SLH-DSA sigVer (the other SLH-DSA files are analogous):

```sh
jq -r '.testGroups[]
  | select(.parameterSet == "SLH-DSA-SHAKE-128s" and .preHash != "preHash")
  | . as $g | .tests[]
  | "", "tgId = \($g.tgId)", "tcId = \(.tcId)",
    "interface = \($g.signatureInterface)", "pk = \(.pk)",
    "message = \(.message)",
    (if has("context") then "context = \(.context)" else empty end),
    "signature = \(.signature)", "testPassed = \(.testPassed)",
    "reason = \(.reason)"' internalProjection.json
```

For ML-DSA-65 sigGen (keyGen selects `.tcId <= 35` from the `ML-DSA-65`
group; sigVer selects its tcIds the same way):

```sh
jq -r '.testGroups[]
  | select(.parameterSet == "ML-DSA-65" and .signatureInterface == "external"
           and .preHash == "pure")
  | . as $g | .tests[]
  | select(.tcId | IN(35, 39, 41, 44, 213, 214, 215, 216))
  | "", "tgId = \($g.tgId)", "tcId = \(.tcId)",
    "deterministic = \($g.deterministic)", "sk = \(.sk)", "pk = \(.pk)",
    "message = \(.message)", "context = \(.context)",
    (if has("rnd") then "rnd = \(.rnd)" else empty end),
    "signature = \(.signature)"' internalProjection.json
```

followed by stripping trailing whitespace (`sed 's/[[:space:]]*$//'`) and
adding the one-line `#` header.
