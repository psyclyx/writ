# NIST ACVP vectors: SLH-DSA-SHAKE-128s

Test vectors for `crates/writ-slhdsa`, consumed by
`crates/writ-slhdsa/tests/acvp.rs`.

## Provenance

- Repository: <https://github.com/usnistgov/ACVP-Server>
- Commit: `975de31eb83d87039ec88934fdc47d8c312b892d` (2026-08-12), fetched
  2026-10-11 from `raw.githubusercontent.com`.
- Source files (each `internalProjection.json`, which holds both prompts and
  expected results), with SHA-256 of the file as fetched:
  - `gen-val/json-files/SLH-DSA-keyGen-FIPS205/internalProjection.json`
    `d7c53a1b6450087047b57aae83a5a51a0ac89ecdb23ebe071e83fbb69ae9d920`
  - `gen-val/json-files/SLH-DSA-sigGen-FIPS205/internalProjection.json`
    `62b42e7c27fda5de8a94aba2943ae413b59b6ea08141f3bc035b1eceae235dba`
  - `gen-val/json-files/SLH-DSA-sigVer-FIPS205/internalProjection.json`
    `a013fc2104f4ed4799d96d51141f65b965969b2cf10646626a021b6d456ce792`

## What was kept

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

## Format

Line-oriented text, one file per ACVP test type:

- Lines starting with `#` are comments.
- Blank lines separate test cases.
- Every other line is `key = value`; the value is the rest of the line after
  `=`, trimmed, and may be empty (an empty context).
- Byte strings are hex. Other values: `tgId`, `tcId` (decimal),
  `interface` (`internal` | `external`), `deterministic` and `testPassed`
  (`true` | `false`), `reason` (free text).

Keys per file:

- keygen: `tgId tcId skSeed skPrf pkSeed sk pk`
- siggen: `tgId tcId interface deterministic sk pk message [context]
[additionalRandomness] signature` — `context` is present for `external`
  only; `additionalRandomness` (opt_rand) for hedged cases only; deterministic
  cases use opt_rand = PK.seed.
- sigver: `tgId tcId interface pk message [context] signature testPassed reason`

## Regenerating

With `jq` (e.g. `nix-shell -p jq`), from the three `internalProjection.json`
files (shown for sigVer; the others are analogous):

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

followed by stripping trailing whitespace (`sed 's/[[:space:]]*$//'`).
