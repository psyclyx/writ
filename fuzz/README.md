# Fuzzing

libFuzzer targets for every decoder of untrusted input (DESIGN.md §3.3).
Each checks a round-trip property as well as that nothing panics:

| target      | input                      | property                                                                 |
| ----------- | -------------------------- | ------------------------------------------------------------------------ |
| `csexp`     | canonical s-expressions    | what decodes re-encodes to exactly the input                             |
| `armor`     | armored text               | what decodes armors back to the same blocks, and was that canonical text |
| `readable`  | the readable form          | print, then parse, gives the same tree                                   |
| `text_keys` | bech32m, ids, key lines    | what parses prints back to the same value                                |
| `bundle`    | bundles, armored or binary | items re-encode to themselves; verifying the material never panics       |

The dev shell has `cargo-fuzz`. It works with stable Rust when the sanitizer
is off (`-s none`); the code has no `unsafe`, so AddressSanitizer would add
little. From this directory:

```sh
mkdir -p corpus/bundle corpus/armor
cp ../vectors/chains/*.writ corpus/bundle/
cp ../vectors/chains/*.writ corpus/armor/
cargo fuzz run -s none bundle -- -max_len=65536 -max_total_time=600
```

`-max_len=65536` lets inputs hold signed items (an SLH-DSA signature is
7856 bytes). Crashes are saved under `artifacts/TARGET/`; replay one with
`cargo fuzz run -s none TARGET artifacts/TARGET/crash-…`, and add a
regression test for it in the crate concerned.
