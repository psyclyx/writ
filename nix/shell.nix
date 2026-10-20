{
  mkShell,
  cargo,
  cargo-nextest,
  cargo-fuzz,
  cargo-audit,
  pkg-config,
  curl,
  openssl,
  clippy,
  marksman,
  nixd,
  nixfmt,
  prettier,
  rust-analyzer,
  rustc,
  rustfmt,
  taplo,
  treefmt,
  bashInteractive,
  bash-completion,
  fish,
  zsh,
  mandoc,
}:
mkShell {
  # The completion tests also exercise bash-completion's _init_completion path.
  WRIT_TEST_BASH_COMPLETION = "${bash-completion}/share/bash-completion/bash_completion";

  packages = [
    # rust
    rustc
    cargo
    clippy
    rustfmt
    rust-analyzer
    cargo-nextest
    cargo-fuzz # fuzz/README.md
    cargo-audit # hooks/pre-commit

    # writ --fetch links the system libcurl (DESIGN.md §18.7)
    pkg-config
    curl
    openssl # the --fetch TLS test serves a record with s_server

    # testing the completion scripts and man pages
    bashInteractive
    bash-completion
    fish
    zsh
    mandoc

    # formatting
    treefmt
    nixfmt
    prettier
    taplo

    # language servers
    nixd
    marksman
  ];
}
