{
  mkShell,
  cargo,
  cargo-nextest,
  cargo-fuzz,
  cargo-audit,
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
