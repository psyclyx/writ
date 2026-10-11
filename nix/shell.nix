{
  mkShell,
  cargo,
  cargo-nextest,
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
}:
mkShell {
  packages = [
    # rust
    rustc
    cargo
    clippy
    rustfmt
    rust-analyzer
    cargo-nextest

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
