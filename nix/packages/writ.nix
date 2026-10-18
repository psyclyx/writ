{
  lib,
  stdenv,
  rustPlatform,
  installShellFiles,
}:
let
  root = ../..;
in
rustPlatform.buildRustPackage {
  pname = "writ";
  version = (lib.importTOML (root + "/Cargo.toml")).workspace.package.version;

  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/README.md") # read by the tour test
      (root + "/crates")
      (root + "/xtask") # a workspace member; its tests check vectors/ and doc/man/
      (root + "/doc")
      (root + "/vectors")
    ];
  };

  cargoLock.lockFile = root + "/Cargo.lock";
  cargoBuildFlags = [
    "--package"
    "writ-tool"
  ];
  # Run the whole workspace's tests: ACVP and writ's own vectors included.
  cargoTestFlags = [ "--workspace" ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = ''
    installManPage doc/man/*.1
  ''
  + lib.optionalString (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
    installShellCompletion --cmd writ \
      --bash <($out/bin/writ completions bash) \
      --fish <($out/bin/writ completions fish) \
      --zsh <($out/bin/writ completions zsh)
  '';

  meta = {
    description = "Signed statements about keys: names, grants, delegation, revocation, rotation";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "writ";
  };
}
