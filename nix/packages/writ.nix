{
  lib,
  rustPlatform,
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
      (root + "/crates")
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

  meta = {
    description = "Signed statements about keys: names, grants, delegation, revocation, rotation";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "writ";
  };
}
