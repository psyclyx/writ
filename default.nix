let
  npins = import ./npins;

  mkPackages =
    lib: callPackage:
    if builtins.pathExists ./nix/packages then
      lib.packagesFromDirectoryRecursive {
        inherit callPackage;
        directory = ./nix/packages;
      }
    else
      { };

  # Packages are called with `final.callPackage` (not `prev`) so that packages
  # in nix/packages/ can reference each other; the fixpoint is lazy, so that
  # cannot recurse. `lib` must come from `prev`: the overlay's attribute names
  # are computed with it, so taking it from `final` would.
  overlay = final: prev: mkPackages prev.lib final.callPackage;
in
{
  nixpkgs ? npins.nixpkgs,
  pkgs ? import nixpkgs { },
}:
let
  finalPkgs = pkgs.extend overlay;
in
rec {
  packages = mkPackages finalPkgs.lib finalPkgs.callPackage;
  inherit overlay;
  shell = finalPkgs.callPackage ./nix/shell.nix { };
  default = packages.writ;
}
