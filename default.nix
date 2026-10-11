let
  npins = import ./npins;

  mkPackages =
    pkgs:
    if builtins.pathExists ./nix/packages then
      pkgs.lib.packagesFromDirectoryRecursive {
        inherit (pkgs) callPackage;
        directory = ./nix/packages;
      }
    else
      { };

  # Packages are scoped against `final` (not `prev`) so that packages in
  # nix/packages/ can reference each other. This cannot infinitely recurse:
  # the fixpoint is lazy, and an attribute is only demanded when something
  # actually depends on it.
  overlay = final: _prev: mkPackages final;
in
{
  nixpkgs ? npins.nixpkgs,
  pkgs ? import nixpkgs { },
}:
let
  finalPkgs = pkgs.extend overlay;
in
rec {
  packages = mkPackages finalPkgs;
  inherit overlay;
  shell = finalPkgs.callPackage ./nix/shell.nix { };
  # default = packages.writ; # uncomment once nix/packages/ has a main package
}
