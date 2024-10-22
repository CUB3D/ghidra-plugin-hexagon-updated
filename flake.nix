{
  description = "A very basic flake";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let pkgs = nixpkgs.legacyPackages.${system}; in
        {
          devShells.default = pkgs.mkShell {
            buildInputs = with pkgs; [
                pkgs.gradle_7
                pkgs.jdk11
                pkgs.gcc
            ];
            shellHook = ''
            '';
          };

# Nix is bad and should feel bad
#          packages.default = pkgs.runCommand "test" {
#            buildInputs = [
#                pkgs.gradle_7
#                pkgs.jdk11
#                pkgs.gcc
#            ];
#            src = ./.;
#          }''
#              #!/bin/bash
#    mkdir -p $out/
#    cp -R $src/* .
#    gradle -I gradle/support/fetchDependencies.gradle buildGhidra --info
#        
#    #cp output.txt $out/
#          '';
        }
      );
}
