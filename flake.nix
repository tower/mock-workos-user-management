{
  description = "Mock WorkOS User Management API";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.buildGoModule {
          pname = "mock-workos-user-management";
          version = "0.1.0";
          src = ./.;
          vendorHash = null;
          subPackages = [ "cmd/mock-workos-user-management" ];
        };
      }
    );
}
