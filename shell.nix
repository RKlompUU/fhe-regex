{ pkgs ? import <nixpkgs> {
    overlays = [
      (import (fetchTarball "https://github.com/oxalica/rust-overlay/archive/master.tar.gz"))
    ];
  }
}:
let
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    (rust-bin.stable.latest.default.override {
      extensions = ["rust-src"];
    })
  ];
}
