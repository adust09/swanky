#!/bin/bash

# Set up Nix environment
. ~/.nix-profile/etc/profile.d/nix.sh

# Create a basic shell.nix if it doesn't exist
if [ ! -f shell.nix ]; then
    cat > shell.nix << 'EOF'
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Add your development dependencies here
  ];
}
EOF
fi

# Initialize Nix shell
nix-shell --run "echo 'Nix environment is ready'" 
