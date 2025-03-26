#!/bin/bash

# Source Nix environment
if [ -e ~/.nix-profile/etc/profile.d/nix.sh ]; then
    . ~/.nix-profile/etc/profile.d/nix.sh
else
    echo "Nix profile not found. Please rebuild the container."
    exit 1
fi

# Verify Nix installation
if ! command -v nix &> /dev/null; then
    echo "Nix is not properly installed. Please rebuild the container."
    exit 1
fi

# Install project dependencies
nix-shell --run "echo 'Nix environment is ready'" 
