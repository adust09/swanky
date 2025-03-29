FROM ubuntu:22.04

# Install basic dependencies and systemd
RUN apt-get update && apt-get install -y \
    curl \
    xz-utils \
    git \
    systemd \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash vscode \
    && echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install Nix as root and verify installation
RUN bash -c 'sh <(curl -L https://nixos.org/nix/install) --daemon' \
    && ls -la /nix \
    && ls -la /root/.nix-profile || echo "Root nix-profile not found" \
    && mkdir -p /nix \
    && chown -R vscode:vscode /nix

# Set up Nix environment for root
RUN echo '. ~/.nix-profile/etc/profile.d/nix.sh' >> /root/.bashrc \
    && ls -la /root/.nix-profile/etc/profile.d/nix.sh || echo "Root nix.sh not found"

# Switch to non-root user
USER vscode

# Initialize Nix for vscode user and verify
RUN bash -c 'sh <(curl -L https://nixos.org/nix/install) --no-daemon' \
    && ls -la ~/.nix-profile || echo "User nix-profile not found" \
    && ls -la ~/.nix-profile/etc/profile.d/nix.sh || echo "User nix.sh not found"

# Set up Nix environment for vscode user
RUN echo '. ~/.nix-profile/etc/profile.d/nix.sh' >> ~/.bashrc \
    && echo '. ~/.nix-profile/etc/profile.d/nix.sh' >> ~/.profile

# Add Nix to user's PATH
ENV PATH="/home/vscode/.nix-profile/bin:${PATH}"

# Set working directory
WORKDIR /workspace

# Keep container running
CMD ["/bin/bash"] 
