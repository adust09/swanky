FROM ubuntu:22.04

# Install basic dependencies and systemd
RUN apt-get update && apt-get install -y \
    curl \
    xz-utils \
    git \
    systemd \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash vscode \
    && echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install Nix as root
RUN bash -c 'sh <(curl -L https://nixos.org/nix/install) --daemon'

# Switch to non-root user
USER vscode

# Add Nix to user's PATH
ENV PATH="/home/vscode/.nix-profile/bin:${PATH}"

# Set up Nix environment
RUN echo '. ~/.nix-profile/etc/profile.d/nix.sh' >> ~/.bashrc

# Set working directory
WORKDIR /workspace

# Keep container running
CMD ["/bin/bash"] 
