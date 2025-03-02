#!/bin/bash
set -e

echo "Step 1: Compiling the Bristol Fashion to SIEVE IR converter..."
rustc keccak_bristol_to_sieve.rs

echo "Step 2: Running the converter to generate the SIEVE IR circuit..."
./keccak_bristol_to_sieve

echo "Step 3: Creating input files for the proof..."
# Create a sample public input file
cat > keccak_public.txt << EOF
version 2.0.0;
public_input;
@type field 2;
@begin
EOF

# Add 1600 zeros as public input (representing the initial state)
for i in {1..1600}; do
    echo "    <0>;" >> keccak_public.txt
done

echo "@end" >> keccak_public.txt

# Create a sample private input file
cat > keccak_private.txt << EOF
version 2.0.0;
private_input;
@type field 2;
@begin
EOF

# Add 1600 zeros as private input (this would be your actual input in a real scenario)
for i in {1..1600}; do
    echo "    <0>;" >> keccak_private.txt
done

echo "@end" >> keccak_private.txt

echo "Step 4: Compiling the SIEVE IR circuit with mac-n-cheese..."
cargo run --manifest-path=diet-mac-and-cheese/Cargo.toml --bin dietmc -- \
    --relation keccak_f.sieve \
    --instance keccak_public.txt \
    --witness keccak_private.txt \
    --text \
    --output keccak_compiled.bin

echo "Step 5: Compiling the schmivitz binaries..."
cargo build --manifest-path=schmivitz/Cargo.toml --bin schmivitz-prover
cargo build --manifest-path=schmivitz/Cargo.toml --bin schmivitz-verifier

echo "Step 6: Generating the VOLE-in-the-Head zero-knowledge proof..."
cargo run --manifest-path=schmivitz/Cargo.toml --bin schmivitz-prover -- \
    --circuit keccak_compiled.bin \
    --private keccak_private.txt \
    --output keccak_proof.bin

echo "Step 7: Verifying the VOLE-in-the-Head zero-knowledge proof..."
cargo run --manifest-path=schmivitz/Cargo.toml --bin schmivitz-verifier -- \
    --circuit keccak_compiled.bin \
    --proof keccak_proof.bin \
    --public keccak_public.txt

echo "Done! The Keccak hash function has been converted to SIEVE IR and a VOLE-in-the-Head zero-knowledge proof has been generated and verified."
