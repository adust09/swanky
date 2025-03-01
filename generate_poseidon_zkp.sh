#!/bin/bash
set -e

echo "Step 1: Compiling the Poseidon to SIEVE IR generator..."
rustc poseidon_to_sieve.rs

echo "Step 2: Running the generator to create the SIEVE IR circuit..."
./poseidon_to_sieve

echo "Step 3: Creating input files for the proof..."
# Create a sample public input file
cat > poseidon_public.txt << EOF
version 2.0.0;
public_input;
@type field 21888242871839275222246405745257275088548364400416034343698204186575808495617;
@begin
    <0>; # Expected output hash
@end
EOF

# Create a sample private input file with 3 field elements as input
cat > poseidon_private.txt << EOF
version 2.0.0;
private_input;
@type field 21888242871839275222246405745257275088548364400416034343698204186575808495617;
@begin
    <1>; # First input element
    <2>; # Second input element
    <3>; # Third input element
@end
EOF

echo "Step 4: Compiling the SIEVE IR circuit with mac-n-cheese..."
cargo run --manifest-path=diet-mac-and-cheese/Cargo.toml --bin dietmc -- \
    --relation poseidon_hash.sieve \
    --instance poseidon_public.txt \
    --witness poseidon_private.txt \
    --text \
    --output poseidon_compiled.bin

echo "Step 5: Compiling the schmivitz binaries..."
cargo build --manifest-path=schmivitz/Cargo.toml --bin schmivitz-prover
cargo build --manifest-path=schmivitz/Cargo.toml --bin schmivitz-verifier

echo "Step 6: Generating the VOLE-in-the-Head zero-knowledge proof..."
cargo run --manifest-path=schmivitz/Cargo.toml --bin schmivitz-prover -- \
    --circuit poseidon_compiled.bin \
    --private poseidon_private.txt \
    --output poseidon_proof.bin

echo "Step 7: Verifying the VOLE-in-the-Head zero-knowledge proof..."
cargo run --manifest-path=schmivitz/Cargo.toml --bin schmivitz-verifier -- \
    --circuit poseidon_compiled.bin \
    --proof poseidon_proof.bin \
    --public poseidon_public.txt

echo "Done! The Poseidon hash function has been implemented in SIEVE IR and a VOLE-in-the-Head zero-knowledge proof has been generated and verified."
