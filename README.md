# Keccak Hash Function VOLE-in-the-Head Zero-Knowledge Proof

This project demonstrates how to convert a Keccak hash function circuit from Bristol Fashion format to SIEVE IR, and then use it to generate a VOLE-in-the-Head zero-knowledge proof.

## Overview

The project consists of the following components:

1. **keccak_bristol_to_sieve.rs**: A Rust program that converts the Keccak hash function circuit from Bristol Fashion format to SIEVE IR.
2. **schmivitz/src/bin/schmivitz-prover.rs**: A binary for generating VOLE-in-the-Head zero-knowledge proofs.
3. **schmivitz/src/bin/schmivitz-verifier.rs**: A binary for verifying VOLE-in-the-Head zero-knowledge proofs.
4. **generate_keccak_zkp.sh**: A shell script that orchestrates the entire process.

## Prerequisites

- Rust and Cargo
- The Swanky cryptography library
- The Bristol Fashion circuit for Keccak hash function (located at `bristol-fashion/circuits/Keccak_f.txt`)
- The schmivitz library for VOLE-in-the-Head zero-knowledge proofs

## Usage

1. Make sure the script is executable:
   ```
   chmod +x generate_keccak_zkp.sh
   ```

2. Run the script:
   ```
   ./generate_keccak_zkp.sh
   ```

The script will:
1. Compile the Bristol Fashion to SIEVE IR converter
2. Convert the Keccak hash function circuit to SIEVE IR
3. Create sample input files for the proof
4. Compile the SIEVE IR circuit with mac-n-cheese
5. Compile the schmivitz binaries
6. Generate a VOLE-in-the-Head zero-knowledge proof
7. Verify the proof

## How It Works

### Bristol Fashion to SIEVE IR Conversion

The Bristol Fashion format represents circuits using gates like XOR, AND, INV, etc. The SIEVE IR format represents circuits using gates like Add, Mul, AddConstant, MulConstant, etc. The conversion process maps each Bristol Fashion gate to its equivalent SIEVE IR gate.

For example:
- XOR gates in Bristol Fashion are converted to Add gates in SIEVE IR (since we're working in F2)
- AND gates in Bristol Fashion are converted to Mul gates in SIEVE IR
- INV gates in Bristol Fashion are converted to AddConstant gates with a constant of 1 in SIEVE IR

### VOLE-in-the-Head Zero-Knowledge Proofs

VOLE-in-the-Head is a technique for generating zero-knowledge proofs that is post-quantum secure. It uses Vector Oblivious Linear Evaluation (VOLE) to create proofs that are publicly verifiable and non-interactive.

The schmivitz library implements the VOLE-in-the-Head protocol as defined by Baum et al. in "Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-head".

## Customization

You can customize the input to the Keccak hash function by modifying the `keccak_private.txt` file. The file contains 1600 bits (represented as 0s and 1s) that serve as the input to the Keccak hash function.

## References

- [Bristol Fashion Circuit Format](https://homes.esat.kuleuven.be/~nsmart/MPC/)
- [SIEVE IR Format](https://github.com/GaloisInc/swanky/tree/main/mac-n-cheese/sieve-parser)
- [VOLE-in-the-Head: Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures](https://eprint.iacr.org/2023/996)
