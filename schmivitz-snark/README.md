# schmivitz-snark

SNARK wrapper for VOLE itH in the Head verification.

## Overview

schmivitz-snark is a Rust library that provides a SNARK (Succinct Non-interactive Argument of Knowledge) implementation for verifying VOLE-based zero-knowledge proofs. It allows converting VOLE proofs from the schmivitz library into SNARK proofs that can be verified on-chain using Solidity.

The library is built on top of the [arkworks](https://github.com/arkworks-rs) ecosystem, specifically using the Groth16 proving system with the BN254 curve (also known as alt_bn128), which is supported by Ethereum and other EVM-compatible blockchains.

## Features

- Convert VOLE-based proofs to SNARK proofs
- Generate Solidity verifier contracts
- Efficient field element conversions between different representations
- Support for boolean circuit constraints

## Installation

Add schmivitz-snark to your Cargo.toml:

```toml
[dependencies]
schmivitz-snark = "0.1.0"
```

If you're working within the swanky ecosystem, you can use the workspace dependency:

```toml
[dependencies]
schmivitz-snark = { path = "../schmivitz-snark" }
```

## Usage

Here's a basic example of how to use schmivitz-snark to convert a VOLE proof to a SNARK proof and generate a Solidity verifier:

```rust
use ark_bn254::Bn254;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use arkworks_solidity_verifier::SolidityVerifier;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{
    constraints::VoleVerificationBoolean,
    f128b_to_boolean_array, f64b_to_boolean_array, f8b_to_boolean_array,
};
use std::fs;
use std::path::Path;

// Generate a VOLE proof using schmivitz
let mut transcript = Transcript::new(b"schmivitz-snark");
let rng = &mut thread_rng();
let schmivitz_proof: Proof<InsecureVole> = Proof::<InsecureVole>::prove(
    &mut circuit,
    &private_input_path,
    &mut transcript,
    rng,
)?;

// Convert the VOLE proof to a SNARK circuit
let cs = ConstraintSystem::<Bn254Fr>::new_ref();
let circuit = build_circuit(cs.clone(), schmivitz_proof.clone());

// Generate proving and verification keys
let mut rng = ark_std::test_rng();
let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

// Generate a Solidity verifier contract
let solidity_verifier = Groth16::<Bn254>::export(&vk);
let output_dir = Path::new("solidity_output");
if !output_dir.exists() {
    fs::create_dir_all(output_dir)?;
}
let output_path = output_dir.join("vole_verifier.sol");
fs::write(&output_path, solidity_verifier)?;

// Generate a SNARK proof
let public_input = vec![];
let snark_proof = Groth16::prove(&pk, circuit, &mut rng)?;

// Verify the SNARK proof
let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;
```

For a complete example, see the [example.rs](examples/example.rs) file.

## Field Conversions

The library provides utilities for converting between different field representations:

- `f8b_to_boolean_array`: Convert an 8-bit field element to a boolean array
- `f64b_to_boolean_array`: Convert a 64-bit field element to a boolean array
- `f128b_to_boolean_array`: Convert a 128-bit field element to a boolean array
- `boolean_array_to_f8b`: Convert a boolean array to an 8-bit field element
- `boolean_array_to_f64b`: Convert a boolean array to a 64-bit field element
- `boolean_array_to_f128b`: Convert a boolean array to a 128-bit field element
