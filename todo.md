# Implementation Steps for Keccak_f ZK Proof System

This document outlines the steps required to implement a system that compiles a Keccak_f circuit from bristol-fashion format using mac-n-cheese, and then generates and verifies proofs with schmivitz.

## 1. Project Setup

- [x] Create a unified CLI tool (`keccak_zk.rs`) that handles compilation, proof generation, and verification
- [x] Set up Cargo.toml with necessary dependencies
- [x] Create a private input file for testing

## 2. Circuit Parsing and Compilation

- [x] Implement function to parse bristol-fashion circuit format
  - [x] Read the Keccak_f.txt file
  - [x] Parse the circuit structure (gates, wires, inputs, outputs)
  - [x] Create an internal representation of the circuit

- [x] Implement circuit compilation to SIEVE IR
  - [x] Count the number of multiplications (AND gates)
  - [x] Optimize circuit representation for SIMD processing
  - [x] Generate binary files for the circuit using mac-n-cheese
  - [x] Add unit tests for circuit parsing and compilation

## 3. Proof Generation

- [ ] Implement proof generation using schmivitz
  - [ ] Create a transcript for the proof
  - [ ] Generate the proof using the Proof::prove method
  - [ ] Serialize and save the proof to a file

## 4. Proof Verification

- [ ] Implement proof verification using schmivitz
  - [ ] Load the proof from file
  - [ ] Create a transcript for verification
  - [ ] Verify the proof using the Proof::verify method

## 5. Testing and Validation

- [ ] Test the circuit compilation
  - [ ] Compile the Keccak_f circuit
  - [ ] Verify the output files are generated correctly

- [ ] Test the proof generation
  - [ ] Generate a proof using a test input
  - [ ] Verify the proof is generated correctly

- [ ] Test the proof verification
  - [ ] Verify a valid proof
  - [ ] Verify that an invalid proof is rejected

## 6. Integration and Optimization

- [ ] Optimize performance
  - [ ] Implement multithreading for circuit evaluation
  - [ ] Optimize memory usage for large circuits

- [ ] Create a complete end-to-end workflow
  - [ ] Document the usage of the tool
  - [ ] Create example scripts for common use cases

## Command Examples

### Compile Circuit
```bash
cargo run -- compile --input bristol-fashion/circuits/Keccak_f.txt --output-prefix keccak
```

### Generate Proof
```bash
cargo run -- prove --circuit keccak.bin --private-input keccak_input.txt --output keccak_proof.bin
```

### Verify Proof
```bash
cargo run -- verify --circuit keccak.bin --proof keccak_proof.bin
```

## 7. Bristol Fashion to SIEVE IR Transpiler Implementation

This section outlines the specific implementation steps for creating a transpiler that converts Bristol Fashion circuit descriptions to SIEVE IR format.

### 7.1 Transpiler Core Implementation

- [x] Create a new module for the transpiler
  - [x] Define data structures for Bristol Fashion circuit representation
  - [x] Define data structures for SIEVE IR circuit representation
  - [x] Implement Bristol Fashion parser (or reuse existing one)

- [x] Implement gate conversion logic
  - [x] XOR gate to add gate conversion
  - [x] AND gate to mul gate conversion
  - [x] INV gate to add-with-constant conversion
  - [x] Add validation to reject unsupported gates (EQ, EQW)

- [x] Implement constant handling
  - [x] Create mechanism for generating constant 1 wire
  - [x] Ensure private input stream provides correct constant values

### 7.2 Input/Output Handling

- [x] Implement Bristol Fashion file reader
  - [x] Parse header information (gates, wires, inputs, outputs)
  - [x] Parse gate definitions
  - [x] Handle error cases (malformed files, unsupported gates)

- [x] Implement SIEVE IR output generator
  - [x] Generate SIEVE IR text format
  - [x] Optionally convert to flatbuffer binary format
  - [x] Ensure proper wire ID mapping

### 7.3 Testing and Validation

- [ ] Create unit tests for gate conversions
  - [ ] Test XOR to add conversion
  - [ ] Test AND to mul conversion
  - [ ] Test INV to add-with-constant conversion

- [ ] Create integration tests with real circuits
  - [ ] Test with SHA-256 circuit
  - [ ] Test with Keccak-f circuit
  - [ ] Verify output correctness by comparing circuit evaluations

### 7.4 CLI and Integration

- [ ] Add transpiler command to the CLI tool
  - [ ] Add command-line options for input/output files
  - [ ] Add options for output format (text/binary)
  - [ ] Add validation options

- [ ] Integrate with existing workflow
  - [ ] Connect transpiler output to proof generation
  - [ ] Update documentation with transpiler usage

### 7.5 Optimization

- [ ] Optimize for large circuits
  - [ ] Implement streaming processing for large files
  - [ ] Optimize memory usage for circuit representation
  - [ ] Add progress reporting for long-running operations

### Command Example

```bash
cargo run -- transpile --input bristol-fashion/circuits/sha256.txt --output sha256_sieve.txt --format text
