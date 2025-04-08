# bristol-2-sieve

bristol-2-sieve is a tool for converting circuits from Bristol Fashion format to SIEVE IR format, enabling their use with the schmivitz zero-knowledge proof system. It focuses particularly on compiling Keccak_f circuits and generating/verifying proofs.

## Overview

bristol-2-sieve provides the following functionality:

1. Converting circuits from Bristol Fashion format to SIEVE IR format
2. Specially optimized compilation of Keccak_f circuits
3. Integration with the schmivitz VOLE-in-the-head zero-knowledge proof system

This tool is designed to efficiently generate zero-knowledge proofs for cryptographic circuits, especially Keccak_f.

## Installation

### Prerequisites

- Rust 2021 Edition or later
- Cargo

### Installation Steps

Clone the repository and build using Cargo:

```bash
git clone <repository-url>
cd swanky
cargo build --release -p bristol2sieve
```

## Usage

bristol-2-sieve can be used as a command-line tool. There are two main commands:

### 1. Compiling Keccak_f Circuit

Compile the Keccak_f circuit from Bristol Fashion format to SIEVE IR format:

```bash
./target/release/bristol2sieve compile
```

This command generates the following files:
- `keccak_f.bin` - The compiled circuit
- `keccak_f.priv.bin` - Private input data

### 2. Transpiling Any Bristol Fashion Circuit

Convert any Bristol Fashion circuit to SIEVE IR format:

```bash
./target/release/bristol2sieve transpile --input <input-file> --output <output-file> [--format <text|binary>]
```

Parameters:
- `--input` or `-i`: Input Bristol Fashion circuit file
- `--output` or `-o`: Output SIEVE IR file
- `--format` or `-f`: Output format (`text` or `binary`, default is `text`)

Example:

```bash
./target/release/bristol2sieve transpile --input bristol-fashion/circuits/sha256.txt --output sha256.sieve --format text
```

## Supported Gates

bristol-2-sieve supports the following gates:

- XOR gates (converted to `add` gates in SIEVE IR)
- AND gates (converted to `mul` gates in SIEVE IR)
- INV gates (converted to `add` gates with a constant 1 wire)

## Technical Details

### Conversion Process

1. Parsing Bristol Fashion Circuit
   - Parsing header information (number of gates, wires, inputs, outputs)
   - Parsing each gate definition

2. Creating SIEVE IR Circuit
   - Generating SIEVE IR header with appropriate type information (field F2)
   - Creating a constant 1 wire for INV operations (using private input)
   - Converting each gate according to mapping rules
   - Handling input and output wires appropriately

3. Outputting SIEVE IR
   - Generating SIEVE IR text representation
   - Optionally converting to flatbuffer binary format

### Gate Mapping

| Bristol Fashion Gate | SIEVE IR Equivalent | Implementation |
|---------------------|---------------------|----------------|
| XOR { a, b, out }   | add                 | `$out <- @add(0: $a, $b)` |
| AND { a, b, out }   | mul                 | `$out <- @mul(0: $a, $b)` |
| INV { a, out }      | add with constant 1 | `$out <- @add(0: $a, $one_wire)` |

## Limitations

- EQ and EQW gates are not directly supported
- The conversion process may take time for large circuits (such as SHA-256 and Keccak-f)

## Contributing

Contributions to the project are welcome. Please feel free to submit bug reports, feature requests, or pull requests.

## License

This project is licensed under [project license].
