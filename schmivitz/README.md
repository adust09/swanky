# Schmivitz

A library for zero-knowledge protocols using VOLE-in-the-head.

## Bristol Circuit Prover

Schmivitz includes a command-line tool for proving and verifying computations using Bristol format circuits. This tool allows users to flexibly specify different circuits and private inputs.

> **Note:** The CLI functionality may not be included in the repository if it's been added to .gitignore. If you don't see the `src/bin/` directory, you can create it yourself following the instructions in the "Enabling CLI Functionality" section below.

### Installation

To build the tool, run:

```bash
cargo build --bin bristol_prover
```

### Usage

The basic usage pattern is:

```bash
bristol_prover prove --bristol <path_to_bristol_circuit> --private-input <path_to_private_input>
```

#### Command-line Options

```
USAGE:
    bristol_prover prove --bristol <FILE> --private-input <FILE>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -b, --bristol <FILE>          Path to the Bristol format circuit file
    -p, --private-input <FILE>    Path to the private input file
```

### Example

To prove a computation using the Keccak-F circuit:

```bash
bristol_prover prove --bristol bristol2sieve/src/keccak_f.txt --private-input bristol2sieve/src/keccak_private_input.txt
```

### Programmatic Usage

You can also use the library programmatically in your Rust code:

```rust
use schmivitz::prove_and_verify_bristol;
use rand::thread_rng;

fn main() -> eyre::Result<()> {
    let mut rng = thread_rng();
    
    // Specify paths to your Bristol circuit and private input
    let bristol_path = "path/to/your/circuit.txt";
    let private_input_path = "path/to/your/private_input.txt";
    
    // Execute the prove and verify cycle
    prove_and_verify_bristol(bristol_path, private_input_path, &mut rng)?;
    
    println!("Proof successfully generated and verified!");
    Ok(())
}
```

### Using the Bristol to Sieve Transpiler

You can also use the Bristol to Sieve transpiler directly in your Rust code:

```rust
use bristol2sieve::transpile;

fn main() -> eyre::Result<()> {
    // Specify paths to your Bristol circuit and output Sieve file
    let bristol_path = "path/to/your/circuit.txt";
    let sieve_output_path = "path/to/output/sieve_circuit.txt";
    
    // Convert Bristol format to Sieve format
    transpile(bristol_path, sieve_output_path)?;
    
    println!("Circuit successfully converted to Sieve format!");
    Ok(())
}
```

If you need more control over the conversion process, you can use the lower-level API:

```rust
use bristol2sieve::transpiler::{BristolCircuit, SieveCircuit};

fn main() -> eyre::Result<()> {
    // Parse Bristol Fashion circuit
    let bristol = BristolCircuit::from_file("path/to/your/circuit.txt")?;
    
    // Convert to SIEVE IR
    let sieve = SieveCircuit::from_bristol(&bristol)?;
    
    // Write SIEVE IR to file
    sieve.to_file("path/to/output/sieve_circuit.txt")?;
    
    println!("Circuit successfully converted to Sieve format!");
    Ok(())
}
```

## Library Features

Schmivitz implements a protocol defined by Baum et al. in _Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-head_. Specifically, it implements the zero-knowledge protocol for degree-2 relations over small- to medium-sized fields.

The name of this crate derives from the "cheesehead" hats traditionally worn by fans of the Packers football team. The Swiss-cheese-like holes in the hats are known as "Schmivitz".

## Enabling CLI Functionality

If the CLI functionality is not included in the repository (i.e., the `src/bin/` directory is missing), you can enable it by creating the following files:

1. Create the file `src/bin/bristol_prover.rs` with the following content:

```rust
//! Command-line interface for the Schmivitz library.
//!
//! This binary provides a command-line interface for proving and verifying
//! computations using Bristol format circuits.

use eyre::Result;
use schmivitz::cli_main;

fn main() -> Result<()> {
    cli_main()
}
```

2. Update `Cargo.toml` to include the binary target:

```toml
[[bin]]
name = "bristol_prover"
path = "src/bin/bristol_prover.rs"
```

After creating these files, you can build and run the CLI tool as described in the "Installation" section.
