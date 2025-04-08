# Bristol to Sieve Transpiler

A tool for compiling Bristol Fashion circuits to SIEVE IR format, enabling the use of Bristol Fashion circuits with zero-knowledge proof systems like schmivitz.

## Installation

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
bristol2sieve = { path = "../bristol2sieve" }
```

## Command-line Usage

To convert a Bristol Fashion circuit to SIEVE IR format using the command-line tool:

```bash
cargo run --bin bristol2sieve -- transpile -i path/to/bristol_circuit.txt -o path/to/output_sieve_circuit.txt
```

### Command-line Options

```
USAGE:
    bristol2sieve transpile --input <FILE> --output <FILE> [--format <FORMAT>]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -i, --input <FILE>      Input Bristol Fashion circuit file
    -o, --output <FILE>     Output SIEVE IR file
    -f, --format <FORMAT>   Output format (text or binary) [default: text]
```

## Programmatic Usage

You can also use the library programmatically in your Rust code:

### Simple Usage

```rust
use bristol2sieve::transpile;
use eyre::Result;

fn main() -> Result<()> {
    // Specify paths to your Bristol circuit and output Sieve file
    let bristol_path = "path/to/your/circuit.txt";
    let sieve_output_path = "path/to/output/sieve_circuit.txt";
    
    // Convert Bristol format to Sieve format
    transpile(bristol_path, sieve_output_path)?;
    
    println!("Circuit successfully converted to Sieve format!");
    Ok(())
}
```

### Advanced Usage

If you need more control over the conversion process, you can use the lower-level API:

```rust
use bristol2sieve::transpiler::{BristolCircuit, SieveCircuit};
use eyre::Result;

fn main() -> Result<()> {
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

## Integration with Schmivitz

The bristol2sieve transpiler can be used together with the schmivitz library to prove and verify computations using Bristol format circuits:

```rust
use bristol2sieve::transpile;
use schmivitz::prove_and_verify_bristol;
use rand::thread_rng;
use eyre::Result;

fn main() -> Result<()> {
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
