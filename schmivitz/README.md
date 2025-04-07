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
bristol_prover prove --bristol bristol_2_sieve/src/keccak_f.txt --private-input bristol_2_sieve/src/keccak_private_input.txt
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
use bristol_2_sieve::transpile;

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
use bristol_2_sieve::transpiler::{BristolCircuit, SieveCircuit};

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

## 日本語での使用方法

### Bristol回路証明ツール

Schmivitzは、Bristol形式の回路を使用して計算を証明および検証するためのコマンドラインツールを含んでいます。このツールを使用すると、ユーザーは異なる回路とプライベート入力を柔軟に指定できます。

### インストール

> **注意:** CLIツールはリポジトリに含まれていない場合があります（.gitignoreに追加されている場合）。含まれていない場合は、上記の「Enabling CLI Functionality」セクションの手順に従って有効にしてください。

ツールをビルドするには、次のコマンドを実行します：

```bash
cargo build --bin bristol_prover
```

### 使用方法

基本的な使用パターンは次のとおりです：

```bash
bristol_prover prove --bristol <Bristol回路ファイルへのパス> --private-input <プライベート入力ファイルへのパス>
```

#### コマンドラインオプション

```
使用法:
    bristol_prover prove --bristol <ファイル> --private-input <ファイル>

フラグ:
    -h, --help       ヘルプ情報を表示
    -V, --version    バージョン情報を表示

オプション:
    -b, --bristol <ファイル>          Bristol形式の回路ファイルへのパス
    -p, --private-input <ファイル>    プライベート入力ファイルへのパス
```

### 例

Keccak-F回路を使用して計算を証明するには：

```bash
bristol_prover prove --bristol bristol_2_sieve/src/keccak_f.txt --private-input bristol_2_sieve/src/keccak_private_input.txt
```

### プログラムでの使用

Rustコードでライブラリをプログラム的に使用することもできます：

```rust
use schmivitz::prove_and_verify_bristol;
use rand::thread_rng;

fn main() -> eyre::Result<()> {
    let mut rng = thread_rng();
    
    // Bristol回路とプライベート入力へのパスを指定
    let bristol_path = "path/to/your/circuit.txt";
    let private_input_path = "path/to/your/private_input.txt";
    
    // 証明と検証のサイクルを実行
    prove_and_verify_bristol(bristol_path, private_input_path, &mut rng)?;
    
    println!("証明が正常に生成され、検証されました！");
    Ok(())
}
```

### Bristol から Sieve へのトランスパイラの使用

Rustコードで Bristol から Sieve へのトランスパイラを直接使用することもできます：

```rust
use bristol_2_sieve::transpile;

fn main() -> eyre::Result<()> {
    // Bristol回路と出力Sieveファイルへのパスを指定
    let bristol_path = "path/to/your/circuit.txt";
    let sieve_output_path = "path/to/output/sieve_circuit.txt";
    
    // Bristol形式からSieve形式に変換
    transpile(bristol_path, sieve_output_path)?;
    
    println!("回路がSieve形式に正常に変換されました！");
    Ok(())
}
```

変換プロセスをより詳細に制御する必要がある場合は、低レベルAPIを使用できます：

```rust
use bristol_2_sieve::transpiler::{BristolCircuit, SieveCircuit};

fn main() -> eyre::Result<()> {
    // Bristol Fashion回路を解析
    let bristol = BristolCircuit::from_file("path/to/your/circuit.txt")?;
    
    // SIEVE IRに変換
    let sieve = SieveCircuit::from_bristol(&bristol)?;
    
    // SIEVE IRをファイルに書き込み
    sieve.to_file("path/to/output/sieve_circuit.txt")?;
    
    println!("回路がSieve形式に正常に変換されました！");
    Ok(())
}
```
