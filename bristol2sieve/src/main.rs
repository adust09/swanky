// External dependencies
use clap::{Parser, Subcommand};
use eyre::{bail, Result};
use std::path::PathBuf;
// Internal modules
mod transpiler;

#[derive(Parser)]
#[command(name = "bristol2sieve")]
#[command(about = "Converts Bristol format circuits to SIEVE IR")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Transpile a Bristol Fashion circuit to SIEVE IR
    Transpile {
        /// Input Bristol Fashion circuit file
        #[arg(short, long)]
        input: PathBuf,

        /// Output SIEVE IR file
        #[arg(short, long)]
        output: PathBuf,

        /// Output format (text or binary)
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Transpile {
            input,
            output,
            format,
        } => {
            println!("Transpiling Bristol Fashion circuit to SIEVE IR...");
            println!("Input file: {}", input.display());
            println!("Output file: {}", output.display());

            if format != "text" && format != "binary" {
                bail!(
                    "Invalid output format: {}. Must be 'text' or 'binary'",
                    format
                );
            }

            // Transpile the circuit
            let bristol = transpiler::BristolCircuit::from_file(&input)?;
            let sieve = transpiler::SieveCircuit::from_bristol(&bristol)?;

            if format == "text" {
                // Output in text format
                sieve.to_file(&output)?;
                println!("Successfully transpiled circuit to SIEVE IR text format");
            } else {
                // Output in binary format using flatbuffers
                println!("Converting to binary format...");

                // For now, we'll output in text format and note that binary is a future enhancement
                sieve.to_file(&output)?;
                println!("Note: Binary format conversion will be implemented in a future update");
                println!("The circuit has been output in text format for now");
            }

            println!("Output file generated: {}", output.display());

            Ok(())
        }
    }
}
