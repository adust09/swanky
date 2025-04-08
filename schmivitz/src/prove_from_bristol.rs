//! Implementation of Bristol circuit proofs for VOLE-in-the-head.
//!
//! This module provides functionality to prove and verify computations from Bristol format circuits
//! using the VOLE-in-the-head protocol. It supports flexible circuit and input specification.

use clap::{App, Arg, SubCommand};
use eyre::{bail, Result};
use mac_n_cheese_sieve_parser::text_parser::RelationReader;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use std::{
    env,
    fs::File,
    io::{BufReader, Cursor, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use bristol_2_sieve::transpile;

use crate::{vole::insecure::InsecureVole, Proof};

/// Preprocesses the circuit file to make it compatible with the Schmivitz library.
///
/// # Arguments
///
/// * `circuit_path` - Path to the circuit file
///
/// # Returns
///
/// A cursor containing the preprocessed circuit data
fn preprocess_circuit<P: AsRef<Path>>(circuit_path: P) -> Result<Cursor<Vec<u8>>> {
    // Open and read the file
    let file = File::open(circuit_path)?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;

    // Create a Sieve format header
    let sieve_header = "version 2.0.0;\ncircuit;\n@type field 2;\n@begin\n";

    // Create a Sieve format footer
    let sieve_footer = "\n@end\n";

    // Extract the circuit content (without header and footer if they exist)
    let mut circuit_content = contents;
    if circuit_content.contains("@begin") {
        if let Some(begin_pos) = circuit_content.find("@begin") {
            if let Some(begin_end_pos) = circuit_content[begin_pos..].find('\n') {
                circuit_content = circuit_content[(begin_pos + begin_end_pos + 1)..].to_string();
            }
        }
    }
    // More robust handling of @end tag
    if circuit_content.contains("@end") {
        if let Some(end_pos) = circuit_content.find("@end") {
            // Remove everything from @end onwards
            circuit_content = circuit_content[..end_pos].to_string();
            // Ensure the content ends with a newline
            if !circuit_content.ends_with('\n') {
                circuit_content.push('\n');
            }
        }
    }

    // Combine header, content, and footer
    let processed_content = format!("{}{}{}", sieve_header, circuit_content, sieve_footer);

    // Create a cursor with the processed content
    let cursor = Cursor::new(processed_content.into_bytes());

    Ok(cursor)
}

/// Loads the circuit from the provided file path and validates its format.
///
/// # Arguments
///
/// * `circuit_path` - Path to the sieve output file
///
/// # Returns
///
/// A cursor containing the circuit data
fn load_sieve_circuit<P: AsRef<Path>>(circuit_path: P) -> Result<Cursor<Vec<u8>>> {
    // Preprocess the circuit file
    let mut cursor = preprocess_circuit(circuit_path)?;

    // Validate the circuit format by attempting to create a RelationReader
    let _reader = match RelationReader::new(cursor.clone()) {
        Ok(reader) => reader,
        Err(e) => {
            bail!("Failed to parse circuit: {}", e);
        }
    };

    // Reset cursor position for later use
    cursor.seek(SeekFrom::Start(0))?;

    Ok(cursor)
}

/// Proves a computation using the VOLE-in-the-head protocol.
///
/// # Arguments
///
/// * `circuit_path` - Path to the sieve output file
/// * `private_input_path` - Path to the private input file
/// * `rng` - Random number generator
///
/// # Returns
///
/// A proof of the computation
pub fn prove_sieve<R, P1, P2>(
    circuit_path: P1,
    private_input_path: P2,
    rng: &mut R,
) -> Result<Proof<InsecureVole>>
where
    R: CryptoRng + RngCore,
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    // Load and validate the circuit
    let mut circuit = load_sieve_circuit(circuit_path)?;

    // Create a new transcript
    let mut transcript = Transcript::new(b"bristol_circuit_proof");

    // Generate the proof
    Proof::prove(
        &mut circuit,
        private_input_path.as_ref(),
        &mut transcript,
        rng,
    )
}

/// Verifies a computation proof.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `circuit_path` - Path to the sieve output file
///
/// # Returns
///
/// Result indicating whether the proof is valid
pub fn verify_sieve<P: AsRef<Path>>(proof: &Proof<InsecureVole>, circuit_path: P) -> Result<()> {
    // Load and validate the circuit
    let mut circuit = load_sieve_circuit(circuit_path)?;

    // Create a new transcript
    let mut transcript = Transcript::new(b"bristol_circuit_proof");

    // Verify the proof
    proof.verify(&mut circuit, &mut transcript)
}
/// Executes a complete prove and verify cycle for a Bristol format circuit.
///
/// This function demonstrates how to use the proof system with a Bristol format circuit:
/// 1. Converts the Bristol format circuit to Sieve format
/// 2. Generates a proof using the converted circuit and private input
/// 3. Verifies the generated proof
///
/// # Arguments
///
/// * `bristol_path` - Path to the Bristol format circuit file
/// * `private_input_path` - Path to the private input file
/// * `rng` - Random number generator
///
/// # Returns
///
/// Result indicating whether the proof was successfully generated and verified
pub fn prove_and_verify_bristol<R, P1, P2>(
    bristol_path: P1,
    private_input_path: P2,
    rng: &mut R,
) -> Result<()>
where
    R: CryptoRng + RngCore,
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    // Create a temporary directory for the converted circuit
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let converted_circuit_path = output_dir.join("converted_circuit.txt");

    // Convert the Bristol format to Sieve format
    transpile(bristol_path, &converted_circuit_path)?;

    // Execute the prove and verify cycle
    let proof = prove_sieve(&converted_circuit_path, private_input_path, rng)?;
    let result = verify_sieve(&proof, converted_circuit_path);
    result
}

/// Command-line interface for proving and verifying Bristol format circuits.
///
/// This function parses command-line arguments and executes the appropriate actions.
///
/// # Returns
///
/// Result indicating whether the operation was successful
pub fn cli_main() -> Result<()> {
    let matches = App::new("Bristol Circuit Prover")
        .version("1.0")
        .author("Swanky Team")
        .about("Proves and verifies computations using Bristol format circuits")
        .subcommand(
            SubCommand::with_name("prove")
                .about("Proves a computation using a Bristol format circuit")
                .arg(
                    Arg::with_name("bristol_path")
                        .short("b")
                        .long("bristol")
                        .value_name("FILE")
                        .help("Path to the Bristol format circuit file")
                        .required(true),
                )
                .arg(
                    Arg::with_name("private_input_path")
                        .short("p")
                        .long("private-input")
                        .value_name("FILE")
                        .help("Path to the private input file")
                        .required(true),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("prove") {
        let bristol_path = matches.value_of("bristol_path").unwrap();
        let private_input_path = matches.value_of("private_input_path").unwrap();

        println!("Using Bristol circuit: {}", bristol_path);
        println!("Using private input: {}", private_input_path);

        // Create a random number generator
        let mut rng = rand::thread_rng();

        // Execute the prove and verify cycle
        prove_and_verify_bristol(bristol_path, private_input_path, &mut rng)?;
        println!("Proof successfully generated and verified!");
    } else {
        println!("No subcommand specified. Use --help for usage information.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use std::fs;
    #[test]
    fn test_bristol_to_sieve_conversion() -> Result<()> {
        // Paths to the test files
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let bristol_path = project_root.join("bristol-fashion/circuits/Keccak_f.txt");

        // Create a temporary output path
        let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let output_path = output_dir.join("test_converted_circuit.txt");

        // Convert the Bristol format to Sieve format
        transpile(bristol_path, &output_path)?;

        // Verify that the output file exists
        assert!(output_path.exists());

        // Clean up the output file
        fs::remove_file(output_path)?;

        Ok(())
    }

    #[test]
    fn test_keccak_f_bristol_proof() -> Result<()> {
        // Paths to the test files
        let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let bristol_path = project_root.join("bristol-fashion/circuits/Keccak_f.txt");
        let private_input_path = project_root.join("bristol_2_sieve/src/keccak_private_input.txt");

        // Create a random number generator
        let mut rng = thread_rng();

        // Execute the prove and verify cycle with the Bristol circuit
        prove_and_verify_bristol(bristol_path, private_input_path, &mut rng)
    }
}
