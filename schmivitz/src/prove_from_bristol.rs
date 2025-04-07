//! Implementation of Keccak-F function for VOLE-in-the-head proofs.
//!
//! This module provides functionality to prove and verify Keccak-F computations
//! using the VOLE-in-the-head protocol.

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

use crate::{vole::insecure::InsecureVole, Proof};
/// Converts a Bristol format circuit to a Sieve format circuit using the bristol_2_sieve command line tool.
///
/// # Arguments
///
/// * `bristol_path` - Path to the Bristol format circuit file
/// * `output_path` - Path to save the converted Sieve format circuit
///
/// # Returns
///
/// Result indicating whether the conversion was successful
pub fn convert_bristol_to_sieve<P1: AsRef<Path>, P2: AsRef<Path>>(
    bristol_path: P1,
    output_path: P2,
) -> Result<()> {
    // Get the absolute paths
    let bristol_path = bristol_path.as_ref().to_path_buf();
    let output_path = output_path.as_ref().to_path_buf();

    // Run the bristol_2_sieve command line tool
    let status = std::process::Command::new("cargo")
        .args([
            "run",
            "--bin",
            "bristol_2_sieve",
            "--",
            "transpile",
            "-i",
            &bristol_path.to_string_lossy(),
            "-o",
            &output_path.to_string_lossy(),
        ])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap())
        .status()?;

    if !status.success() {
        bail!("Failed to run bristol_2_sieve transpiler: {}", status);
    }

    Ok(())
}
/// Preprocesses the Keccak-F circuit file to make it compatible with the Schmivitz library.
///
/// # Arguments
///
/// * `circuit_path` - Path to the Keccak-F circuit file
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
    if circuit_content.contains("@end") {
        if let Some(end_pos) = circuit_content.find("@end") {
            circuit_content = circuit_content[..end_pos].to_string();
        }
    }

    // Combine header, content, and footer
    let processed_content = format!("{}{}{}", sieve_header, circuit_content, sieve_footer);

    // Create a cursor with the processed content
    let cursor = Cursor::new(processed_content.into_bytes());

    Ok(cursor)
}

/// Loads the Keccak-F circuit from the provided file path and validates its format.
///
/// # Arguments
///
/// * `circuit_path` - Path to the Keccak-F sieve output file
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

/// Proves a Keccak-F computation using the VOLE-in-the-head protocol.
///
/// # Arguments
///
/// * `circuit_path` - Path to the Keccak-F sieve output file
/// * `private_input_path` - Path to the private input file
/// * `rng` - Random number generator
///
/// # Returns
///
/// A proof of the Keccak-F computation
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
    // Load and validate the Keccak-F circuit
    let mut circuit = load_sieve_circuit(circuit_path)?;

    // Create a new transcript
    let mut transcript = Transcript::new(b"keccak_f_proof");

    // Generate the proof
    Proof::prove(
        &mut circuit,
        private_input_path.as_ref(),
        &mut transcript,
        rng,
    )
}

/// Verifies a Keccak-F computation proof.
///
/// # Arguments
///
/// * `proof` - The proof to verify
/// * `circuit_path` - Path to the Keccak-F sieve output file
///
/// # Returns
///
/// Result indicating whether the proof is valid
pub fn verify_keccak_f<P: AsRef<Path>>(proof: &Proof<InsecureVole>, circuit_path: P) -> Result<()> {
    // Load and validate the Keccak-F circuit
    let mut circuit = load_sieve_circuit(circuit_path)?;

    // Create a new transcript
    let mut transcript = Transcript::new(b"keccak_f_proof");

    // Verify the proof
    proof.verify(&mut circuit, &mut transcript)
}

/// Executes a complete prove and verify cycle for Keccak-F.
///
/// This function demonstrates how to use the Keccak-F proof system by:
/// 1. Generating a proof using the provided circuit and private input
/// 2. Verifying the generated proof
///
/// # Arguments
///
/// * `circuit_path` - Path to the Keccak-F sieve output file
/// * `private_input_path` - Path to the private input file
/// * `rng` - Random number generator
///
/// # Returns
///
/// Result indicating whether the proof was successfully generated and verified
pub fn prove_and_verify<R, P1, P2>(
    circuit_path: P1,
    private_input_path: P2,
    rng: &mut R,
) -> Result<()>
where
    R: CryptoRng + RngCore,
    P1: AsRef<Path>,
    P2: AsRef<Path>,
{
    // Generate the proof
    let proof = prove_sieve(&circuit_path, &private_input_path, rng)?;

    // Verify the proof
    verify_keccak_f(&proof, circuit_path)
}

/// Executes a complete prove and verify cycle for Keccak-F using the bristol_2_sieve circuit.
///
/// This function demonstrates how to use the Keccak-F proof system with the actual Keccak-F circuit:
/// 1. Converts the Bristol format circuit to Sieve format
/// 2. Generates a proof using the converted circuit and private input
/// 3. Verifies the generated proof
///
/// # Arguments
///
/// * `rng` - Random number generator
///
/// # Returns
///
/// Result indicating whether the proof was successfully generated and verified
pub fn prove_and_verify_bristol<R>(rng: &mut R) -> Result<()>
where
    R: CryptoRng + RngCore,
{
    // Paths to the Bristol format circuit and private input
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let bristol_path = project_root.join("bristol_2_sieve/src/keccak_f.txt");
    let private_input_path = project_root.join("bristol_2_sieve/src/keccak_private_input.txt");

    // Create a temporary directory for the converted circuit
    let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let converted_circuit_path = output_dir.join("converted_keccak_f.txt");

    // Convert the Bristol format to Sieve format
    convert_bristol_to_sieve(bristol_path, &converted_circuit_path)?;

    // Execute the prove and verify cycle
    let result = prove_and_verify(&converted_circuit_path, private_input_path, rng);

    // Don't clean up the temporary file for debugging
    // std::fs::remove_file(converted_circuit_path)?;

    result
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
        let bristol_path = project_root.join("bristol_2_sieve/src/keccak_f.txt");

        // Create a temporary output path
        let output_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let output_path = output_dir.join("converted_keccak_f.txt");

        // Convert the Bristol format to Sieve format
        convert_bristol_to_sieve(bristol_path, &output_path)?;

        // Verify that the output file exists
        assert!(output_path.exists());

        // Clean up the output file
        fs::remove_file(output_path)?;

        Ok(())
    }

    #[test]
    fn test_keccak_f_bristol_proof() -> Result<()> {
        // Create a random number generator
        let mut rng = thread_rng();

        // Execute the prove and verify cycle with the Bristol circuit
        prove_and_verify_bristol(&mut rng)
    }
}
