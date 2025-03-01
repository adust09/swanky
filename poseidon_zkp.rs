use eyre::{eyre, Result};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    println!("Poseidon Hash Zero-Knowledge Proof System");
    println!("=========================================");

    // Step 1: Create input files for the proof
    println!("Step 1: Creating input files for the proof...");
    create_input_files()?;

    // Step 2: Compile the SIEVE IR circuit with mac-n-cheese
    println!("Step 2: Compiling the SIEVE IR circuit with mac-n-cheese...");
    compile_circuit()?;

    // Step 3: Generate the VOLE-in-the-Head zero-knowledge proof
    println!("Step 3: Generating the VOLE-in-the-Head zero-knowledge proof...");
    generate_proof()?;

    // Step 4: Verify the VOLE-in-the-Head zero-knowledge proof
    println!("Step 4: Verifying the VOLE-in-the-Head zero-knowledge proof...");
    verify_proof()?;

    println!("Done! The Poseidon hash function defined in poseidon.txt has been used to generate and verify a VOLE-in-the-Head zero-knowledge proof.");
    Ok(())
}

fn create_input_files() -> Result<()> {
    // Create a sample public input file
    let public_input = r#"version 2.0.0;
public_input;
@type field 21888242871839275222246405745257275088548364400416034343698204186575808495617;
@begin
    <0>; # Expected output hash
@end"#;

    fs::write("poseidon_public.txt", public_input)?;
    println!("  Created poseidon_public.txt");

    // Create a sample private input file with 3 field elements as input
    let private_input = r#"version 2.0.0;
private_input;
@type field 21888242871839275222246405745257275088548364400416034343698204186575808495617;
@begin
    <1>; # First input element
    <2>; # Second input element
    <3>; # Third input element
@end"#;

    fs::write("poseidon_private.txt", private_input)?;
    println!("  Created poseidon_private.txt");

    Ok(())
}

fn compile_circuit() -> Result<()> {
    // Check if poseidon.txt exists
    if !Path::new("poseidon.txt").exists() {
        return Err(eyre!("poseidon.txt not found"));
    }

    // Use diet-mac-and-cheese to compile the circuit
    let status = std::process::Command::new("cargo")
        .args([
            "run",
            "--manifest-path=diet-mac-and-cheese/Cargo.toml",
            "--bin",
            "dietmc",
            "--",
            "--relation",
            "poseidon.txt",
            "--instance",
            "poseidon_public.txt",
            "--witness",
            "poseidon_private.txt",
            "--text",
            "--output",
            "poseidon_compiled.bin",
        ])
        .status()?;

    if !status.success() {
        return Err(eyre!("Failed to compile the circuit"));
    }

    println!("  Circuit compiled to poseidon_compiled.bin");
    Ok(())
}

fn generate_proof() -> Result<()> {
    // Load the circuit
    let circuit_path = PathBuf::from("poseidon_compiled.bin");
    let private_path = PathBuf::from("poseidon_private.txt");

    println!("  Loading circuit from {}", circuit_path.display());
    let mut circuit_file = File::open(circuit_path)?;

    // Initialize transcript
    println!("  Initializing transcript...");
    let mut transcript = Transcript::new(b"poseidon-vole-in-the-head");

    // Initialize RNG
    println!("  Initializing RNG...");
    let mut rng = thread_rng();

    // Generate the proof
    println!("  Generating proof...");
    let proof =
        Proof::<InsecureVole>::prove(&mut circuit_file, &private_path, &mut transcript, &mut rng)?;

    // For now, we'll just print that the proof was generated
    // In a real implementation, you would need to properly serialize the proof
    println!("  Proof generated successfully");

    println!("  Proof generation complete!");
    Ok(())
}

fn verify_proof() -> Result<()> {
    // In a real implementation, you would deserialize the proof here
    // For now, we'll just generate a new proof for demonstration purposes

    // Load the circuit
    let circuit_path = PathBuf::from("poseidon_compiled.bin");
    let private_path = PathBuf::from("poseidon_private.txt");

    println!("  Note: In this demo, we're generating a new proof for verification");
    println!("  In a real implementation, you would deserialize the proof from a file");

    // Generate a proof for verification
    let mut circuit_file = File::open(&circuit_path)?;
    let mut transcript_for_prove = Transcript::new(b"poseidon-vole-in-the-head");
    let mut rng = thread_rng();
    let proof = Proof::<InsecureVole>::prove(
        &mut circuit_file,
        &private_path,
        &mut transcript_for_prove,
        &mut rng,
    )?;

    // Initialize transcript for verification
    println!("  Initializing transcript...");
    let mut transcript = Transcript::new(b"poseidon-vole-in-the-head");

    // Verify the proof
    println!("  Verifying proof...");
    let mut circuit_file = File::open(circuit_path)?;
    match proof.verify(&mut circuit_file, &mut transcript) {
        Ok(_) => {
            println!("  Proof verification successful!");
            Ok(())
        }
        Err(e) => {
            println!("  Proof verification failed: {}", e);
            Err(eyre!("Proof verification failed"))
        }
    }
}
