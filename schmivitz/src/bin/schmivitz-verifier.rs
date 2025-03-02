use eyre::{eyre, Result};
use merlin::Transcript;
use schmivitz::{vole::insecure::InsecureVole, Proof};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::process::exit;
use swanky_serialization::Deserialize;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut circuit_path = None;
    let mut proof_path = None;
    let mut public_path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--circuit" => {
                i += 1;
                if i < args.len() {
                    circuit_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--proof" => {
                i += 1;
                if i < args.len() {
                    proof_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--public" => {
                i += 1;
                if i < args.len() {
                    public_path = Some(PathBuf::from(&args[i]));
                }
            }
            _ => {
                eprintln!("Unknown argument: {}", args[i]);
                print_usage();
                exit(1);
            }
        }
        i += 1;
    }

    let circuit_path = circuit_path.ok_or_else(|| {
        print_usage();
        eyre!("Missing --circuit argument")
    })?;

    let proof_path = proof_path.ok_or_else(|| {
        print_usage();
        eyre!("Missing --proof argument")
    })?;

    let public_path = public_path.ok_or_else(|| {
        print_usage();
        eyre!("Missing --public argument")
    })?;

    // Load the circuit
    println!("Loading circuit from {}", circuit_path.display());
    let mut circuit_file = File::open(circuit_path)?;

    // Load the proof
    println!("Loading proof from {}", proof_path.display());
    let proof_file = File::open(proof_path)?;
    let proof_reader = BufReader::new(proof_file);
    let proof = Proof::<InsecureVole>::deserialize(proof_reader)?;

    // Initialize transcript
    println!("Initializing transcript...");
    let mut transcript = Transcript::new(b"keccak-vole-in-the-head");

    // Verify the proof
    println!("Verifying proof...");
    match proof.verify(&mut circuit_file, &mut transcript) {
        Ok(_) => {
            println!("Proof verification successful!");
            Ok(())
        }
        Err(e) => {
            println!("Proof verification failed: {}", e);
            Err(eyre!("Proof verification failed"))
        }
    }
}

fn print_usage() {
    eprintln!("Usage: schmivitz-verifier --circuit <circuit_file> --proof <proof_file> --public <public_input_file>");
}
