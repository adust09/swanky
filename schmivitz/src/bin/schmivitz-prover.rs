use eyre::{eyre, Result};
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{vole::insecure::InsecureVole, Proof};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::process::exit;
use swanky_serialization::Serialize;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut circuit_path = None;
    let mut private_path = None;
    let mut output_path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--circuit" => {
                i += 1;
                if i < args.len() {
                    circuit_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--private" => {
                i += 1;
                if i < args.len() {
                    private_path = Some(PathBuf::from(&args[i]));
                }
            }
            "--output" => {
                i += 1;
                if i < args.len() {
                    output_path = Some(PathBuf::from(&args[i]));
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

    let private_path = private_path.ok_or_else(|| {
        print_usage();
        eyre!("Missing --private argument")
    })?;

    let output_path = output_path.ok_or_else(|| {
        print_usage();
        eyre!("Missing --output argument")
    })?;

    // Load the circuit
    println!("Loading circuit from {}", circuit_path.display());
    let mut circuit_file = File::open(circuit_path)?;

    // Initialize transcript
    println!("Initializing transcript...");
    let mut transcript = Transcript::new(b"keccak-vole-in-the-head");

    // Initialize RNG
    println!("Initializing RNG...");
    let mut rng = thread_rng();

    // Generate the proof
    println!("Generating proof...");
    let proof =
        Proof::<InsecureVole>::prove(&mut circuit_file, &private_path, &mut transcript, &mut rng)?;

    // Write the proof to the output file
    println!("Writing proof to {}", output_path.display());
    let output_file = File::create(output_path)?;
    let mut writer = BufWriter::new(output_file);
    proof.serialize(&mut writer)?;
    writer.flush()?;

    println!("Proof generation complete!");
    Ok(())
}

fn print_usage() {
    eprintln!("Usage: schmivitz-prover --circuit <circuit_file> --private <private_input_file> --output <output_file>");
}
