use ark_bn254::Bn254;
use ark_bn254::Fr as Bn254Fr;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
use ark_snark::SNARK;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::build_circuit;
use std::{
    fs::{self, File},
    io::{Cursor, Write},
};
use tempfile::tempdir;
use tracing_subscriber::layer::SubscriberExt;

fn main() -> Result<()> {
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    // target circuit - read from circuit.txt
    let circuit_str = fs::read_to_string("schmivitz-snark/examples/circuit.txt")?;
    let circuit = Cursor::new(circuit_str.as_bytes());

    // read private input from private.txt
    let private_input_bytes = fs::read_to_string("schmivitz-snark/examples/private.txt")?;

    let dir = tempdir().unwrap();
    let private_input_path = dir.path().join("private_inputs");
    let mut private_input = File::create(private_input_path.clone()).unwrap();
    writeln!(private_input, "{}", private_input_bytes).unwrap();

    let mut transcript = Transcript::new(b"schmivitz-snark");
    let rng = &mut thread_rng();
    let schmivitz_proof: Proof<InsecureVole> = Proof::<InsecureVole>::prove(
        &mut circuit.clone(),
        &private_input_path,
        &mut transcript,
        rng,
    )?;

    // validate proof
    let mut test_verify_transcript = Transcript::new(b"schmivitz-snark");
    schmivitz_proof
        .verify(&mut circuit.clone(), &mut test_verify_transcript)
        .expect("Verification should succeed");

    // Create a constraint system for boolean conversions
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();

    // Build the circuit using boolean arrays
    let circuit = build_circuit(cs.clone(), schmivitz_proof.clone());
    println!("num of constraints{:?}", cs.num_constraints());

    let mut rng = ark_std::test_rng();
    println!("hoge");
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    let public_input = vec![];

    println!("hoge");
    let snark_proof = Groth16::prove(&pk, circuit, &mut rng)?;
    println!("hoge");
    let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

    println!(
        "Verified SNARK proof with boolean arrays: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    Ok(())
}
