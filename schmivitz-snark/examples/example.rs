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
    fs::{self},
    io::Cursor,
};
use tracing_subscriber::layer::SubscriberExt;

fn main() -> Result<()> {
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);

    let circuit_str = fs::read_to_string("schmivitz-snark/examples/circuit.txt")?;
    let circuit = Cursor::new(circuit_str.as_bytes());

    let private_input_path = std::path::Path::new("schmivitz-snark/examples/private.txt");

    let mut transcript = Transcript::new(b"schmivitz-snark");
    let rng = &mut thread_rng();
    let schmivitz_proof: Proof<InsecureVole> = Proof::<InsecureVole>::prove(
        &mut circuit.clone(),
        private_input_path,
        &mut transcript,
        rng,
    )?;

    let mut test_verify_transcript = Transcript::new(b"schmivitz-snark");
    schmivitz_proof
        .verify(&mut circuit.clone(), &mut test_verify_transcript)
        .expect("Verification should succeed");

    let cs = ConstraintSystem::<Bn254Fr>::new_ref();
    let circuit = build_circuit(cs.clone(), schmivitz_proof.clone());

    println!("num of constraints={:?}", cs.num_constraints());

    let mut rng = ark_std::test_rng();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    println!("num_constraints: {:?}", cs.num_constraints());
    println!("num_instance_variables: {:?}", cs.num_instance_variables());
    println!("num_witness_variables: {:?}", cs.num_witness_variables());

    let public_input = vec![];

    println!("Generating SNARK proof...");
    let snark_proof = Groth16::prove(&pk, circuit, &mut rng)?;
    println!("Verifying SNARK proof...");
    let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

    println!(
        "Verified SNARK proof : {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    Ok(())
}
