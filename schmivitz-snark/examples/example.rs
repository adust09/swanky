use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use arkworks_solidity_verifier::SolidityVerifier;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{
    f128b_to_ark, f64b_to_ark, f8b_to_ark, PartialDecommitmentVar, TranscriptWrapper,
    VoleVerification,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};
use swanky_field_binary::{F128b, F8b};
use tempfile::tempdir;

fn main() -> Result<()> {
    // target circuit
    let circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
            $0 ... $1 <- @private(0);
            $2 <- @add(0: $0, $1);
        @end";
    let circuit = Cursor::new(circuit_bytes.as_bytes());

    let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 0 >;
        @end";

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

    let mut test_verify_transcript = Transcript::new(b"schmivitz-snark");
    assert!(schmivitz_proof
        .verify(&mut circuit.clone(), &mut test_verify_transcript)
        .is_ok());

    // circuit_specific_setupでpanicが発生するが、rollup.rsとの差分はこのbuildingの部分だけ
    let circuit_defining_cs = build_circuit(schmivitz_proof.clone());

    let mut rng = ark_std::test_rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();

    let solidity_verifier = Groth16::<Bn254>::export(&vk);
    let output_dir = Path::new("solidity_output");
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }
    let output_path = output_dir.join("vole_verifier.sol");
    fs::write(&output_path, solidity_verifier)?;
    println!("Solidity verifier generated at: {}", output_path.display());

    let circuit_to_verify_against = build_circuit(schmivitz_proof.clone());
    let public_input = vec![
        circuit_to_verify_against.degree_0_commitment.unwrap(),
        circuit_to_verify_against.degree_1_commitment.unwrap(),
        circuit_to_verify_against
            .partial_decommitment
            .verifier_key
            .unwrap(),
    ];

    let snark_proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng)?;
    let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

    println!(
        "Verified SNARK proof: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    Ok(())
}

fn build_circuit(schmivitz_proof: Proof<InsecureVole>) -> VoleVerification {
    let mut transcript = Transcript::new(b"schmivitz-snark");
    let mut transcript_wrapper = TranscriptWrapper::from(&mut transcript);

    transcript_wrapper.append_public_values();

    // let witness_commitment_ark: Vec<Bn254Fr> = schmivitz_proof
    //     .witness_commitment
    //     .iter()
    //     .map(f64b_to_ark)
    //     .collect();
    // transcript_wrapper.append_witness_commitment(&witness_commitment_ark);

    // Extract witness challenges from the transcript
    // This ensures challenges are derived deterministically from the transcript
    let expected_witness_challenges =
        transcript_wrapper.extract_witness_challenges(schmivitz_proof.witness_challenges.len());

    // println!(
    //     "witness_challenges.len: {:?} \n",
    //     expected_witness_challenges.len()
    // );

    // Append polynomial commitments to continue the transcript
    // transcript_wrapper.append_polynomial_commitments(
    //     f128b_to_ark(&schmivitz_proof.degree_0_commitment),
    //     f128b_to_ark(&schmivitz_proof.degree_1_commitment),
    // );
    // convert vole to arkworks variants
    VoleVerification {
        // vole_challenge(missed but only used in outside of verification logic)
        witness_commitment: Some(
            schmivitz_proof
                .witness_commitment
                .iter()
                .map(f64b_to_ark)
                .collect(),
        ),
        witness_challenges: Some(expected_witness_challenges),
        degree_0_commitment: Some(f128b_to_ark(&schmivitz_proof.degree_0_commitment)),
        degree_1_commitment: Some(f128b_to_ark(&schmivitz_proof.degree_1_commitment)),
        // decommitment_challenge(missed but only used in outside of verification logic)
        partial_decommitment: PartialDecommitmentVar {
            verifier_key: Some(f128b_to_ark(
                &schmivitz_proof.partial_decommitment.verifier_key(),
            )),
            mask_voles: Some(
                schmivitz_proof
                    .partial_decommitment
                    .mask_voles()
                    .iter()
                    .map(|arg0: &F128b| f128b_to_ark(arg0))
                    .collect(),
            ),
            witness_voles: Some(
                schmivitz_proof
                    .partial_decommitment
                    .witness_voles()
                    .iter()
                    .flat_map(|arr| arr.iter().copied().map(|value: F8b| f8b_to_ark(&value)))
                    .collect(),
            ),
        },
    }
}
