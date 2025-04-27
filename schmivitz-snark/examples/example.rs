use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::Groth16;
use ark_snark::SNARK;
use arkworks_solidity_verifier::SolidityVerifier;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{
    insecure::InsecureVole,
    parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM},
    Proof,
};
use schmivitz_snark::{
    convert_proof, f128b_to_ark, f64b_to_ark, f8b_to_ark, PartialDecommitmentVar,
    TranscriptWrapper, VoleProof, VoleVerification,
};
use serde_json;
use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};
use swanky_field_binary::{F128b, F8b};
use tempfile::tempdir;

fn main() -> Result<()> {
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

    let mut transcript = Transcript::new(b"schmivitz-snark example");
    let rng = &mut thread_rng();
    let schmivitz_proof: Proof<InsecureVole> = Proof::<InsecureVole>::prove(
        &mut circuit.clone(),
        &private_input_path,
        &mut transcript,
        rng,
    )?;
    let vole_proof = convert_proof(&schmivitz_proof)?;
    let proof_json = serde_json::to_string_pretty(&vole_proof)?;
    fs::write("proof.json", proof_json)?;
    validate_proof(vole_proof.clone())?;
    let circuit_defining_cs = build_circuit(vole_proof.clone());

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

    let circuit_to_verify_against = build_circuit(vole_proof.clone());
    let public_input = vec![
        circuit_to_verify_against.degree_0_commitment,
        circuit_to_verify_against.degree_1_commitment,
        circuit_to_verify_against.partial_decommitment.verifier_key,
    ];

    let snark_proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng)?;
    let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

    println!(
        "Verified SNARK proof: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    Ok(())
}

fn build_circuit(vole_proof: VoleProof) -> VoleVerification {
    let mut transcript = Transcript::new(b"schmivitz-snark");
    let mut transcript_wrapper = TranscriptWrapper::from(&mut transcript);

    transcript_wrapper.append_public_values();

    let witness_commitment_ark: Vec<Bn254Fr> = vole_proof
        .witness_commitment
        .iter()
        .map(f64b_to_ark)
        .collect();
    transcript_wrapper.append_witness_commitment(&witness_commitment_ark);

    // Extract witness challenges from the transcript
    // This ensures challenges are derived deterministically from the transcript
    let witness_challenges =
        transcript_wrapper.extract_witness_challenges(vole_proof.witness_challenges.len());

    // Append polynomial commitments to continue the transcript
    transcript_wrapper.append_polynomial_commitments(
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
    );
    VoleVerification {
        // Public Inputs
        degree_0_commitment: f128b_to_ark(&vole_proof.degree_0_commitment),
        degree_1_commitment: f128b_to_ark(&vole_proof.degree_1_commitment),
        // Private Inputs
        witness_commitment: vole_proof
            .witness_commitment
            .iter()
            .map(f64b_to_ark)
            .collect(),
        partial_decommitment: PartialDecommitmentVar {
            verifier_key: f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
            mask_voles: vole_proof
                .partial_decommitment
                .mask_voles()
                .iter()
                .map(|arg0: &F128b| f128b_to_ark(arg0))
                .collect(),
            witness_voles: vole_proof
                .partial_decommitment
                .witness_voles()
                .iter()
                .flat_map(|arr| arr.iter().copied().map(|value: F8b| f8b_to_ark(&value)))
                .collect(),
        },
        witness_challenges,
    }
}

fn validate_proof(vole_proof: VoleProof) -> Result<()> {
    // Validate the proof
    println!(
        "witness_commitment: {:?}",
        vole_proof.witness_commitment.len()
    );
    println!(
        "partial_decommitment: {:?}",
        vole_proof.partial_decommitment.witness_voles().len()
    );
    println!(
        "witness_challenge: {:?}",
        vole_proof.witness_challenges.len()
    );
    if vole_proof.witness_commitment.len() != vole_proof.partial_decommitment.witness_voles().len()
    {
        return Err(eyre::eyre!(
            "Invalid proof: Did not commit to the same number of witnesses {} as there are VOLEs {}",
            vole_proof.witness_commitment.len(),
            vole_proof.partial_decommitment.witness_voles().len()
        ));
    }
    if vole_proof.witness_challenges.len() > vole_proof.witness_commitment.len() {
        return Err(eyre::eyre!(
            "Invalid proof: More challenges {} than we have witnesses to commit to {}",
            vole_proof.witness_challenges.len(),
            vole_proof.witness_commitment.len()
        ));
    }

    let expected_commitment =
        vole_proof.partial_decommitment.witness_voles().len() + REPETITION_PARAM * VOLE_SIZE_PARAM;
    if vole_proof.witness_commitment.len() != expected_commitment {
        return Err(eyre::eyre!(
            "Invalid proof: Expected {} witness commitments, but got {}",
            expected_commitment,
            vole_proof.witness_commitment.len()
        ));
    }

    Ok(())
}
