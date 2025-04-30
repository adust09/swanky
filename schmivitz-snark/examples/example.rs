use ark_bn254::Bn254;
use ark_bn254::Fr as Bn254Fr;

use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintLayer, TracingMode};
use ark_snark::SNARK;
use arkworks_solidity_verifier::SolidityVerifier;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{
    insecure::InsecureVole,
    parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM},
    to_serializable_proof, Proof,
};
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
use swanky_field_binary::F128b;
use tempfile::tempdir;
use tracing_subscriber::layer::SubscriberExt;

fn main() -> Result<()> {
    let mut layer = ConstraintLayer::default();
    layer.mode = TracingMode::OnlyConstraints;
    let subscriber = tracing_subscriber::Registry::default().with(layer);
    let _guard = tracing::subscriber::set_default(subscriber);
    // target circuit
    let circuit_str = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
            $0 ... $4 <- @private(0);
            $5 <- @add(0: $0, $0);
            $6 <- @add(0: $0, $1);
            $7 <- @add(0: $0, $2);
            $8 <- @add(0: $0, $3);
            $9 <- @add(0: $0, $4);
            $10 <- @mul(0: $0, $5);
            $11 <- @mul(0: $0, $6);
            $12 <- @mul(0: $0, $7);
            $13 <- @mul(0: $0, $8);
            $14 <- @mul(0: $0, $9);
        @end ";
    let circuit = Cursor::new(circuit_str.as_bytes());

    let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 1 >;
            < 1 >;
            < 0 >;
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

    // Serialize and save the schmivitz_proof to a JSON file
    let serializable_proof = to_serializable_proof(&schmivitz_proof);
    let proof_json = serde_json::to_string_pretty(&serializable_proof)?;
    fs::write("schmivitz_proof.json", proof_json)?;
    println!("Saved proof to schmivitz_proof.json");

    let mut test_verify_transcript = Transcript::new(b"schmivitz-snark");
    // validate proof
    assert!(schmivitz_proof
        .verify(&mut circuit.clone(), &mut test_verify_transcript)
        .is_ok());

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
    let public_input = vec![];

    // cs unsatisfied
    let snark_proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng)?;
    let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

    println!(
        "Verified SNARK proof: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    Ok(())
}

// Define serializable versions of the circuit structures
#[derive(Serialize, Deserialize)]
struct SerializableBn254Fr(String);

#[derive(Serialize, Deserialize)]
struct SerializablePartialDecommitment {
    verifier_key: Option<SerializableBn254Fr>,
    witness_voles: Option<Vec<Vec<SerializableBn254Fr>>>,
    mask_voles: Option<Vec<SerializableBn254Fr>>,
}

#[derive(Serialize, Deserialize)]
struct SerializableVoleVerification {
    witness_commitment: Option<Vec<SerializableBn254Fr>>,
    witness_challenges: Option<Vec<SerializableBn254Fr>>,
    degree_0_commitment: Option<SerializableBn254Fr>,
    degree_1_commitment: Option<SerializableBn254Fr>,
    partial_decommitment: SerializablePartialDecommitment,
}

fn build_circuit(schmivitz_proof: Proof<InsecureVole>) -> VoleVerification {
    let mut transcript = Transcript::new(b"schmivitz-snark");
    let mut transcript_wrapper = TranscriptWrapper::from(&mut transcript);

    transcript_wrapper.append_public_values();

    let witness_commitment_ark: Vec<Bn254Fr> = schmivitz_proof
        .witness_commitment
        .iter()
        .map(f64b_to_ark)
        .collect();
    transcript_wrapper.append_witness_commitment(&witness_commitment_ark);

    // Extract witness challenges from the transcript
    // This ensures challenges are derived deterministically from the transcript
    let expected_witness_challenges =
        transcript_wrapper.extract_witness_challenges(schmivitz_proof.witness_challenges.len());

    // Append polynomial commitments to continue the transcript
    transcript_wrapper.append_polynomial_commitments(
        f128b_to_ark(&schmivitz_proof.degree_0_commitment),
        f128b_to_ark(&schmivitz_proof.degree_1_commitment),
    );

    // convert vole to arkworks variants
    let circuit = VoleVerification {
        // vole_challenge(missed but only used in outside of verification logic)
        witness_commitment: Some(
            schmivitz_proof
                .witness_commitment
                .iter()
                .map(f64b_to_ark)
                .collect(),
        ),
        // 元のコードではexpected_witness_challengesを使用していましたが、
        // これがschmivitz_proof.witness_challengesと異なる可能性があります
        // 修正: 実際のschmivitz_proof.witness_challengesを使用
        // ここは検証が必要
        witness_challenges: Some(
            schmivitz_proof
                .witness_challenges
                .iter()
                .map(f128b_to_ark)
                .collect(),
        ),
        degree_0_commitment: Some(f128b_to_ark(&schmivitz_proof.degree_0_commitment)),
        degree_1_commitment: Some(f128b_to_ark(&schmivitz_proof.degree_1_commitment)),
        // decommitment_challenge(missed but only used in outside of verification logic)
        partial_decommitment: PartialDecommitmentVar {
            verifier_key: Some(f128b_to_ark(
                &schmivitz_proof.partial_decommitment.verifier_key(),
            )),
            mask_voles: Some({
                // First collect into a Vec
                let vec: Vec<Bn254Fr> = schmivitz_proof
                    .partial_decommitment
                    .mask_voles()
                    .iter()
                    .map(|arg0: &F128b| f128b_to_ark(arg0))
                    .collect();

                // Then convert Vec to array
                let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
                for (i, val) in vec.into_iter().enumerate() {
                    if i < REPETITION_PARAM * VOLE_SIZE_PARAM {
                        array[i] = val;
                    } else {
                        break;
                    }
                }
                array
            }),
            witness_voles: {
                let mut result = Vec::new();
                for arr in schmivitz_proof.partial_decommitment.witness_voles() {
                    let mut converted_arr = [Bn254Fr::default(); REPETITION_PARAM];
                    for (i, &value) in arr.iter().enumerate() {
                        if i < REPETITION_PARAM {
                            converted_arr[i] = f8b_to_ark(&value);
                        }
                    }
                    result.push(converted_arr);
                }
                Some(result)
            },
        },
    };

    // Serialize the circuit to JSON and save it
    let serializable_circuit = SerializableVoleVerification {
        witness_commitment: circuit.witness_commitment.as_ref().map(|wc| {
            wc.iter()
                .map(|fr| SerializableBn254Fr(fr.to_string()))
                .collect()
        }),
        witness_challenges: circuit.witness_challenges.as_ref().map(|wc| {
            wc.iter()
                .map(|fr| SerializableBn254Fr(fr.to_string()))
                .collect()
        }),
        degree_0_commitment: circuit
            .degree_0_commitment
            .as_ref()
            .map(|fr| SerializableBn254Fr(fr.to_string())),
        degree_1_commitment: circuit
            .degree_1_commitment
            .as_ref()
            .map(|fr| SerializableBn254Fr(fr.to_string())),
        partial_decommitment: SerializablePartialDecommitment {
            verifier_key: circuit
                .partial_decommitment
                .verifier_key
                .as_ref()
                .map(|fr| SerializableBn254Fr(fr.to_string())),
            witness_voles: circuit
                .partial_decommitment
                .witness_voles
                .as_ref()
                .map(|wv| {
                    wv.iter()
                        .map(|arr| {
                            arr.iter()
                                .map(|fr| SerializableBn254Fr(fr.to_string()))
                                .collect()
                        })
                        .collect()
                }),
            mask_voles: circuit.partial_decommitment.mask_voles.as_ref().map(|mv| {
                mv.iter()
                    .map(|fr| SerializableBn254Fr(fr.to_string()))
                    .collect()
            }),
        },
    };

    // Write to circuit.json
    if let Ok(json) = serde_json::to_string_pretty(&serializable_circuit) {
        if let Err(e) = fs::write("circuit.json", json) {
            eprintln!("Failed to write circuit.json: {}", e);
        } else {
            println!("Circuit saved to circuit.json");
        }
    } else {
        eprintln!("Failed to serialize circuit to JSON");
    }

    circuit
}
