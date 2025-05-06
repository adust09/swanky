// use ark_bn254::Bn254;
// use ark_bn254::Fr as Bn254Fr;

// use ark_groth16::Groth16;
// use ark_relations::r1cs::{ConstraintLayer, TracingMode};
// use ark_snark::SNARK;
// use arkworks_solidity_verifier::SolidityVerifier;
// use eyre::Result;
// use merlin::Transcript;
// use rand::thread_rng;
// use schmivitz::{
//     insecure::InsecureVole,
//     parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM},
//     to_serializable_proof, Proof,
// };
// // Import the VerificationResult directly from the proof module
// use schmivitz::proof::VerificationResult;
// use schmivitz_snark::{
//     f128b_to_ark, f64b_to_ark, f8b_to_ark, serializable::serialize_bn254fr, SchmivitzValues,
//     VoleVerification,
// };
// // Import PartialDecommitmentVar from the same module as VoleVerification
// use schmivitz_snark::constraints::PartialDecommitmentVar;
// use std::{
//     fs::{self, File},
//     io::{Cursor, Write},
//     path::Path,
// };
// use swanky_field_binary::F128b;
// use tempfile::tempdir;
// use tracing_subscriber::layer::SubscriberExt;

// fn main() -> Result<()> {
//     let mut layer = ConstraintLayer::default();
//     layer.mode = TracingMode::OnlyConstraints;
//     let subscriber = tracing_subscriber::Registry::default().with(layer);
//     let _guard = tracing::subscriber::set_default(subscriber);
//     // target circuit
//     let circuit_str = "version 2.0.0;
//         circuit;
//         @type field 2;
//         @begin
//             $0 ... $4 <- @private(0);
//             $5 <- @add(0: $0, $0);
//             $6 <- @add(0: $0, $1);
//             $7 <- @add(0: $0, $2);
//             $8 <- @add(0: $0, $3);
//             $9 <- @add(0: $0, $4);
//             $10 <- @mul(0: $0, $5);
//             $11 <- @mul(0: $0, $6);
//             $12 <- @mul(0: $0, $7);
//             $13 <- @mul(0: $0, $8);
//             $14 <- @mul(0: $0, $9);
//         @end ";
//     let circuit = Cursor::new(circuit_str.as_bytes());

//     let private_input_bytes = "version 2.0.0;
//         private_input;
//         @type field 2;
//         @begin
//             < 1 >;
//             < 1 >;
//             < 1 >;
//             < 0 >;
//             < 0 >;
//         @end";

//     let dir = tempdir().unwrap();
//     let private_input_path = dir.path().join("private_inputs");
//     let mut private_input = File::create(private_input_path.clone()).unwrap();
//     writeln!(private_input, "{}", private_input_bytes).unwrap();

//     let mut transcript = Transcript::new(b"schmivitz-snark");
//     let rng = &mut thread_rng();
//     let schmivitz_proof: Proof<InsecureVole> = Proof::<InsecureVole>::prove(
//         &mut circuit.clone(),
//         &private_input_path,
//         &mut transcript,
//         rng,
//     )?;

//     // Serialize and save the schmivitz_proof to a JSON file
//     let serializable_proof = to_serializable_proof(&schmivitz_proof);
//     let proof_json = serde_json::to_string_pretty(&serializable_proof)?;
//     fs::write("schmivitz_proof.json", proof_json)?;

//     // validate proof
//     let mut test_verify_transcript = Transcript::new(b"schmivitz-snark");
//     let verification_result = schmivitz_proof
//         .verify(&mut circuit.clone(), &mut test_verify_transcript)
//         .expect("Verification should succeed");

//     let circuit = build_circuit(schmivitz_proof.clone(), &verification_result);

//     let mut rng = ark_std::test_rng();
//     let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

//     let solidity_verifier = Groth16::<Bn254>::export(&vk);
//     let output_dir = Path::new("solidity_output");
//     if !output_dir.exists() {
//         fs::create_dir_all(output_dir)?;
//     }
//     let output_path = output_dir.join("vole_verifier.sol");
//     fs::write(&output_path, solidity_verifier)?;
//     println!("Solidity verifier generated at: {}", output_path.display());

//     let public_input = vec![];

//     let snark_proof = Groth16::prove(&pk, circuit, &mut rng)?;
//     let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

//     println!(
//         "Verified SNARK proof: {}",
//         if is_valid { "VALID" } else { "INVALID" }
//     );

//     Ok(())
// }

// fn build_circuit(
//     schmivitz_proof: Proof<InsecureVole>,
//     verification_result: &VerificationResult,
// ) -> VoleVerification {
//     // convert vole to arkworks variants
//     let circuit = VoleVerification {
//         // vole_challenge(missed but only used in outside of verification logic)
//         witness_commitment: Some(
//             schmivitz_proof
//                 .witness_commitment
//                 .iter()
//                 .map(f64b_to_ark)
//                 .collect(),
//         ),
//         witness_challenges: Some(
//             schmivitz_proof
//                 .witness_challenges
//                 .iter()
//                 .map(f128b_to_ark)
//                 .collect(),
//         ),
//         degree_0_commitment: Some(f128b_to_ark(&schmivitz_proof.degree_0_commitment)),
//         degree_1_commitment: Some(f128b_to_ark(&schmivitz_proof.degree_1_commitment)),
//         // decommitment_challenge(missed but only used in outside of verification logic)
//         partial_decommitment: PartialDecommitmentVar {
//             verifier_key: Some(f128b_to_ark(
//                 &schmivitz_proof.partial_decommitment.verifier_key(),
//             )),
//             mask_voles: Some({
//                 // First collect into a Vec
//                 let vec: Vec<Bn254Fr> = schmivitz_proof
//                     .partial_decommitment
//                     .mask_voles()
//                     .iter()
//                     .map(|arg0: &F128b| f128b_to_ark(arg0))
//                     .collect();

//                 // Then convert Vec to array
//                 let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
//                 for (i, val) in vec.into_iter().enumerate() {
//                     if i < REPETITION_PARAM * VOLE_SIZE_PARAM {
//                         array[i] = val;
//                     } else {
//                         break;
//                     }
//                 }
//                 array
//             }),
//             witness_voles: {
//                 let mut result = Vec::new();
//                 for arr in schmivitz_proof.partial_decommitment.witness_voles() {
//                     let mut converted_arr = [Bn254Fr::default(); REPETITION_PARAM];
//                     for (i, &value) in arr.iter().enumerate() {
//                         if i < REPETITION_PARAM {
//                             converted_arr[i] = f8b_to_ark(&value);
//                         }
//                     }
//                     result.push(converted_arr);
//                 }
//                 Some(result)
//             },
//         },
//         schmivitz_values: Some(SchmivitzValues {
//             d_delta: Some({
//                 let mut result = Vec::new();
//                 for arr in verification_result.d_delta.iter() {
//                     let mut converted_arr = [Bn254Fr::default(); REPETITION_PARAM];
//                     for (i, val) in arr.iter().enumerate() {
//                         if i < REPETITION_PARAM {
//                             converted_arr[i] = f8b_to_ark(val);
//                         }
//                     }
//                     result.push(converted_arr);
//                 }
//                 result
//             }),
//             masked_witnesses: Some(
//                 verification_result
//                     .masked_witnesses
//                     .iter()
//                     .map(|v| f128b_to_ark(v))
//                     .collect(),
//             ),
//             validation_mask: Some(f128b_to_ark(&verification_result.validation_mask)),
//             validation_aggregate: Some(f128b_to_ark(&verification_result.validation_aggregate)),
//             validation_from_schmivitz: Some(f128b_to_ark(&verification_result.validation)),
//             actual_validation: Some(f128b_to_ark(&verification_result.validation)),
//         }),
//     };

//     // Serialize the circuit to JSON and save it
//     serialize_bn254fr(&circuit);
//     circuit
// }

use ark_bn254::Bn254;
use ark_bn254::Fr as Bn254Fr;
use ark_groth16::Groth16;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::r1cs::{ConstraintLayer, ConstraintSystem, TracingMode};
use ark_snark::SNARK;
use arkworks_solidity_verifier::SolidityVerifier;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, to_serializable_proof, Proof};
// Import the boolean array conversion functions
use schmivitz_snark::{
    constraints::{PartialDecommitmentBoolean, VoleVerificationBoolean},
    f128b_to_boolean_array, f64b_to_boolean_array, f8b_to_boolean_array,
};
use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};
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

    // validate proof
    let mut test_verify_transcript = Transcript::new(b"schmivitz-snark");
    let verification_result = schmivitz_proof
        .verify(&mut circuit.clone(), &mut test_verify_transcript)
        .expect("Verification should succeed");

    // Create a constraint system for boolean conversions
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();

    // Build the circuit using boolean arrays
    let circuit = build_circuit(cs.clone(), schmivitz_proof.clone());

    let mut rng = ark_std::test_rng();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();

    let solidity_verifier = Groth16::<Bn254>::export(&vk);
    let output_dir = Path::new("solidity_output");
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }
    let output_path = output_dir.join("vole_verifier_boolean.sol");
    fs::write(&output_path, solidity_verifier)?;
    println!("Solidity verifier generated at: {}", output_path.display());

    let public_input = vec![];

    let snark_proof = Groth16::prove(&pk, circuit, &mut rng)?;
    let is_valid = Groth16::verify(&vk, &public_input, &snark_proof)?;

    println!(
        "Verified SNARK proof with boolean arrays: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    Ok(())
}

fn build_circuit(
    cs: ark_relations::r1cs::ConstraintSystemRef<Bn254Fr>,
    schmivitz_proof: Proof<InsecureVole>,
) -> VoleVerificationBoolean {
    // Convert binary field elements to boolean arrays

    // Convert witness commitment (F64b) to boolean arrays
    let witness_commitment_booleans: Vec<Vec<Boolean<Bn254Fr>>> = schmivitz_proof
        .witness_commitment
        .iter()
        .map(|value| f64b_to_boolean_array(cs.clone(), value).unwrap())
        .collect();

    // Convert witness challenges (F128b) to boolean arrays
    let witness_challenges_booleans: Vec<Vec<Boolean<Bn254Fr>>> = schmivitz_proof
        .witness_challenges
        .iter()
        .map(|value| f128b_to_boolean_array(cs.clone(), value).unwrap())
        .collect();

    // Convert degree commitments to boolean arrays
    let degree_0_commitment_boolean =
        f128b_to_boolean_array(cs.clone(), &schmivitz_proof.degree_0_commitment).unwrap();

    let degree_1_commitment_boolean =
        f128b_to_boolean_array(cs.clone(), &schmivitz_proof.degree_1_commitment).unwrap();

    // Convert verifier key to boolean array
    let verifier_key_boolean = f128b_to_boolean_array(
        cs.clone(),
        &schmivitz_proof.partial_decommitment.verifier_key(),
    )
    .unwrap();

    // Process mask voles using boolean arrays
    let mask_voles_booleans: Vec<Vec<Boolean<Bn254Fr>>> = schmivitz_proof
        .partial_decommitment
        .mask_voles()
        .iter()
        .map(|value| f128b_to_boolean_array(cs.clone(), value).unwrap())
        .collect();

    // Process witness voles using boolean arrays
    let mut witness_voles_booleans = Vec::new();
    for arr in schmivitz_proof.partial_decommitment.witness_voles() {
        // Convert each F8b value to boolean array
        let arr_booleans: Vec<Vec<Boolean<Bn254Fr>>> = arr
            .iter()
            .map(|value| f8b_to_boolean_array(cs.clone(), value).unwrap())
            .collect();

        witness_voles_booleans.push(arr_booleans);
    }

    // Build the circuit with boolean arrays
    let circuit = VoleVerificationBoolean {
        witness_commitment: witness_commitment_booleans,
        witness_challenges: witness_challenges_booleans,
        degree_0_commitment: degree_0_commitment_boolean,
        degree_1_commitment: degree_1_commitment_boolean,
        partial_decommitment: PartialDecommitmentBoolean {
            verifier_key: verifier_key_boolean,
            mask_voles: mask_voles_booleans,
            witness_voles: witness_voles_booleans,
        },
    };

    // Skip serialization for now
    circuit
}
