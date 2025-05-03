use std::{
    fs::{self, File},
    io::Write,
};

use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, R1CSVar};
use serde::{Deserialize, Serialize};

/// Serializable representation of Bn254Fr field element
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableBn254Fr(pub String);

/// Serializable representation of PartialDecommitmentVar
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializablePartialDecommitment {
    pub verifier_key: Option<SerializableBn254Fr>,
    pub witness_voles: Option<Vec<Vec<SerializableBn254Fr>>>,
    pub mask_voles: Option<Vec<SerializableBn254Fr>>,
}

/// Serializable representation of VoleVerification
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SerializableVoleVerification {
    pub witness_commitment: Option<Vec<SerializableBn254Fr>>,
    pub witness_challenges: Option<Vec<SerializableBn254Fr>>,
    pub degree_0_commitment: Option<SerializableBn254Fr>,
    pub degree_1_commitment: Option<SerializableBn254Fr>,
    pub partial_decommitment: SerializablePartialDecommitment,
    // Optional additional fields that might be used in some contexts
    pub d_delta: Option<Vec<[SerializableBn254Fr; REPETITION_PARAM]>>,
    pub masked_witnesses: Option<Vec<SerializableBn254Fr>>,
    pub validation_mask: Option<SerializableBn254Fr>,
    pub validation_aggregate: Option<SerializableBn254Fr>,
}

// Create a serializable structure to hold all variable values
#[derive(Serialize, Deserialize)]
pub struct ArkVars {
    pub witness_commitment: Vec<String>,
    pub witness_challenges: Vec<String>,
    pub verifier_key: String,
    pub degree_0_commitment: String,
    pub degree_1_commitment: String,
    pub validation_from_schmivitz: String,
    pub actual_validation_from_schmivitz: String,
    pub validation: String,
    pub actual_validation: String,
    pub validation_aggregate: String,
    pub validation_mask: String,
    pub masked_witnesses: Vec<String>,
    pub d_delta: Vec<String>,
    pub mask_voles: Vec<String>,
    pub witness_voles: Vec<Vec<String>>,
    // New fields
    pub d_delta_from_schmivitz: String,
    pub masked_witness_from_schmivitz: String,
    pub validation_aggregate_from_schmivitz: String,
    pub validation_mask_from_schmivitz: String,
    pub result: String,
}

/// Save circuit variables to a JSON file
///
/// This function extracts values from FpVar variables, creates an ArkVars struct,
/// serializes it to JSON, and writes it to a file named "ark_var.json".
///
/// # Arguments
///
/// * `witness_commitment_var` - Vector of witness commitment variables
/// * `witness_challenges_var` - Vector of witness challenge variables
/// * `verifier_key_var` - Verifier key variable
/// * `degree_0_commitment_var` - Degree 0 commitment variable
/// * `degree_1_commitment_var` - Degree 1 commitment variable
/// * `validation_var` - Validation variable
/// * `actual_validation_var` - Actual validation variable
/// * `validation_aggregate_var` - Validation aggregate variable
/// * `validation_mask_var` - Validation mask variable
/// * `masked_witnesses_var` - Vector of masked witness variables
/// * `d_delta_var` - Vector of d_delta variables
/// * `mask_voles_var` - Vector of mask vole variables
/// * `witness_voles_var` - Vector of vectors of witness vole variables
/// * `validation_from_schmivitz_var` - Optional validation from schmivitz variable
/// * `actual_validation_from_schmivitz_var` - Optional actual validation from schmivitz variable
use schmivitz::parameters::REPETITION_PARAM;

use crate::VoleVerification;

pub fn save_variables_to_json(
    witness_commitment_var: &Vec<FpVar<Bn254Fr>>,
    witness_challenges_var: &Vec<FpVar<Bn254Fr>>,
    verifier_key_var: &FpVar<Bn254Fr>,
    degree_0_commitment_var: &FpVar<Bn254Fr>,
    degree_1_commitment_var: &FpVar<Bn254Fr>,
    validation_var: &FpVar<Bn254Fr>,
    actual_validation_var: &FpVar<Bn254Fr>,
    validation_aggregate_var: &FpVar<Bn254Fr>,
    validation_mask_var: &FpVar<Bn254Fr>,
    masked_witnesses_var: &Vec<FpVar<Bn254Fr>>,
    d_delta_var: &Vec<[FpVar<Bn254Fr>; REPETITION_PARAM]>,
    mask_voles_var: &Vec<FpVar<Bn254Fr>>,
    witness_voles_var: &Vec<Vec<FpVar<Bn254Fr>>>,
    validation_from_schmivitz_var: Option<&FpVar<Bn254Fr>>,
    actual_validation_from_schmivitz_var: Option<&FpVar<Bn254Fr>>,
    // New parameters
    d_delta_from_schmivitz_var: &FpVar<Bn254Fr>,
    masked_witness_from_schmivitz_var: &FpVar<Bn254Fr>,
    validation_aggregate_from_schmivitz_var: &FpVar<Bn254Fr>,
    validation_mask_from_schmivitz_var: &FpVar<Bn254Fr>,
    result_var: &FpVar<Bn254Fr>,
) {
    // Extract values from FpVar variables
    let ark_vars = ArkVars {
        witness_commitment: witness_commitment_var
            .iter()
            .map(|v: &FpVar<ark_ff::Fp256<ark_bn254::FrParameters>>| {
                format!("{:?}", v.value().unwrap_or_default())
            })
            .collect(),
        witness_challenges: witness_challenges_var
            .iter()
            .map(|v| format!("{:?}", v.value().unwrap_or_default()))
            .collect(),
        verifier_key: format!("{:?}", verifier_key_var.clone().value().unwrap_or_default()),
        degree_0_commitment: format!("{:?}", degree_0_commitment_var.value().unwrap_or_default()),
        degree_1_commitment: format!("{:?}", degree_1_commitment_var.value().unwrap_or_default()),
        validation: format!("{:?}", validation_var.value().unwrap_or_default()),
        actual_validation: format!("{:?}", actual_validation_var.value().unwrap_or_default()),
        validation_aggregate: format!("{:?}", validation_aggregate_var.value().unwrap_or_default()),
        validation_mask: format!("{:?}", validation_mask_var.value().unwrap_or_default()),
        masked_witnesses: masked_witnesses_var
            .iter()
            .map(|v| format!("{:?}", v.value().unwrap_or_default()))
            .collect(),
        d_delta: d_delta_var
            .iter()
            .map(|arr| {
                // Convert each array element to a string and join them
                arr.iter()
                    .map(|v| format!("{:?}", v.value().unwrap_or_default()))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .collect(),
        mask_voles: mask_voles_var
            .iter()
            .map(|v| format!("{:?}", v.value().unwrap_or_default()))
            .collect(),
        witness_voles: witness_voles_var
            .iter()
            .map(|arr| {
                arr.iter()
                    .map(|v| format!("{:?}", v.value().unwrap_or_default()))
                    .collect()
            })
            .collect(),
        validation_from_schmivitz: validation_from_schmivitz_var
            .map(|v| format!("{:?}", v.value().unwrap_or_default()))
            .unwrap_or_default(),
        actual_validation_from_schmivitz: actual_validation_from_schmivitz_var
            .map(|v| format!("{:?}", v.value().unwrap_or_default()))
            .unwrap_or_default(),
        // New fields
        d_delta_from_schmivitz: format!(
            "{:?}",
            d_delta_from_schmivitz_var.value().unwrap_or_default()
        ),
        masked_witness_from_schmivitz: format!(
            "{:?}",
            masked_witness_from_schmivitz_var
                .value()
                .unwrap_or_default()
        ),
        validation_aggregate_from_schmivitz: format!(
            "{:?}",
            validation_aggregate_from_schmivitz_var
                .value()
                .unwrap_or_default()
        ),
        validation_mask_from_schmivitz: format!(
            "{:?}",
            validation_mask_from_schmivitz_var
                .value()
                .unwrap_or_default()
        ),
        result: format!("{:?}", result_var.value().unwrap_or_default()),
    };

    // Serialize to JSON and write to file
    match serde_json::to_string_pretty(&ark_vars) {
        Ok(json) => match File::create("ark_var.json") {
            Ok(mut file) => {
                if let Err(e) = file.write_all(json.as_bytes()) {
                    println!("Error writing to ark_var.json: {}", e);
                } else {
                    println!("Successfully wrote variables to ark_var.json");
                }
            }
            Err(e) => println!("Error creating ark_var.json: {}", e),
        },
        Err(e) => println!("Error serializing variables: {}", e),
    }
}

// Using serializable structures from the shared module

pub fn serialize_bn254fr(circuit: &VoleVerification) -> SerializableVoleVerification {
    // Convert the Bn254Fr value to a string representation
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
        // Add the new fields with None values since they're not used in this context
        d_delta: None,
        masked_witnesses: None,
        validation_mask: None,
        validation_aggregate: None,
    };
    // Write to vole-verification-circuit.json
    if let Ok(json) = serde_json::to_string_pretty(&serializable_circuit) {
        if let Err(e) = fs::write("vole-verification-circuit.json", json) {
            eprintln!("Failed to write vole-verification-circuit.json: {}", e);
        } else {
            println!("Circuit saved to vole-verification-circuit.json");
        }
    } else {
        eprintln!("Failed to serialize circuit to JSON");
    }
    serializable_circuit
}

pub fn serialize_bn254fr_revised(circuit: &VoleVerification) -> SerializableVoleVerification {
    // Convert the Bn254Fr value to a string representation
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
        // Add the new fields with None values since they're not used in this context
        d_delta: None,
        masked_witnesses: None,
        validation_mask: None,
        validation_aggregate: None,
    };
    // Write to vole-verification-circuit.json
    if let Ok(json) = serde_json::to_string_pretty(&serializable_circuit) {
        if let Err(e) = fs::write("vole-verification-circuit.json", json) {
            eprintln!("Failed to write vole-verification-circuit.json: {}", e);
        } else {
            println!("Circuit saved to vole-verification-circuit.json");
        }
    } else {
        eprintln!("Failed to serialize circuit to JSON");
    }
    serializable_circuit
}
