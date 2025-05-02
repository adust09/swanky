#[cfg(test)]
mod tests {
    use crate::constraints::{PartialDecommitmentVar, VoleVerification};
    use crate::serializable::{
        SerializableBn254Fr, SerializablePartialDecommitment, SerializableVoleVerification,
    };
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints,
    };
    use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};
    use serde_json;
    use std::fs;
    use tracing_subscriber::layer::SubscriberExt;
    /// Helper function to create a test circuit with default values
    fn create_test_circuit() -> VoleVerification {
        // Create the circuit
        let circuit = VoleVerification {
            witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)].into(),
            witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)].into(),
            degree_0_commitment: Some(Bn254Fr::from(1u64)),
            degree_1_commitment: Some(Bn254Fr::from(2u64)),
            partial_decommitment: PartialDecommitmentVar {
                verifier_key: Some(Bn254Fr::from(3u64)),
                witness_voles: {
                    // Create two arrays to match the two elements in witness_commitment
                    let mut array1 = [Bn254Fr::default(); REPETITION_PARAM];
                    array1[0] = Bn254Fr::from(10u64);
                    array1[1] = Bn254Fr::from(11u64);
                    array1[2] = Bn254Fr::from(10u64);
                    array1[3] = Bn254Fr::from(11u64);
                    array1[4] = Bn254Fr::from(10u64);
                    array1[5] = Bn254Fr::from(11u64);
                    array1[6] = Bn254Fr::from(10u64);
                    array1[7] = Bn254Fr::from(11u64);
                    array1[8] = Bn254Fr::from(10u64);
                    array1[9] = Bn254Fr::from(11u64);
                    array1[10] = Bn254Fr::from(10u64);
                    array1[11] = Bn254Fr::from(11u64);
                    array1[12] = Bn254Fr::from(10u64);
                    array1[13] = Bn254Fr::from(11u64);
                    array1[14] = Bn254Fr::from(10u64);
                    array1[15] = Bn254Fr::from(11u64);

                    let mut array2 = [Bn254Fr::default(); REPETITION_PARAM];
                    array2[0] = Bn254Fr::from(12u64);
                    array2[1] = Bn254Fr::from(13u64);
                    array2[2] = Bn254Fr::from(12u64);
                    array2[3] = Bn254Fr::from(13u64);
                    array2[4] = Bn254Fr::from(12u64);
                    array2[5] = Bn254Fr::from(13u64);
                    array2[6] = Bn254Fr::from(12u64);
                    array2[7] = Bn254Fr::from(13u64);
                    array2[8] = Bn254Fr::from(12u64);
                    array2[9] = Bn254Fr::from(13u64);
                    array2[10] = Bn254Fr::from(12u64);
                    array2[11] = Bn254Fr::from(13u64);
                    array2[12] = Bn254Fr::from(12u64);
                    array2[13] = Bn254Fr::from(13u64);
                    array2[14] = Bn254Fr::from(12u64);
                    array2[15] = Bn254Fr::from(13u64);

                    vec![array1, array2].into()
                },
                mask_voles: {
                    let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
                    array[0] = Bn254Fr::from(6u64);
                    array[1] = Bn254Fr::from(7u64);
                    Some(array)
                },
            },
        };

        // Serialize the circuit to JSON and save it
        let serializable_circuit = SerializableVoleVerification {
            witness_commitment: Some(
                vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)]
                    .iter()
                    .map(|fr| SerializableBn254Fr(fr.to_string()))
                    .collect(),
            ),
            witness_challenges: Some(
                vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)]
                    .iter()
                    .map(|fr| SerializableBn254Fr(fr.to_string()))
                    .collect(),
            ),
            degree_0_commitment: Some(SerializableBn254Fr(Bn254Fr::from(1u64).to_string())),
            degree_1_commitment: Some(SerializableBn254Fr(Bn254Fr::from(2u64).to_string())),
            partial_decommitment: SerializablePartialDecommitment {
                verifier_key: Some(SerializableBn254Fr(Bn254Fr::from(3u64).to_string())),
                witness_voles: Some(vec![
                    (0..REPETITION_PARAM)
                        .map(|i| {
                            let value = if i % 2 == 0 { 10u64 } else { 11u64 };
                            SerializableBn254Fr(Bn254Fr::from(value).to_string())
                        })
                        .collect(),
                    (0..REPETITION_PARAM)
                        .map(|i| {
                            let value = if i % 2 == 0 { 12u64 } else { 13u64 };
                            SerializableBn254Fr(Bn254Fr::from(value).to_string())
                        })
                        .collect(),
                ]),
                mask_voles: Some(
                    (0..REPETITION_PARAM * VOLE_SIZE_PARAM)
                        .map(|i| {
                            let value = if i == 0 {
                                6u64
                            } else if i == 1 {
                                7u64
                            } else {
                                0u64
                            };
                            SerializableBn254Fr(Bn254Fr::from(value).to_string())
                        })
                        .collect(),
                ),
            },
            // Add the new fields with None values since they're not used in this context
            d_delta: None,
            masked_witnesses: None,
            validation_mask: None,
            validation_aggregate: None,
        };

        // Write to test_circuit.json
        if let Ok(json) = serde_json::to_string_pretty(&serializable_circuit) {
            if let Err(e) = fs::write("test_circuit.json", json) {
                eprintln!("Failed to write test_circuit.json: {}", e);
            } else {
                println!("Test circuit saved to test_circuit.json");
            }
        } else {
            eprintln!("Failed to serialize test circuit to JSON");
        }

        // Return the circuit
        circuit
    }

    fn test_cs(vole_verification: VoleVerification) -> bool {
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        vole_verification.generate_constraints(cs.clone()).unwrap();
        let result = cs.is_satisfied().unwrap();
        if !result {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        result
    }

    #[test]
    fn test_constraint_generation() {
        let circuit = create_test_circuit();

        test_cs(circuit);
    }
}
