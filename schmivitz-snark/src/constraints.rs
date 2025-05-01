use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};

use crate::gadgets::{CircuitTraverser, MaskedWitnessVar};

#[derive(Debug, Clone)]
pub struct VoleVerification {
    // vole_challenge(missed but only used in outside of verification logic)
    pub witness_commitment: Option<Vec<Bn254Fr>>,
    pub witness_challenges: Option<Vec<Bn254Fr>>,
    pub degree_0_commitment: Option<Bn254Fr>,
    pub degree_1_commitment: Option<Bn254Fr>,
    //decommitment_challenge(missed but only used in outside of verification logic)
    pub partial_decommitment: PartialDecommitmentVar,
}
#[derive(Debug, Clone)]
pub struct PartialDecommitmentVar {
    pub verifier_key: Option<Bn254Fr>,
    pub witness_voles: Option<Vec<[Bn254Fr; REPETITION_PARAM]>>,
    pub mask_voles: Option<[Bn254Fr; REPETITION_PARAM * VOLE_SIZE_PARAM]>,
}

impl ConstraintSynthesizer<Bn254Fr> for VoleVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        let witness_commitment_var = Vec::<FpVar<Bn254Fr>>::new_witness(
            ark_relations::ns!(cs, "witness_commitment"),
            || {
                self.witness_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;
        let witness_challenges_var = Vec::<FpVar<Bn254Fr>>::new_witness(
            ark_relations::ns!(cs, "witness_challenges"),
            || {
                self.witness_challenges
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

        // Output witness_commitment_var values to console
        // if cs.is_in_setup_mode() == false {
        //     println!("witness_commitment_var values from constraints.rs:");
        //     for (i, challenge) in witness_commitment_var.iter().enumerate() {
        //         match challenge.value() {
        //             Ok(value) => println!("  [{}]: {:?}", i, value),
        //             Err(_) => println!("  [{}]: Error retrieving value", i),
        //         }
        //     }
        //     println!();
        // }

        let verifier_key_var = FpVar::new_witness(ark_relations::ns!(cs, "verifier_key"), || {
            self.partial_decommitment
                .verifier_key
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Output verifier_key_var value to console
        // if cs.is_in_setup_mode() == false {
        //     println!("verifier_key from constraints.rs:");
        //     match verifier_key_var.value() {
        //         Ok(value) => println!("  {:?}", value),
        //         Err(_) => println!("  Error retrieving value"),
        //     }
        //     println!();
        // }
        let degree_0_commitment_var =
            FpVar::new_witness(ark_relations::ns!(cs, "degree_0_commitment"), || {
                self.degree_0_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let degree_1_commitment_var =
            FpVar::new_witness(ark_relations::ns!(cs, "degree_1_commitment"), || {
                self.degree_1_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        // Get the witness voles from the partial decommitment
        let witness_voles = self
            .partial_decommitment
            .witness_voles
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Create a vector to hold the witness vole
        let mut witness_voles_var = Vec::with_capacity(witness_voles.len());

        // For each vole array in the witness voles
        for vole_array in witness_voles.iter() {
            // Create a vector to hold the FpVar elements for this array
            let mut fp_vec = Vec::with_capacity(REPETITION_PARAM);

            // For each element in the vole array
            for val in vole_array.iter() {
                // Create a witness variable for the element
                let var =
                    FpVar::new_witness(ark_relations::ns!(cs, "witness_vole_element"), || {
                        Ok(*val)
                    })?;
                fp_vec.push(var);
            }

            witness_voles_var.push(fp_vec);
        }

        // Output witness_voles_var values to console
        // if cs.is_in_setup_mode() == false {
        //     println!("witness_voles from constraints.rs:");
        //     for (i, vole_array) in witness_voles_var.iter().enumerate() {
        //         println!("  witness_voles[{}]:", i);
        //         for (j, vole) in vole_array.iter().enumerate() {
        //             match vole.value() {
        //                 Ok(value) => println!("    [{}]: {:?}", j, value),
        //                 Err(_) => println!("    [{}]: Error retrieving value", j),
        //             }
        //         }
        //     }
        //     println!();
        // }

        // Step 1: Compute d_delta from witness commitment and verifier key
        let d_delta_var = MaskedWitnessVar::compute_d_delta(
            cs.clone(),
            &witness_commitment_var,
            &verifier_key_var,
        )?;

        // Output d_delta_var values to console
        if cs.is_in_setup_mode() == false {
            println!("d_delta_var values from constraints.rs:");
            for (i, dd_array) in d_delta_var.iter().enumerate() {
                println!("d_delta_var[{}]:", i);
                for (j, dd) in dd_array.iter().enumerate() {
                    match dd.value() {
                        Ok(value) => println!("  [{}]: {:?}", j, value),
                        Err(_) => println!("  [{}]: Error retrieving value", j),
                    }
                }
            }
            println!();
        }

        // Step 2: Compute masked witnesses from witness voles and d_delta
        let masked_witnesses_var =
            MaskedWitnessVar::compute_masked_witness(&witness_voles_var, &d_delta_var)?;

        // Output masked_witnesses_var values to console
        if cs.is_in_setup_mode() == false {
            println!("masked_witnesses_var from constraints.rs:");
            for (i, witness) in masked_witnesses_var.iter().enumerate() {
                match witness.value() {
                    Ok(value) => println!("  [{}]: {:?}", i, value),
                    Err(_) => println!("  [{}]: Error retrieving value", i),
                }
            }
            println!();
        }

        let validation_aggregate_var = CircuitTraverser::compute_validation_aggregate(
            &witness_challenges_var,
            &masked_witnesses_var,
        )?;

        if cs.is_in_setup_mode() == false {
            let validation_aggregate_value = validation_aggregate_var
                .value()
                .unwrap_or_else(|_| Bn254Fr::from(0u64));
            println!(
                "validation_aggregate_var = {:?}",
                validation_aggregate_value
            );
        }
        // Step 3: Combine mask VOLEs to get validation_mask (q* in proof.rs)
        // Get the mask_voles from the partial_decommitment
        let mask_voles = self
            .partial_decommitment
            .mask_voles
            .clone()
            .ok_or(SynthesisError::AssignmentMissing)?;

        // Create FpVar variables for each mask_vole
        let mut mask_voles_var = Vec::with_capacity(mask_voles.len());
        for val in mask_voles.iter() {
            let var = FpVar::new_witness(ark_relations::ns!(cs, "mask_vole_element"), || Ok(*val))?;
            mask_voles_var.push(var);
        }

        // Output mask_voles_var values to console
        if cs.is_in_setup_mode() == false {
            println!("mask_voles from constraints.rs:");
            for (i, vole) in mask_voles_var.iter().enumerate().take(10) {
                // Only show first 10 to avoid too much output
                match vole.value() {
                    Ok(value) => println!("  [{}]: {:?}", i, value),
                    Err(_) => println!("  [{}]: Error retrieving value", i),
                }
            }
            println!("  ... (showing only first 10 elements)");
            println!();
        }

        // Compute validation_mask using the refactored function
        let validation_mask_var =
            MaskedWitnessVar::compute_validation_mask(cs.clone(), &mask_voles_var)?;

        // Step 4: Compute the final validation value
        // In proof.rs: let validation = validation_aggregate + validation_mask;
        let validation_var = validation_aggregate_var + validation_mask_var;

        // Step 5: Check the main constraint of the proof
        let actual_validation_var =
            degree_1_commitment_var * verifier_key_var + degree_0_commitment_var;

        // Enforce that validation equals actual_validation
        if cs.is_in_setup_mode() == false {
            let validation_value = validation_var
                .value()
                .unwrap_or_else(|_| Bn254Fr::from(0u64));
            let actual_validation_value = actual_validation_var
                .value()
                .unwrap_or_else(|_| Bn254Fr::from(0u64));

            println!("validation_var = {:?}\n", validation_value);
            println!("actual_validation_var = {:?}\n", actual_validation_value);
            println!("equal?: {}\n", validation_value == actual_validation_value);

            debug_assert!(cs.is_satisfied().unwrap());
        }
        validation_var.enforce_equal(&actual_validation_var)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::ConstraintSystem;

    fn create_test_circuit() -> VoleVerification {
        VoleVerification {
            witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)].into(),
            witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)].into(),
            degree_0_commitment: Some(Bn254Fr::from(1u64)),
            degree_1_commitment: Some(Bn254Fr::from(2u64)),
            partial_decommitment: PartialDecommitmentVar {
                verifier_key: Some(Bn254Fr::from(3u64)),
                witness_voles: {
                    let mut arr = [Bn254Fr::default(); REPETITION_PARAM];
                    arr[0] = Bn254Fr::from(10u64);
                    arr[1] = Bn254Fr::from(11u64);
                    vec![arr].into()
                },
                mask_voles: {
                    let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
                    array[0] = Bn254Fr::from(6u64);
                    array[1] = Bn254Fr::from(7u64);
                    Some(array)
                },
            },
        }
    }

    #[test]
    fn test_circuit_creation() {
        let circuit = create_test_circuit();

        assert_eq!(circuit.degree_0_commitment, Some(Bn254Fr::from(1u64)));
        assert_eq!(circuit.degree_1_commitment, Some(Bn254Fr::from(2u64)));
        assert_eq!(
            circuit.partial_decommitment.verifier_key,
            Some(Bn254Fr::from(3u64))
        );
    }

    #[test]
    fn test_constraint_generation() {
        let circuit = create_test_circuit();
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());
        let constraints = cs.constraint_names();
        println!("Generated constraints: {:?}", constraints);
        assert!(result.is_ok(), "Constraint generation should succeed");

        let num_constraints = cs.num_constraints();
        println!("Number of constraints generated: {}", num_constraints);
        assert!(
            num_constraints > 0,
            "Expected constraints to be generated, but got {}",
            num_constraints
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
    }
}
