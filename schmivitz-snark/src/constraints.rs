use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};

use crate::{
    gadgets::{CircuitTraverser, MaskedWitnessVar},
    save_variables_to_json,
};

#[derive(Debug, Clone)]
pub struct VoleVerification {
    // vole_challenge(missed but only used in outside of verification logic)
    pub witness_commitment: Option<Vec<Bn254Fr>>,
    pub witness_challenges: Option<Vec<Bn254Fr>>,
    pub degree_0_commitment: Option<Bn254Fr>,
    pub degree_1_commitment: Option<Bn254Fr>,
    //decommitment_challenge(missed but only used in outside of verification logic)
    pub partial_decommitment: PartialDecommitmentVar,
    pub schmivitz_values: Option<SchmivitzValues>,
}

#[derive(Debug, Clone)]
pub struct SchmivitzValues {
    pub d_delta: Option<Vec<Vec<Bn254Fr>>>,
    pub masked_witnesses: Option<Vec<Bn254Fr>>,
    pub validation_mask: Option<Bn254Fr>,
    pub validation_aggregate: Option<Bn254Fr>,
    pub validation_from_schmivitz: Option<Bn254Fr>,
    pub actual_validation: Option<Bn254Fr>,
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

        let verifier_key_var = FpVar::new_witness(ark_relations::ns!(cs, "verifier_key"), || {
            self.partial_decommitment
                .verifier_key
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

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
        let d_delta_from_schmivitz_var =
            FpVar::new_witness(ark_relations::ns!(cs, "d_delta_from_schmivitz"), || {
                self.schmivitz_values
                    .clone()
                    .unwrap()
                    .d_delta
                    .as_ref()
                    .and_then(|v| v.first().and_then(|inner| inner.first()))
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let mask_witness_from_schmivitz_var = FpVar::new_witness(
            ark_relations::ns!(cs, "mask_witness_from_schmivitz"),
            || {
                self.schmivitz_values
                    .clone()
                    .unwrap()
                    .masked_witnesses
                    .as_ref()
                    .and_then(|v| v.first())
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;
        let validation_mask_from_schmivitz_var = FpVar::new_witness(
            ark_relations::ns!(cs, "validation_mask_from_schmivitz"),
            || {
                self.schmivitz_values
                    .clone()
                    .unwrap()
                    .validation_mask
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;
        let validation_aggregate_from_schmivitz_var =
            FpVar::new_witness(ark_relations::ns!(cs, "validation_aggregate"), || {
                self.schmivitz_values
                    .clone()
                    .unwrap()
                    .validation_aggregate
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let validation_from_schmivitz_var =
            FpVar::new_witness(ark_relations::ns!(cs, "validation_from_schmivitz"), || {
                self.schmivitz_values
                    .clone()
                    .unwrap()
                    .validation_from_schmivitz
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let actual_validation_from_schmivitz_var = FpVar::new_witness(
            ark_relations::ns!(cs, "actual_validation_from_schmivitz"),
            || {
                self.schmivitz_values
                    .clone()
                    .unwrap()
                    .actual_validation
                    .ok_or(SynthesisError::AssignmentMissing)
            },
        )?;

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

        // Step 1: Compute d_delta from witness commitment and verifier key
        let d_delta_var = MaskedWitnessVar::compute_d_delta(
            cs.clone(),
            &witness_commitment_var,
            &verifier_key_var.clone(),
        )?;

        // Step 2: Compute masked witnesses from witness voles and d_delta
        let masked_witnesses_var =
            MaskedWitnessVar::compute_masked_witness(&witness_voles_var, &d_delta_var)?;

        let validation_aggregate_var = CircuitTraverser::compute_validation_aggregate(
            &witness_challenges_var,
            &masked_witnesses_var,
        )?;

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

        // Compute validation_mask using the refactored function
        let validation_mask_var =
            MaskedWitnessVar::compute_validation_mask(cs.clone(), &mask_voles_var)?;

        // Step 4: Compute the final validation value
        // In proof.rs: let validation = validation_aggregate + validation_mask;
        let validation_var = validation_aggregate_var.clone() + validation_mask_var.clone();

        // Step 5: Check the main constraint of the proof
        let actual_validation_var = degree_1_commitment_var.clone() * verifier_key_var.clone()
            + degree_0_commitment_var.clone();

        // Optionally store the values in a JSON file
        // if cs.is_in_setup_mode() == false {
        //     save_variables_to_json(
        //         &witness_commitment_var,
        //         &witness_challenges_var,
        //         &verifier_key_var,
        //         &degree_0_commitment_var,
        //         &degree_1_commitment_var,
        //         &validation_var,
        //         &actual_validation_var,
        //         &validation_aggregate_var,
        //         &validation_mask_var,
        //         &masked_witnesses_var,
        //         &d_delta_var,
        //         &mask_voles_var,
        //         &witness_voles_var,
        //         None, // validation_from_schmivitz_var
        //         None, // actual_validation_from_schmivitz_var
        //     );
        // }
        // Enforce that validation equals actual_validation
        validation_var.enforce_equal(&actual_validation_var) // 計算が合わない
                                                             // validation_from_schmivitz_var.enforce_equal(&actual_validation_from_schmivitz_var)
                                                             // IDが合わない
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use ark_bn254::Fr as Bn254Fr;
//     use ark_relations::r1cs::ConstraintSystem;

//     fn create_test_circuit() -> VoleVerification {
//         VoleVerification {
//             witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)].into(),
//             witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)].into(),
//             degree_0_commitment: Some(Bn254Fr::from(1u64)),
//             degree_1_commitment: Some(Bn254Fr::from(2u64)),
//             partial_decommitment: PartialDecommitmentVar {
//                 verifier_key: Some(Bn254Fr::from(3u64)),
//                 witness_voles: {
//                     let mut arr = [Bn254Fr::default(); REPETITION_PARAM];
//                     arr[0] = Bn254Fr::from(10u64);
//                     arr[1] = Bn254Fr::from(11u64);
//                     vec![arr].into()
//                 },
//                 mask_voles: {
//                     let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
//                     array[0] = Bn254Fr::from(6u64);
//                     array[1] = Bn254Fr::from(7u64);
//                     Some(array)
//                 },
//             },
//         }
//     }

//     #[test]
//     fn test_circuit_creation() {
//         let circuit = create_test_circuit();

//         assert_eq!(circuit.degree_0_commitment, Some(Bn254Fr::from(1u64)));
//         assert_eq!(circuit.degree_1_commitment, Some(Bn254Fr::from(2u64)));
//         assert_eq!(
//             circuit.partial_decommitment.verifier_key,
//             Some(Bn254Fr::from(3u64))
//         );
//     }

//     #[test]
//     fn test_constraint_generation() {
//         let circuit = create_test_circuit();
//         let cs = ConstraintSystem::<Bn254Fr>::new_ref();
//         let result = circuit.generate_constraints(cs.clone());
//         let constraints = cs.constraint_names();
//         println!("Generated constraints: {:?}", constraints);
//         assert!(result.is_ok(), "Constraint generation should succeed");

//         let num_constraints = cs.num_constraints();
//         println!("Number of constraints generated: {}", num_constraints);
//         assert!(
//             num_constraints > 0,
//             "Expected constraints to be generated, but got {}",
//             num_constraints
//         );
//         assert!(
//             cs.is_satisfied().unwrap(),
//             "Constraints should be satisfied"
//         );
//     }
// }
