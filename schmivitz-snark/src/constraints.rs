// use ark_bn254::Fr as Bn254Fr;
// use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
// use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
// use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};

// use crate::{
//     gadgets::{CircuitTraverser, MaskedWitnessVar},
//     save_variables_to_json,
// };

// #[derive(Debug, Clone)]
// pub struct VoleVerification {
//     // vole_challenge(missed but only used in outside of verification logic)
//     pub witness_commitment: Option<Vec<Bn254Fr>>,
//     pub witness_challenges: Option<Vec<Bn254Fr>>,
//     pub degree_0_commitment: Option<Bn254Fr>,
//     pub degree_1_commitment: Option<Bn254Fr>,
//     //decommitment_challenge(missed but only used in outside of verification logic)
//     pub partial_decommitment: PartialDecommitmentVar,
//     pub schmivitz_values: Option<SchmivitzValues>,
// }

// #[derive(Debug, Clone)]
// pub struct SchmivitzValues {
//     pub d_delta: Option<Vec<[Bn254Fr; REPETITION_PARAM]>>,
//     pub masked_witnesses: Option<Vec<Bn254Fr>>,
//     pub validation_mask: Option<Bn254Fr>,
//     pub validation_aggregate: Option<Bn254Fr>,
//     pub validation_from_schmivitz: Option<Bn254Fr>,
//     pub actual_validation: Option<Bn254Fr>,
// }
// #[derive(Debug, Clone)]
// pub struct PartialDecommitmentVar {
//     pub verifier_key: Option<Bn254Fr>,
//     pub witness_voles: Option<Vec<[Bn254Fr; REPETITION_PARAM]>>,
//     pub mask_voles: Option<[Bn254Fr; REPETITION_PARAM * VOLE_SIZE_PARAM]>,
// }

// impl ConstraintSynthesizer<Bn254Fr> for VoleVerification {
//     fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
//         let witness_commitment_var = Vec::<FpVar<Bn254Fr>>::new_witness(
//             ark_relations::ns!(cs, "witness_commitment"),
//             || {
//                 self.witness_commitment
//                     .ok_or(SynthesisError::AssignmentMissing)
//             },
//         )?;
//         let witness_challenges_var = Vec::<FpVar<Bn254Fr>>::new_witness(
//             ark_relations::ns!(cs, "witness_challenges"),
//             || {
//                 self.witness_challenges
//                     .ok_or(SynthesisError::AssignmentMissing)
//             },
//         )?;

//         let verifier_key_var = FpVar::new_witness(ark_relations::ns!(cs, "verifier_key"), || {
//             self.partial_decommitment
//                 .verifier_key
//                 .ok_or(SynthesisError::AssignmentMissing)
//         })?;

//         let degree_0_commitment_var =
//             FpVar::new_witness(ark_relations::ns!(cs, "degree_0_commitment"), || {
//                 self.degree_0_commitment
//                     .ok_or(SynthesisError::AssignmentMissing)
//             })?;
//         let degree_1_commitment_var =
//             FpVar::new_witness(ark_relations::ns!(cs, "degree_1_commitment"), || {
//                 self.degree_1_commitment
//                     .ok_or(SynthesisError::AssignmentMissing)
//             })?;
//         let d_delta_from_schmivitz_var =
//             FpVar::new_witness(ark_relations::ns!(cs, "d_delta_from_schmivitz"), || {
//                 self.schmivitz_values
//                     .clone()
//                     .unwrap()
//                     .d_delta
//                     .as_ref()
//                     .and_then(|v| v.first().map(|arr| arr[0]))
//                     .ok_or(SynthesisError::AssignmentMissing)
//             })?;
//         let masked_witness_from_schmivitz_var = FpVar::new_witness(
//             ark_relations::ns!(cs, "mask_witness_from_schmivitz"),
//             || {
//                 self.schmivitz_values
//                     .clone()
//                     .unwrap()
//                     .masked_witnesses
//                     .as_ref()
//                     .and_then(|v| v.first())
//                     .copied()
//                     .ok_or(SynthesisError::AssignmentMissing)
//             },
//         )?;
//         let validation_mask_from_schmivitz_var = FpVar::new_witness(
//             ark_relations::ns!(cs, "validation_mask_from_schmivitz"),
//             || {
//                 self.schmivitz_values
//                     .clone()
//                     .unwrap()
//                     .validation_mask
//                     .ok_or(SynthesisError::AssignmentMissing)
//             },
//         )?;
//         let validation_aggregate_from_schmivitz_var =
//             FpVar::new_witness(ark_relations::ns!(cs, "validation_aggregate"), || {
//                 self.schmivitz_values
//                     .clone()
//                     .unwrap()
//                     .validation_aggregate
//                     .ok_or(SynthesisError::AssignmentMissing)
//             })?;
//         let validation_from_schmivitz_var =
//             FpVar::new_witness(ark_relations::ns!(cs, "validation_from_schmivitz"), || {
//                 self.schmivitz_values
//                     .clone()
//                     .unwrap()
//                     .validation_from_schmivitz
//                     .ok_or(SynthesisError::AssignmentMissing)
//             })?;
//         let actual_validation_from_schmivitz_var = FpVar::new_witness(
//             ark_relations::ns!(cs, "actual_validation_from_schmivitz"),
//             || {
//                 self.schmivitz_values
//                     .clone()
//                     .unwrap()
//                     .actual_validation
//                     .ok_or(SynthesisError::AssignmentMissing)
//             },
//         )?;

//         // Get the witness voles from the partial decommitment
//         let witness_voles = self
//             .partial_decommitment
//             .witness_voles
//             .clone()
//             .ok_or(SynthesisError::AssignmentMissing)?;

//         // Create a vector to hold the witness vole
//         let mut witness_voles_var = Vec::with_capacity(witness_voles.len());

//         // For each vole array in the witness voles
//         for vole_array in witness_voles.iter() {
//             // Create a vector to hold the FpVar elements for this array
//             let mut fp_vec = Vec::with_capacity(REPETITION_PARAM);

//             // For each element in the vole array
//             for val in vole_array.iter() {
//                 // Create a witness variable for the element
//                 let var =
//                     FpVar::new_witness(ark_relations::ns!(cs, "witness_vole_element"), || {
//                         Ok(*val)
//                     })?;
//                 fp_vec.push(var);
//             }

//             witness_voles_var.push(fp_vec);
//         }

//         // Step 1: Compute d_delta from witness commitment and verifier key
//         let d_delta_var = MaskedWitnessVar::compute_d_delta(
//             cs.clone(),
//             &witness_commitment_var,
//             &verifier_key_var.clone(),
//         )?;

//         // Step 2: Compute masked witnesses from witness voles and d_delta
//         let masked_witnesses_var =
//             MaskedWitnessVar::compute_masked_witness(&witness_voles_var, &d_delta_var)?;

//         let validation_aggregate_var = CircuitTraverser::compute_validation_aggregate(
//             &witness_challenges_var,
//             &masked_witnesses_var,
//         )?;

//         // Step 3: Combine mask VOLEs to get validation_mask (q* in proof.rs)
//         // Get the mask_voles from the partial_decommitment
//         let mask_voles = self
//             .partial_decommitment
//             .mask_voles
//             .clone()
//             .ok_or(SynthesisError::AssignmentMissing)?;

//         // Create FpVar variables for each mask_vole
//         let mut mask_voles_var = Vec::with_capacity(mask_voles.len());
//         for val in mask_voles.iter() {
//             let var = FpVar::new_witness(ark_relations::ns!(cs, "mask_vole_element"), || Ok(*val))?;
//             mask_voles_var.push(var);
//         }

//         // Compute validation_mask using the refactored function
//         let validation_mask_var =
//             MaskedWitnessVar::compute_validation_mask(cs.clone(), &mask_voles_var)?;

//         // Step 4: Compute the final validation value
//         // In proof.rs: let validation = validation_aggregate + validation_mask;
//         let validation_var = validation_aggregate_var.clone() + validation_mask_var.clone();

//         // Step 5: Check the main constraint of the proof
//         let actual_validation_var = degree_1_commitment_var.clone() * verifier_key_var.clone()
//             + degree_0_commitment_var.clone();
//         // validation_var.enforce_equal(&actual_validation_var)
//         let result = validation_aggregate_from_schmivitz_var.clone()
//             + validation_mask_from_schmivitz_var.clone();
//         // Optionally store the values in a JSON file
//         if cs.is_in_setup_mode() == false {
//             // Convert d_delta_var to match the expected type Vec<[FpVar<Bn254Fr>; REPETITION_PARAM]>
//             save_variables_to_json(
//                 &witness_commitment_var,
//                 &witness_challenges_var,
//                 &verifier_key_var,
//                 &degree_0_commitment_var,
//                 &degree_1_commitment_var,
//                 &validation_var,
//                 &actual_validation_var,
//                 &validation_aggregate_var,
//                 &validation_mask_var,
//                 &masked_witnesses_var,
//                 &d_delta_var,
//                 &mask_voles_var,
//                 &witness_voles_var,
//                 Some(&validation_from_schmivitz_var),
//                 Some(&actual_validation_from_schmivitz_var),
//                 // New parameters
//                 &d_delta_from_schmivitz_var,
//                 &masked_witness_from_schmivitz_var,
//                 &validation_aggregate_from_schmivitz_var,
//                 &validation_mask_from_schmivitz_var,
//                 &result, // Add the result variable
//             );
//         }
//         Ok(())
//     }
// }

// // #[cfg(test)]
// // mod tests {
// //     use super::*;
// //     use ark_bn254::Fr as Bn254Fr;
// //     use ark_relations::r1cs::ConstraintSystem;

// //     fn create_test_circuit() -> VoleVerification {
// //         VoleVerification {
// //             witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)].into(),
// //             witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)].into(),
// //             degree_0_commitment: Some(Bn254Fr::from(1u64)),
// //             degree_1_commitment: Some(Bn254Fr::from(2u64)),
// //             partial_decommitment: PartialDecommitmentVar {
// //                 verifier_key: Some(Bn254Fr::from(3u64)),
// //                 witness_voles: {
// //                     let mut arr = [Bn254Fr::default(); REPETITION_PARAM];
// //                     arr[0] = Bn254Fr::from(10u64);
// //                     arr[1] = Bn254Fr::from(11u64);
// //                     vec![arr].into()
// //                 },
// //                 mask_voles: {
// //                     let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
// //                     array[0] = Bn254Fr::from(6u64);
// //                     array[1] = Bn254Fr::from(7u64);
// //                     Some(array)
// //                 },
// //             },
// //         }
// //     }

// //     #[test]
// //     fn test_circuit_creation() {
// //         let circuit = create_test_circuit();

// //         assert_eq!(circuit.degree_0_commitment, Some(Bn254Fr::from(1u64)));
// //         assert_eq!(circuit.degree_1_commitment, Some(Bn254Fr::from(2u64)));
// //         assert_eq!(
// //             circuit.partial_decommitment.verifier_key,
// //             Some(Bn254Fr::from(3u64))
// //         );
// //     }

// //     #[test]
// //     fn test_constraint_generation() {
// //         let circuit = create_test_circuit();
// //         let cs = ConstraintSystem::<Bn254Fr>::new_ref();
// //         let result = circuit.generate_constraints(cs.clone());
// //         let constraints = cs.constraint_names();
// //         println!("Generated constraints: {:?}", constraints);
// //         assert!(result.is_ok(), "Constraint generation should succeed");

// //         let num_constraints = cs.num_constraints();
// //         println!("Number of constraints generated: {}", num_constraints);
// //         assert!(
// //             num_constraints > 0,
// //             "Expected constraints to be generated, but got {}",
// //             num_constraints
// //         );
// //         assert!(
// //             cs.is_satisfied().unwrap(),
// //             "Constraints should be satisfied"
// //         );
// //     }
// // }
use std::iter::zip;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::MaskedWitnessVarRevised;

#[derive(Debug, Clone)]
pub struct VoleVerificationBoolean {
    pub witness_commitment: Vec<Vec<Boolean<Bn254Fr>>>, // F64b as boolean arrays
    pub witness_challenges: Vec<Vec<Boolean<Bn254Fr>>>, // F128b as boolean arrays
    pub degree_0_commitment: Vec<Boolean<Bn254Fr>>,     // F128b as boolean array
    pub degree_1_commitment: Vec<Boolean<Bn254Fr>>,     // F128b as boolean array
    pub partial_decommitment: PartialDecommitmentBoolean,
}

#[derive(Debug, Clone)]
pub struct PartialDecommitmentBoolean {
    pub verifier_key: Vec<Boolean<Bn254Fr>>, // F128b as boolean array
    pub witness_voles: Vec<Vec<Vec<Boolean<Bn254Fr>>>>, // Vec<[F8b; REPETITION_PARAM]> as boolean arrays
    pub mask_voles: Vec<Vec<Boolean<Bn254Fr>>>, // [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] as boolean arrays
}

impl ConstraintSynthesizer<Bn254Fr> for VoleVerificationBoolean {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError>
    where
        Bn254Fr: PrimeField,
    {
        // Step 1: Compute d_delta from witness commitment and verifier key
        let d_delta_var = MaskedWitnessVarRevised::compute_d_delta(
            &self.witness_commitment,
            &self.partial_decommitment.verifier_key.clone(),
        )?;

        // Step 2: Compute masked witnesses from witness voles and d_delta
        let masked_witnesses_var = MaskedWitnessVarRevised::compute_masked_witness(
            &self.partial_decommitment.witness_voles,
            &d_delta_var,
        )?;

        // Step 3: Compute validation_mask
        let validation_mask_var = MaskedWitnessVarRevised::compute_validation_mask(
            cs.clone(),
            &self.partial_decommitment.mask_voles,
        )?;

        println!("is_satisfied: {:?}\n", cs.is_satisfied());

        let validation_aggregate_var =
            MaskedWitnessVarRevised::compute_validation_aggregate_revise(
                &self.witness_challenges,
                &masked_witnesses_var,
            )?;

        // Step 4: Compute the final validation value
        let validation_var = zip(validation_aggregate_var, validation_mask_var)
            .map(|(agg, mask)| agg.or(&mask))
            .collect::<Vec<_>>();

        // Step 5: Calculate actual_validation (degree_1_commitment * verifier_key + degree_0_commitment)
        // This corresponds to the calculation in proof.rs line 317-318:
        // let actual_validation = self.degree_1_commitment * self.partial_decommitment.verifier_key()
        //     + self.degree_0_commitment;

        // First, compute degree_1_commitment * verifier_key using Boolean operations
        let mut product = Vec::with_capacity(128);
        for _ in 0..128 {
            product.push(Boolean::constant(false));
        }

        // For each bit in degree_1_commitment
        for (i, d1_bit) in self.degree_1_commitment.iter().enumerate() {
            if i >= 128 {
                break;
            }

            // For each bit in verifier_key
            for (j, key_bit) in self.partial_decommitment.verifier_key.iter().enumerate() {
                if j >= 128 || i + j >= 128 {
                    continue;
                }

                // Compute d1_bit AND key_bit
                let and_result = Boolean::and(d1_bit, key_bit)?;

                // XOR with the corresponding bit in product (at position i+j)
                product[i + j] = Boolean::xor(&product[i + j], &and_result)?;
            }
        }

        // Now add degree_0_commitment to the product (XOR for boolean addition in F2)
        let actual_validation_var = zip(product, self.degree_0_commitment.clone())
            .map(|(prod_bit, d0_bit)| Boolean::xor(&prod_bit, &d0_bit))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        // Step 6: Check that validation_var equals actual_validation_var
        for (val_bit, actual_bit) in zip(&validation_var, &actual_validation_var) {
            val_bit.clone().unwrap().clone().enforce_equal(actual_bit)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};

    #[test]
    fn test_boolean_circuit_creation() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create some test boolean values
        let test_boolean = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let test_boolean_vec = vec![test_boolean.clone(); 8]; // 8 bits for F8b

        // Create a test circuit
        let circuit = VoleVerificationBoolean {
            witness_commitment: vec![test_boolean_vec.clone(); 2],
            witness_challenges: vec![vec![test_boolean.clone(); 128]; 2], // 128 bits for F128b
            degree_0_commitment: vec![test_boolean.clone(); 128],
            degree_1_commitment: vec![test_boolean.clone(); 128],
            partial_decommitment: PartialDecommitmentBoolean {
                verifier_key: vec![test_boolean.clone(); 128],
                witness_voles: vec![vec![test_boolean_vec.clone(); REPETITION_PARAM]],
                mask_voles: vec![vec![test_boolean; 128]; REPETITION_PARAM * VOLE_SIZE_PARAM],
            },
        };

        // This test will fail because we're using placeholder values
        // In a real implementation, we would use actual boolean values
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
    }
}
