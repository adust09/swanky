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
    pub mask_voles: Option<[Bn254Fr; REPETITION_PARAM * VOLE_SIZE_PARAM]>, // todo: use in combine
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
        let verifier_key_var = FpVar::new_input(ark_relations::ns!(cs, "verifier_key"), || {
            self.partial_decommitment
                .verifier_key
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

        // Step 1: Compute d_delta
        let mut d_delta_var = Vec::with_capacity(witness_commitment_var.len());

        // For each witness commitment, compute d_delta array
        for commitment in witness_commitment_var.iter() {
            // Create an array of REPETITION_PARAM elements
            let mut delta_array = Vec::with_capacity(REPETITION_PARAM);

            // In proof.rs, each witness commitment is multiplied by each key in the verifier_key_array
            // Here, we'll create an array where the first element is commitment * verifier_key
            // and the rest are zeros (since we don't have the bit conversion logic from proof.rs)
            let delta = commitment.clone() * verifier_key_var.clone();

            // Add the delta as the first element
            delta_array.push(delta);

            // Add zeros for the rest of the elements
            for _ in 1..REPETITION_PARAM {
                // Create a zero FpVar
                let zero_var = FpVar::<Bn254Fr>::new_constant(
                    ark_relations::ns!(cs, "zero"),
                    Bn254Fr::from(0),
                )?;
                delta_array.push(zero_var);
            }

            // Convert Vec to array
            let delta_array: [FpVar<Bn254Fr>; REPETITION_PARAM] = delta_array.try_into().unwrap();
            d_delta_var.push(delta_array);
        }

        // Step 2: Compute masked witnesses
        let masked_witnesses_var =
            MaskedWitnessVar::compute_masked_witness(&witness_voles_var, &d_delta_var)?;
        let validation_aggregate_var = CircuitTraverser::compute_validation_aggregate(
            &witness_challenges_var, // challengesに名を変え、into_partで使われる
            &masked_witnesses_var,
        )?;

        // let validation_mask_var = combine(self.partial_decommitment.mask_voles());
        // let validation = validation_aggregate_var + validation_mask;

        let degree_0_commitment_var =
            FpVar::new_input(ark_relations::ns!(cs, "degree_0_commitment"), || {
                self.degree_0_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let degree_1_commitment_var =
            FpVar::new_input(ark_relations::ns!(cs, "degree_1_commitment"), || {
                self.degree_1_commitment
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let actual_validation_var =
            degree_1_commitment_var.clone() * verifier_key_var + degree_0_commitment_var;
        validation_aggregate_var.enforce_equal(&actual_validation_var) // gadgetを無視してもfailsするのはcomvineとかやってないから
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
