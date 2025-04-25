use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{CircuitTraversalGadget, ConstraintVerificationGadget, MaskedWitnessGadget};

#[derive(Debug, Clone)]
pub struct VoleVerification {
    // Public inputs
    pub degree_0_commitment: Bn254Fr,
    pub degree_1_commitment: Bn254Fr,
    pub verifier_key: Bn254Fr, // this variable is should be in the partial decommitment?

    // Private inputs (witness)
    pub witness_commitment: Vec<Bn254Fr>,
    pub partial_decommitment: Vec<Bn254Fr>,
    pub witness_challenges: Vec<Bn254Fr>,
}

// impl VoleVerificationCircuit {
//     fn validate_witness(&self) -> Result<(), SynthesisError> {
//         self.validate_vector_sizes()?;
//         self.validate_witness_size_against_circuit()?;

//         Ok(())
//     }

// fn validate_vector_sizes(&self) -> Result<(), SynthesisError> {
//     if self.witness_commitment.is_empty() {
//         return Err(SynthesisError::Unsatisfiable);
//     }
//     if self.partial_decommitment.is_empty() {
//         return Err(SynthesisError::Unsatisfiable);
//     }
//     if self.witness_challenges.is_empty() {
//         return Err(SynthesisError::Unsatisfiable);
//     }

//     Ok(())
// }

//     fn validate_witness_size_against_circuit(&self) -> Result<(), SynthesisError> {
//         let max_wire_id = self.calculate_max_wire_id();

//         if self.witness_commitment.len() < max_wire_id + 1 {
//             return Err(SynthesisError::Unsatisfiable);
//         }

//         Ok(())
//     }

//     fn calculate_max_wire_id(&self) -> usize {
//         let mut max_id = 0;

//         for gate in &self.circuit_gates {
//             match gate {
//                 Gate::Add { dst, left, right } => {
//                     max_id = max_id.max(*dst).max(*left).max(*right);
//                 }
//                 Gate::Mul { dst, left, right } => {
//                     max_id = max_id.max(*dst).max(*left).max(*right);
//                 }
//                 Gate::PrivateInput { dst_range } => {
//                     max_id = max_id.max(dst_range.end);
//                 }
//             }
//         }
//         max_id.try_into().unwrap()
//     }
// }

impl ConstraintSynthesizer<Bn254Fr> for VoleVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        // self.validate_witness()?;
        let degree_0_commitment_var =
            FpVar::new_input(ark_relations::ns!(cs, "degree_0_commitment"), || {
                Ok(&self.degree_0_commitment)
            })?;
        let degree_1_commitment_var =
            FpVar::new_input(ark_relations::ns!(cs, "degree_1_commitment"), || {
                Ok(&self.degree_1_commitment)
            })?;
        let verifier_key_var = FpVar::new_input(ark_relations::ns!(cs, "verifier_key"), || {
            Ok(&self.verifier_key)
        })?;

        let witness_commitment_var = Vec::<FpVar<Bn254Fr>>::new_witness(
            ark_relations::ns!(cs, "witness_commitment"),
            || Ok(self.witness_commitment.clone()),
        )?;
        let partial_decommitment_var = Vec::<FpVar<Bn254Fr>>::new_witness(
            ark_relations::ns!(cs, "partial_decommitment"),
            || Ok(self.partial_decommitment.clone()),
        )?;
        let witness_challenges_var = Vec::<FpVar<Bn254Fr>>::new_witness(
            ark_relations::ns!(cs, "witness_challenges"),
            || Ok(self.witness_challenges.clone()),
        )?;

        // if witness_commitment_var.len() != partial_decommitment_var.len() {
        //     println!("witness_commitment_var.len() != partial_decommitment_var.len()");
        //     println!(
        //         "witness_commitment_var: {:?}\n",
        //         witness_commitment_var.len()
        //     );
        //     println!(
        //         "partial_decommitment_var: {:?}\n",
        //         partial_decommitment_var.len()
        //     );
        //     // setup時にここで死ぬ
        //     return Err(SynthesisError::Unsatisfiable);
        // }
        // if witness_commitment_var.len() != witness_challenges_var.len() {
        //     println!("witness_commitment_var.len() != witness_challenges_var.len()");
        //     println!(
        //         "witness_commitment_var: {:?}\n",
        //         witness_commitment_var.len()
        //     );
        //     println!(
        //         "witness_challenges_var: {:?}\n",
        //         witness_challenges_var.len()
        //     );
        //     return Err(SynthesisError::Unsatisfiable);
        // }

        let masked_witnesses_var = MaskedWitnessGadget::compute(
            &witness_commitment_var,
            &partial_decommitment_var,
            &verifier_key_var,
        )?;

        // if witness_challenges_var.len() != masked_witnesses_var.len() {
        //     println!("witness_challenges_var.len() != masked_witnesses_var.len()");
        //     println!(
        //         "witness_challenges_var: {:?}\n",
        //         witness_challenges_var.len()
        //     );
        //     println!("masked_witnesses_var: {:?}\n", masked_witnesses_var.len());
        //     return Err(SynthesisError::Unsatisfiable);
        // }

        let validation_aggregate_var = CircuitTraversalGadget::compute_validation_aggregate(
            &witness_challenges_var,
            &masked_witnesses_var,
        )?;

        let result = ConstraintVerificationGadget::verify(
            &validation_aggregate_var,
            &degree_0_commitment_var,
            &degree_1_commitment_var,
            &verifier_key_var,
        )?
        .enforce_equal(&Boolean::TRUE);
        print!(
            "Validation result: {:?} \n",
            validation_aggregate_var.value()
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::ConstraintSystem;

    fn create_test_circuit() -> VoleVerification {
        VoleVerification {
            // Public inputs
            degree_0_commitment: Bn254Fr::from(1u64),
            degree_1_commitment: Bn254Fr::from(2u64),
            verifier_key: Bn254Fr::from(3u64),

            // Private inputs (witness)
            witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)],
            partial_decommitment: vec![Bn254Fr::from(6u64), Bn254Fr::from(7u64)],
            witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)],
        }
    }

    #[test]
    fn test_circuit_creation() {
        let circuit = create_test_circuit();

        assert_eq!(circuit.degree_0_commitment, Bn254Fr::from(1u64));
        assert_eq!(circuit.degree_1_commitment, Bn254Fr::from(2u64));
        assert_eq!(circuit.verifier_key, Bn254Fr::from(3u64));
        assert_eq!(circuit.witness_commitment.len(), 2);
        assert_eq!(circuit.partial_decommitment.len(), 2);
        assert_eq!(circuit.witness_challenges.len(), 2);
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

    #[test]
    fn test_circuit_with_different_sizes() {
        let circuit = VoleVerification {
            degree_0_commitment: Bn254Fr::from(1u64),
            degree_1_commitment: Bn254Fr::from(2u64),
            verifier_key: Bn254Fr::from(3u64),
            witness_commitment: vec![Bn254Fr::from(4u64); 10],
            partial_decommitment: vec![Bn254Fr::from(6u64); 10],
            witness_challenges: vec![Bn254Fr::from(8u64); 10],
        };

        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        let result = circuit.generate_constraints(cs.clone());
        let constraints = cs.constraint_names();
        println!("Generated constraints: {:?}", constraints);
        assert!(
            result.is_ok(),
            "Constraint generation should succeed with different sizes"
        );
        assert!(
            cs.is_satisfied().unwrap(),
            "Constraints should be satisfied"
        );
    }
}
