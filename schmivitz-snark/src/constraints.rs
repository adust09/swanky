use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{CircuitTraversalGadget, ConstraintVerificationGadget, MaskedWitnessVar};

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
    pub mask_voles: Option<Vec<Bn254Fr>>,
    pub witness_voles: Option<Vec<Bn254Fr>>,
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
        let verifier_key_var = FpVar::new_input(ark_relations::ns!(cs, "verifier_key"), || {
            self.partial_decommitment
                .verifier_key
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let witness_voles_var =
            Vec::<FpVar<Bn254Fr>>::new_witness(ark_relations::ns!(cs, "witness_voles"), || {
                self.partial_decommitment
                    .witness_voles
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;
        let mask_voles_var =
            Vec::<FpVar<Bn254Fr>>::new_witness(ark_relations::ns!(cs, "mask_voles"), || {
                self.partial_decommitment
                    .mask_voles
                    .ok_or(SynthesisError::AssignmentMissing)
            })?;

        let masked_witnesses_var = MaskedWitnessVar::compute(
            &witness_voles_var,
            &mask_voles_var,
            &verifier_key_var,
            &witness_challenges_var,
            &witness_commitment_var,
        )?;

        let validation_aggregate_var = CircuitTraversalGadget::compute_validation_aggregate(
            &witness_challenges_var,
            &masked_witnesses_var,
        )?;

        ConstraintVerificationGadget::verify(
            &validation_aggregate_var,
            &degree_0_commitment_var,
            &degree_1_commitment_var,
            &verifier_key_var,
        )?
        .enforce_equal(&Boolean::TRUE)
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
                mask_voles: vec![Bn254Fr::from(6u64), Bn254Fr::from(7u64)].into(),
                witness_voles: vec![Bn254Fr::from(10u64), Bn254Fr::from(11u64)].into(),
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
