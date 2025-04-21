use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{
    CircuitTraversalGadget, ConstraintVerificationGadget, Gate, MaskedWitnessGadget,
};

pub struct VoleVerificationCircuit {
    // Public inputs
    pub degree_0_commitment: Bn254Fr,
    pub degree_1_commitment: Bn254Fr,
    pub verifier_key: Bn254Fr, // this variable is should be in the partial decommitment?

    // Private inputs (witness)
    pub witness_commitment: Vec<Bn254Fr>,
    pub partial_decommitment: Vec<Bn254Fr>,
    pub witness_challenges: Vec<Bn254Fr>,

    // Circuit description
    pub circuit_gates: Vec<Gate>,
}

impl ConstraintSynthesizer<Bn254Fr> for VoleVerificationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        let degree_0_commitment_var =
            FpVar::new_input(cs.clone(), || Ok(self.degree_0_commitment))?;
        let degree_1_commitment_var =
            FpVar::new_input(cs.clone(), || Ok(self.degree_1_commitment))?;
        let verifier_key_var = FpVar::new_input(cs.clone(), || Ok(self.verifier_key))?;

        let witness_commitment_var =
            Vec::<FpVar<Bn254Fr>>::new_witness(cs.clone(), || Ok(self.witness_commitment.clone()))?;

        let partial_decommitment_var = Vec::<FpVar<Bn254Fr>>::new_witness(cs.clone(), || {
            Ok(self.partial_decommitment.clone())
        })?;

        let witness_challenges_var =
            Vec::<FpVar<Bn254Fr>>::new_witness(cs.clone(), || Ok(self.witness_challenges.clone()))?;

        let masked_witnesses_var = MaskedWitnessGadget::compute(
            cs.clone(),
            &witness_commitment_var,
            &partial_decommitment_var,
            &verifier_key_var,
        )?;

        let validation_aggregate_var = if self.circuit_gates.is_empty() {
            // If no circuit gates are provided, use the simplified dot product method
            CircuitTraversalGadget::compute_validation_aggregate(
                cs.clone(),
                &witness_challenges_var,
                &masked_witnesses_var,
            )?
        } else {
            // If circuit gates are provided, use the full circuit traversal method
            CircuitTraversalGadget::compute_validation_aggregate_with_circuit(
                cs.clone(),
                witness_challenges_var,
                verifier_key_var.clone(),
                masked_witnesses_var,
                &self.circuit_gates,
            )?
        };

        let is_valid = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation_aggregate_var,
            &degree_0_commitment_var,
            &degree_1_commitment_var,
            &verifier_key_var,
        )?;

        // Enforce that the verification passes
        is_valid.enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}
