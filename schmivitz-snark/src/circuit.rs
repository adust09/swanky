use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{CircuitTraversalGadget, ConstraintVerificationGadget, MaskedWitnessGadget};

pub struct VoleVerificationCircuit {
    // Public inputs
    pub degree_0_commitment: Bn254Fr,
    pub degree_1_commitment: Bn254Fr,
    pub verifier_key: Bn254Fr,
    pub validation_aggregate: Bn254Fr,

    // Private inputs (witness)
    pub witness_commitment: Vec<Bn254Fr>,
    pub partial_decommitment: Vec<Bn254Fr>,
    pub witness_challenges: Vec<Bn254Fr>,
}

// Entire the circuit should be implemented in below function
// Validating the proof structure
// Checking transcript challenges
// Computing masked witnesses
// Traversing the circuit to compute validation aggregates
// Verifying the final constraint equation

impl ConstraintSynthesizer<Bn254Fr> for VoleVerificationCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError> {
        // 1. Allocate public inputs
        let degree_0_commitment_var =
            FpVar::new_input(cs.clone(), || Ok(self.degree_0_commitment))?;
        let degree_1_commitment_var =
            FpVar::new_input(cs.clone(), || Ok(self.degree_1_commitment))?;
        let verifier_key_var = FpVar::new_input(cs.clone(), || Ok(self.verifier_key))?;
        let validation_aggregate_var =
            FpVar::new_input(cs.clone(), || Ok(self.validation_aggregate))?;
        // 2. Allocate private inputs
        let witness_commitment_var =
            Vec::<FpVar<Bn254Fr>>::new_witness(cs.clone(), || Ok(self.witness_commitment.clone()))?;

        let partial_decommitment_var = Vec::<FpVar<Bn254Fr>>::new_witness(cs.clone(), || {
            Ok(self.partial_decommitment.clone())
        })?;

        let witness_challenges_var =
            Vec::<FpVar<Bn254Fr>>::new_witness(cs.clone(), || Ok(self.witness_challenges.clone()))?;

        // 3. Compute masked witnesses
        let masked_witnesses_var = MaskedWitnessGadget::compute(
            cs.clone(),
            &witness_commitment_var,
            &verifier_key_var,
            &partial_decommitment_var,
        )?;

        // 4. Compute validation aggregate by traversing the circuit
        let computed_validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges_var,
            &verifier_key_var,
            &masked_witnesses_var,
        )?;

        // 5. Verify that the computed validation aggregate matches the provided one
        computed_validation_aggregate.enforce_equal(&validation_aggregate_var)?;

        // 6. Verify final constraint
        let is_valid = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation_aggregate_var,
            &degree_1_commitment_var,
            &verifier_key_var,
            &degree_0_commitment_var,
        )?;

        // Enforce that the verification passes
        is_valid.enforce_equal(&Boolean::constant(true))?;

        Ok(())
    }
}
