use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::ops::{Add, Mul};

/// CircuitTraversalGadget is responsible for traversing the circuit structure
/// and computing the validation aggregate based on witness challenges and masked witnesses.
pub struct CircuitTraversalGadget;

impl CircuitTraversalGadget {
    /// Computes the validation aggregate by traversing the circuit structure.
    ///
    /// # Arguments
    ///
    /// * `cs` - Constraint system reference
    /// * `witness_challenge` - Array of witness challenges
    /// * `verifier_key` - Verifier key
    /// * `masked_witnesses` - Array of masked witnesses computed from witness commitments
    ///
    /// # Returns
    ///
    /// * Result containing the validation aggregate or a synthesis error
    pub fn compute_validation_aggregate(
        cs: ConstraintSystemRef<Bn254Fr>,
        witness_challenge: &[FpVar<Bn254Fr>],
        verifier_key: &FpVar<Bn254Fr>,
        masked_witnesses: &[FpVar<Bn254Fr>],
    ) -> Result<FpVar<Bn254Fr>, SynthesisError> {
        // Ensure we have the same number of challenges as masked witnesses
        if witness_challenge.len() != masked_witnesses.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Initialize the validation aggregate with zero
        let mut validation_aggregate = FpVar::zero();

        // Traverse the circuit structure and compute the validation aggregate
        // The validation aggregate is computed as the sum of (challenge * masked_witness)
        // for each wire in the circuit
        for (challenge, masked_witness) in witness_challenge.iter().zip(masked_witnesses.iter()) {
            // Compute challenge * masked_witness
            let term = challenge.mul(masked_witness);

            // Add to the validation aggregate
            validation_aggregate = validation_aggregate.add(&term);
        }

        Ok(validation_aggregate)
    }
}
