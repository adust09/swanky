use std::iter::zip;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::MaskedWitnessVar;
use crate::gadgets::ValidationVar;

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
    fn generate_constraints(self, _cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError>
    where
        Bn254Fr: PrimeField,
    {
        // Step 1: Compute d_delta from witness commitment and verifier key
        let d_delta_var = MaskedWitnessVar::compute_d_delta(
            &self.witness_commitment,
            &self.partial_decommitment.verifier_key.clone(),
        )?;

        // Step 2: Compute masked witnesses from witness voles and d_delta
        let masked_witnesses_var = MaskedWitnessVar::compute_masked_witness(
            &self.partial_decommitment.witness_voles,
            &d_delta_var,
        )?;

        // Step 3: Compute validation_mask
        let validation_mask_var = ValidationVar::combine(&self.partial_decommitment.mask_voles)?;

        // Step 4: Compute the final validation value
        let validation_aggregate_var = ValidationVar::compute_validation_aggregate(
            &self.witness_challenges,
            &masked_witnesses_var,
        )?;

        let validation_var = zip(validation_aggregate_var, validation_mask_var)
            .map(|(agg, mask)| agg.or(&mask))
            .collect::<Vec<_>>();

        // Step 5: Calculate actual_validation (degree_1_commitment * verifier_key + degree_0_commitment)
        let actual_validation_var = ValidationVar::compute_actual_validation(
            &self.degree_0_commitment,
            &self.degree_1_commitment,
            &self.partial_decommitment.verifier_key,
        )?;

        // Step 6: Check that validation_var equals actual_validation_var
        for (val_bit, actual_bit) in zip(&validation_var, &actual_validation_var) {
            val_bit.clone().unwrap().clone().enforce_equal(actual_bit)?;
        }

        Ok(())
    }
}
