use std::iter::zip;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{boolean::Boolean, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use schmivitz::{insecure::InsecureVole, Proof};

use crate::{
    f128b_to_boolean_array, f8b_to_boolean_array, field_mappings::f128b_to_boolean_array_public,
    gadgets::ValidationVar,
};
use crate::{f64b_to_boolean_array, gadgets::MaskedWitnessVar};

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

pub fn build_circuit(
    cs: ark_relations::r1cs::ConstraintSystemRef<Bn254Fr>,
    schmivitz_proof: Proof<InsecureVole>,
) -> VoleVerificationBoolean {
    // Convert binary field elements to boolean arrays

    // Convert witness commitment (F64b) to boolean arrays
    let witness_commitment_booleans: Vec<Vec<Boolean<Bn254Fr>>> = schmivitz_proof
        .witness_commitment
        .iter()
        .map(|value| f64b_to_boolean_array(cs.clone(), value).unwrap())
        .collect();

    // Convert witness challenges (F128b) to boolean arrays
    let witness_challenges_booleans: Vec<Vec<Boolean<Bn254Fr>>> = schmivitz_proof
        .witness_challenges
        .iter()
        .map(|value| f128b_to_boolean_array_public(cs.clone(), value).unwrap())
        .collect();

    // Convert degree commitments to boolean arrays
    let degree_0_commitment_boolean =
        f128b_to_boolean_array(cs.clone(), &schmivitz_proof.degree_0_commitment).unwrap();

    let degree_1_commitment_boolean =
        f128b_to_boolean_array(cs.clone(), &schmivitz_proof.degree_1_commitment).unwrap();

    // Convert verifier key to boolean array
    let verifier_key_boolean = f128b_to_boolean_array(
        cs.clone(),
        &schmivitz_proof.partial_decommitment.verifier_key(),
    )
    .unwrap();

    // Process mask voles using boolean arrays
    let mask_voles_booleans: Vec<Vec<Boolean<Bn254Fr>>> = schmivitz_proof
        .partial_decommitment
        .mask_voles()
        .iter()
        .map(|value| f128b_to_boolean_array(cs.clone(), value).unwrap())
        .collect();

    // Process witness voles using boolean arrays
    let mut witness_voles_booleans = Vec::new();
    for arr in schmivitz_proof.partial_decommitment.witness_voles() {
        // Convert each F8b value to boolean array
        let arr_booleans: Vec<Vec<Boolean<Bn254Fr>>> = arr
            .iter()
            .map(|value| f8b_to_boolean_array(cs.clone(), value).unwrap())
            .collect();

        witness_voles_booleans.push(arr_booleans);
    }

    // Build the circuit with boolean arrays
    let circuit = VoleVerificationBoolean {
        witness_commitment: witness_commitment_booleans,
        witness_challenges: witness_challenges_booleans,
        degree_0_commitment: degree_0_commitment_boolean,
        degree_1_commitment: degree_1_commitment_boolean,
        partial_decommitment: PartialDecommitmentBoolean {
            verifier_key: verifier_key_boolean,
            mask_voles: mask_voles_booleans,
            witness_voles: witness_voles_booleans,
        },
    };

    circuit
}
