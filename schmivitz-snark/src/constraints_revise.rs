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
            cs.clone(),
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
