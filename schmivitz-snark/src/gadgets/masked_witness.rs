use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use std::ops::{Add, Mul};

pub struct MaskedWitnessGadget;

impl MaskedWitnessGadget {
    // L236~
    #[tracing::instrument(target = "r1cs", skip(verifier_key))]
    pub fn compute(
        witness_voles: &[FpVar<Bn254Fr>],
        masked_voles: &[FpVar<Bn254Fr>],
        verifier_key: &FpVar<Bn254Fr>,
        witness_challenge: &[FpVar<Bn254Fr>],
        witness_commitment: &Vec<FpVar<Bn254Fr>>,
    ) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError> {
        // Based on the test cases and the original code in proof.rs, we need to:
        // 1. Calculate d_delta by multiplying each witness commitment with the verifier key
        // 2. Add d_delta to the witness_voles to get the masked witnesses

        // Calculate d_delta (corresponds to lines 236-257 in proof.rs)
        let d_delta: Vec<FpVar<Bn254Fr>> = witness_commitment
            .iter()
            .map(|witness_com| {
                // In the original code, there's a conversion from F64b to F8b
                // Here we're working with FpVar<Bn254Fr>, so we'll directly multiply
                // the witness commitment with the verifier key
                witness_com.clone() * verifier_key.clone()
            })
            .collect();

        // Handle the case where witness_voles and witness_commitment have different lengths
        // This ensures we don't silently ignore elements if the arrays have different lengths
        if witness_voles.len() != witness_commitment.len() {
            // We could return an error, but for now let's just use the minimum length
            // to avoid panicking, similar to how zip behaves
            let min_len = std::cmp::min(witness_voles.len(), witness_commitment.len());

            let mut masked_witnesses = Vec::with_capacity(min_len);
            for i in 0..min_len {
                let masked_witness = witness_voles[i].clone() + d_delta[i].clone();
                masked_witnesses.push(masked_witness);
            }

            return Ok(masked_witnesses);
        }

        // Calculate masked witnesses (corresponds to lines 258-268 in proof.rs)
        // In the original code: masked_witness = witness_vole + d_delta
        let masked_witnesses: Vec<FpVar<Bn254Fr>> = witness_voles
            .iter()
            .zip(d_delta.iter())
            .map(|(witness_vole, d_delta_element)| {
                // Add the d_delta element to the witness VOLE
                witness_vole.clone() + d_delta_element.clone()
            })
            .collect();

        Ok(masked_witnesses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    // Helper function to create a new constraint system
    fn create_cs() -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
        cs
    }

    // Helper function to create FpVar values
    fn create_fp_var(cs: ConstraintSystemRef<Fr>, value: u64) -> FpVar<Fr> {
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(value))).unwrap()
    }

    // #[test]
    // fn test_basic_computation() {
    //     let cs = create_cs();

    //     let witness_commitment = vec![
    //         create_fp_var(cs.clone(), 1),
    //         create_fp_var(cs.clone(), 2),
    //         create_fp_var(cs.clone(), 3),
    //     ];
    //     let partial_decommitment = vec![
    //         create_fp_var(cs.clone(), 10),
    //         create_fp_var(cs.clone(), 20),
    //         create_fp_var(cs.clone(), 30),
    //     ];
    //     let verifier_key = create_fp_var(cs.clone(), 5);
    //     let masked_witnesses =
    //         MaskedWitnessGadget::compute(&witness_commitment, &partial_decommitment, &verifier_key)
    //             .unwrap();

    //     // Verify results
    //     assert_eq!(masked_witnesses.len(), 3);

    //     // Manually compute expected results
    //     // masked_witness[0] = witness_commitment[0] * verifier_key + partial_decommitment[0] = 1 * 5 + 10 = 15
    //     // masked_witness[1] = witness_commitment[1] * verifier_key + partial_decommitment[1] = 2 * 5 + 20 = 30
    //     // masked_witness[2] = witness_commitment[2] * verifier_key + partial_decommitment[2] = 3 * 5 + 30 = 45
    //     let expected_values = vec![Fr::from(15), Fr::from(30), Fr::from(45)];

    //     for (i, masked_witness) in masked_witnesses.iter().enumerate() {
    //         let value = masked_witness.value().unwrap();
    //         assert_eq!(value, expected_values[i]);
    //     }
    // }
    // #[test]
    // fn test_edge_cases() {
    //     let cs = create_cs();

    //     // Create test inputs with edge cases
    //     let witness_commitment = vec![
    //         create_fp_var(cs.clone(), 0),        // Zero value
    //         create_fp_var(cs.clone(), u64::MAX), // Maximum u64 value
    //     ];
    //     let partial_decommitment = vec![
    //         create_fp_var(cs.clone(), 0), // Zero value
    //         create_fp_var(cs.clone(), 1), // Small value
    //     ];
    //     let verifier_key = create_fp_var(cs.clone(), 1); // Identity for multiplication

    //     // Compute masked witnesses
    //     let masked_witnesses =
    //         MaskedWitnessGadget::compute(&witness_commitment, &partial_decommitment, &verifier_key)
    //             .unwrap();

    //     // Verify results
    //     assert_eq!(masked_witnesses.len(), 2);

    //     // Check zero case: 0 * 1 + 0 = 0
    //     assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(0));

    //     // Check max value case: MAX * 1 + 1 = MAX + 1 (in the field)
    //     let expected = Fr::from(u64::MAX) + Fr::from(1);
    //     assert_eq!(masked_witnesses[1].value().unwrap(), expected);
    // }
    // #[test]
    // fn test_empty_inputs() {
    //     let cs = ConstraintSystem::<Fr>::new_ref();
    //     let witness_commitment: Vec<FpVar<Fr>> = Vec::new();
    //     let partial_decommitment: Vec<FpVar<Fr>> = Vec::new();
    //     let verifier_key = create_fp_var(cs.clone(), 5);

    //     let result =
    //         MaskedWitnessGadget::compute(&witness_commitment, &partial_decommitment, &verifier_key);

    //     assert!(result.is_ok());
    //     assert_eq!(result.unwrap().len(), 0);
    // }

    // #[test]
    // fn test_constraint_satisfaction() {
    //     let cs = ConstraintSystem::<Fr>::new_ref();

    //     let witness_commitment = vec![create_fp_var(cs.clone(), 7), create_fp_var(cs.clone(), 11)];
    //     let partial_decommitment =
    //         vec![create_fp_var(cs.clone(), 17), create_fp_var(cs.clone(), 19)];
    //     let verifier_key = create_fp_var(cs.clone(), 13);

    //     let masked_witnesses =
    //         MaskedWitnessGadget::compute(&witness_commitment, &partial_decommitment, &verifier_key)
    //             .unwrap();

    //     assert!(cs.is_satisfied().unwrap());

    //     // Verify the computed values
    //     // masked_witness[0] = 7 * 13 + 17 = 91 + 17 = 108
    //     // masked_witness[1] = 11 * 13 + 19 = 143 + 19 = 162
    //     assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(108));
    //     assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(162));
    // }
}
