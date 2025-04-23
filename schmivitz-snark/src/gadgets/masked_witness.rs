use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::ops::{Add, Mul};

pub struct MaskedWitnessGadget;

impl MaskedWitnessGadget {
    // L236~L271
    pub fn compute(
        _cs: ConstraintSystemRef<Bn254Fr>,
        witness_commitment: &[FpVar<Bn254Fr>],
        partial_decommitment: &[FpVar<Bn254Fr>],
        verifier_key: &FpVar<Bn254Fr>,
    ) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError> {
        let mut masked_witnesses = Vec::new();
        for (i, witness) in witness_commitment.iter().enumerate() {
            let masked_witness = witness.mul(verifier_key).add(&partial_decommitment[i]);
            masked_witnesses.push(masked_witness);
        }
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

    #[test]
    fn test_basic_computation() {
        let cs = create_cs();

        // Create test inputs
        let witness_commitment = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
        ];
        let partial_decommitment = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];
        let verifier_key = create_fp_var(cs.clone(), 5);

        // Compute masked witnesses
        let masked_witnesses = MaskedWitnessGadget::compute(
            cs.clone(),
            &witness_commitment,
            &partial_decommitment,
            &verifier_key,
        )
        .unwrap();

        // Verify results
        assert_eq!(masked_witnesses.len(), 3);

        // Manually compute expected results
        // masked_witness[0] = witness_commitment[0] * verifier_key + partial_decommitment[0] = 1 * 5 + 10 = 15
        // masked_witness[1] = witness_commitment[1] * verifier_key + partial_decommitment[1] = 2 * 5 + 20 = 30
        // masked_witness[2] = witness_commitment[2] * verifier_key + partial_decommitment[2] = 3 * 5 + 30 = 45
        let expected_values = vec![Fr::from(15), Fr::from(30), Fr::from(45)];

        for (i, masked_witness) in masked_witnesses.iter().enumerate() {
            let value = masked_witness.value().unwrap();
            assert_eq!(value, expected_values[i]);
        }
    }

    #[test]
    /// Test with edge cases (zero values, maximum field values)
    fn test_edge_cases() {
        let cs = create_cs();

        // Create test inputs with edge cases
        let witness_commitment = vec![
            create_fp_var(cs.clone(), 0),        // Zero value
            create_fp_var(cs.clone(), u64::MAX), // Maximum u64 value
        ];
        let partial_decommitment = vec![
            create_fp_var(cs.clone(), 0), // Zero value
            create_fp_var(cs.clone(), 1), // Small value
        ];
        let verifier_key = create_fp_var(cs.clone(), 1); // Identity for multiplication

        // Compute masked witnesses
        let masked_witnesses = MaskedWitnessGadget::compute(
            cs.clone(),
            &witness_commitment,
            &partial_decommitment,
            &verifier_key,
        )
        .unwrap();

        // Verify results
        assert_eq!(masked_witnesses.len(), 2);

        // Check zero case: 0 * 1 + 0 = 0
        assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(0));

        // Check max value case: MAX * 1 + 1 = MAX + 1 (in the field)
        let expected = Fr::from(u64::MAX) + Fr::from(1);
        assert_eq!(masked_witnesses[1].value().unwrap(), expected);
    }

    #[test]
    fn test_empty_inputs() {
        let cs = create_cs();
        let witness_commitment: Vec<FpVar<Fr>> = Vec::new();
        let partial_decommitment: Vec<FpVar<Fr>> = Vec::new();
        let verifier_key = create_fp_var(cs.clone(), 5);

        let result = MaskedWitnessGadget::compute(
            cs.clone(),
            &witness_commitment,
            &partial_decommitment,
            &verifier_key,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_constraint_satisfaction() {
        let cs = create_cs();

        // Create test inputs
        let witness_commitment = vec![create_fp_var(cs.clone(), 7), create_fp_var(cs.clone(), 11)];
        let partial_decommitment =
            vec![create_fp_var(cs.clone(), 17), create_fp_var(cs.clone(), 19)];
        let verifier_key = create_fp_var(cs.clone(), 13);

        // Compute masked witnesses
        let masked_witnesses = MaskedWitnessGadget::compute(
            cs.clone(),
            &witness_commitment,
            &partial_decommitment,
            &verifier_key,
        )
        .unwrap();

        // Check that the constraints are satisfied
        assert!(cs.is_satisfied().unwrap());

        // Verify the computed values
        // masked_witness[0] = 7 * 13 + 17 = 91 + 17 = 108
        // masked_witness[1] = 11 * 13 + 19 = 143 + 19 = 162
        assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(108));
        assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(162));
    }
}
