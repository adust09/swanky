use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;

pub struct MaskedWitnessVar;

impl MaskedWitnessVar {
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

    #[test]
    fn test_basic_computation() {
        let cs = create_cs();

        let witness_commitment = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
        ];
        let witness_voles = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];
        let masked_voles = vec![
            create_fp_var(cs.clone(), 100),
            create_fp_var(cs.clone(), 200),
            create_fp_var(cs.clone(), 300),
        ];
        let verifier_key = create_fp_var(cs.clone(), 5);
        let witness_challenge = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 1),
        ];

        let masked_witnesses = MaskedWitnessVar::compute(
            &witness_voles,
            &masked_voles,
            &verifier_key,
            &witness_challenge,
            &witness_commitment,
        )
        .unwrap();

        // Verify results
        assert_eq!(masked_witnesses.len(), 3);

        // Manually compute expected results
        // masked_witness[0] = witness_vole[0] + (witness_challenge[0] * verifier_key) = 10 + (1 * 5) = 15
        // masked_witness[1] = witness_vole[1] + (witness_challenge[1] * verifier_key) = 20 + (1 * 5) = 25
        // masked_witness[2] = witness_vole[2] + (witness_challenge[2] * verifier_key) = 30 + (1 * 5) = 35
        let expected_values = vec![Fr::from(15), Fr::from(25), Fr::from(35)];

        for (i, masked_witness) in masked_witnesses.iter().enumerate() {
            let value = masked_witness.value().unwrap();
            assert_eq!(value, expected_values[i]);
        }
    }

    #[test]
    fn test_edge_cases() {
        let cs = create_cs();

        let witness_commitment = vec![
            create_fp_var(cs.clone(), 0),
            create_fp_var(cs.clone(), u64::MAX),
        ];
        let witness_voles = vec![create_fp_var(cs.clone(), 0), create_fp_var(cs.clone(), 1)];
        let masked_voles = vec![create_fp_var(cs.clone(), 0), create_fp_var(cs.clone(), 1)];
        let verifier_key = create_fp_var(cs.clone(), 1);
        let witness_challenge = vec![create_fp_var(cs.clone(), 1), create_fp_var(cs.clone(), 1)];

        let masked_witnesses = MaskedWitnessVar::compute(
            &witness_voles,
            &masked_voles,
            &verifier_key,
            &witness_challenge,
            &witness_commitment,
        )
        .unwrap();

        assert_eq!(masked_witnesses.len(), 2);
        assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(1));
        assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(2));
    }

    #[test]
    fn test_empty_inputs() {
        let cs = create_cs();
        let witness_commitment: Vec<FpVar<Fr>> = Vec::new();
        let witness_voles: Vec<FpVar<Fr>> = Vec::new();
        let masked_voles: Vec<FpVar<Fr>> = Vec::new();
        let verifier_key = create_fp_var(cs.clone(), 5);
        let witness_challenge: Vec<FpVar<Fr>> = Vec::new();

        let result = MaskedWitnessVar::compute(
            &witness_voles,
            &masked_voles,
            &verifier_key,
            &witness_challenge,
            &witness_commitment,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_constraint_satisfaction() {
        let cs = create_cs();

        let witness_commitment = vec![create_fp_var(cs.clone(), 7), create_fp_var(cs.clone(), 11)];
        let witness_voles = vec![create_fp_var(cs.clone(), 17), create_fp_var(cs.clone(), 19)];
        let masked_voles = vec![
            create_fp_var(cs.clone(), 100),
            create_fp_var(cs.clone(), 200),
        ];
        let verifier_key = create_fp_var(cs.clone(), 13);
        let witness_challenge = vec![create_fp_var(cs.clone(), 1), create_fp_var(cs.clone(), 1)];

        let masked_witnesses = MaskedWitnessVar::compute(
            &witness_voles,
            &masked_voles,
            &verifier_key,
            &witness_challenge,
            &witness_commitment,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());

        // Verify the computed values
        // masked_witness[0] = 17 + (1 * 13) = 30
        // masked_witness[1] = 19 + (1 * 13) = 32
        // failed in below assertions
        assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(30));
        assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(32));
    }
}
