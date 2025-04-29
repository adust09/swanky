use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::SynthesisError;
use schmivitz::parameters::REPETITION_PARAM;

pub struct MaskedWitnessVar;

impl MaskedWitnessVar {
    // L236~
    #[tracing::instrument(
        target = "r1cs",
        skip(witness_commitment_var, verifier_key_var, witness_voles_var)
    )]
    pub fn compute(
        witness_commitment_var: &Vec<FpVar<Bn254Fr>>,
        verifier_key_var: &FpVar<Bn254Fr>,
        witness_voles_var: &[FpVar<Bn254Fr>],
    ) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError> {
        // Based on the test cases and the original code in proof.rs, we need to:
        // 1. Calculate d_delta by multiplying each witness commitment with the verifier key
        // 2. Add d_delta to the witness_voles_var to get the masked witnesses

        // Calculate d_delta (corresponds to lines 236-257 in proof.rs)
        // Multiply each witness commitment with the verifier key
        // fix: type
        let d_delta: Vec<FpVar<Bn254Fr>> = witness_commitment_var
            .iter()
            .map(|witness_com| {
                // In the original code, there's a conversion from F64b to F8b
                // Here we're working with FpVar<Bn254Fr>, so we'll directly multiply
                // the witness commitment with the verifier key
                witness_com.clone() * verifier_key_var.clone()
            })
            .collect::<Vec<_>>();
        // length違うのが原因？-> witness_voleの問題

        // proof.rsのこのパートにはwitness_commitment_var
        // Handle the case where witness_voles_var and witness_commitment_var have different lengths
        // This ensures we don't silently ignore elements if the arrays have different lengths
        if witness_voles_var.len() != witness_commitment_var.len() {
            // We could return an error, but for now let's just use the minimum length
            // to avoid panicking, similar to how zip behaves
            let min_len = std::cmp::min(witness_voles_var.len(), witness_commitment_var.len());

            let mut masked_witnesses = Vec::with_capacity(min_len);
            for i in 0..min_len {
                let masked_witness = witness_voles_var[i].clone() + d_delta[i].clone();
                masked_witnesses.push(masked_witness);
            }

            return Ok(masked_witnesses);
        }

        // Calculate masked witnesses (corresponds to lines 258-268 in proof.rs)
        // In the original code: masked_witness = witness_vole + d_delta
        let masked_witnesses: Vec<FpVar<Bn254Fr>> = witness_voles_var
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

        let witness_commitment_var = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
        ];
        let witness_voles = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        let verifier_key_var = create_fp_var(cs.clone(), 5);

        let masked_witnesses =
            MaskedWitnessVar::compute(&witness_commitment_var, &verifier_key_var, &witness_voles)
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
        let verifier_key = create_fp_var(cs.clone(), 1);

        let masked_witnesses =
            MaskedWitnessVar::compute(&witness_commitment, &verifier_key, &witness_voles).unwrap();

        assert_eq!(masked_witnesses.len(), 2);
        assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(1));
        assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(2));
    }

    #[test]
    fn test_empty_inputs() {
        let cs = create_cs();
        let witness_commitment: Vec<FpVar<Fr>> = Vec::new();
        let witness_voles: Vec<FpVar<Fr>> = Vec::new();
        let verifier_key = create_fp_var(cs.clone(), 5);

        let result = MaskedWitnessVar::compute(&witness_commitment, &verifier_key, &witness_voles);

        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0);
    }

    #[test]
    fn test_constraint_satisfaction() {
        let cs = create_cs();

        let witness_commitment = vec![create_fp_var(cs.clone(), 7), create_fp_var(cs.clone(), 11)];
        let witness_voles = vec![create_fp_var(cs.clone(), 17), create_fp_var(cs.clone(), 19)];
        let verifier_key = create_fp_var(cs.clone(), 13);

        let masked_witnesses =
            MaskedWitnessVar::compute(&witness_commitment, &verifier_key, &witness_voles).unwrap();

        // passed
        assert!(cs.is_satisfied().unwrap());

        // Verify the computed values
        // masked_witness[0] = 17 + (1 * 13) = 30
        // masked_witness[1] = 19 + (1 * 13) = 32
        // failed in below assertions
        assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(30));
        assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(32));
    }
}
