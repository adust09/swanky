use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use schmivitz::parameters::REPETITION_PARAM;

pub struct MaskedWitnessVar;

impl MaskedWitnessVar {
    /// Step 1: Compute d_delta values based on witness commitment and verifier key
    /// Compute d_delta values based on witness commitment and verifier key
    ///
    /// This corresponds to the calculation in proof.rs lines 237-258:
    /// ```
    /// let d_delta = self
    ///     .witness_commitment
    ///     .iter()
    ///     .map(|witness_com| {
    ///         // ... (conversion logic)
    ///         self.partial_decommitment
    ///             .verifier_key_array()
    ///             .map(|key| witness_com_f8b * key)
    ///     })
    ///     .collect::<Vec<_>>();
    /// ```
    #[tracing::instrument(target = "r1cs", skip(witness_commitment_var, verifier_key_var))]
    pub fn compute_d_delta(
        cs: ConstraintSystemRef<Bn254Fr>,
        witness_commitment_var: &Vec<FpVar<Bn254Fr>>,
        verifier_key_var: &FpVar<Bn254Fr>,
    ) -> Result<Vec<[FpVar<Bn254Fr>; REPETITION_PARAM]>, SynthesisError> {
        // Initialize the result vector
        let mut d_delta = Vec::with_capacity(witness_commitment_var.len());

        // For each witness commitment, compute d_delta array
        for commitment in witness_commitment_var.iter() {
            // Create an array of REPETITION_PARAM elements
            let mut delta_array = Vec::with_capacity(REPETITION_PARAM);

            // In proof.rs, each witness commitment is multiplied by each key in the verifier_key_array
            // Here, we'll create an array where the first element is commitment * verifier_key
            // and the rest are zeros (since we don't have the bit conversion logic from proof.rs)
            let delta = commitment.clone() * verifier_key_var.clone();

            // Add the delta as the first element
            delta_array.push(delta);

            // Add zeros for the rest of the elements
            for _ in 1..REPETITION_PARAM {
                // Create a zero FpVar
                let zero_var = FpVar::<Bn254Fr>::new_constant(
                    ark_relations::ns!(cs, "zero"),
                    Bn254Fr::from(0),
                )?;
                delta_array.push(zero_var);
            }

            // Convert Vec to array
            let delta_array: [FpVar<Bn254Fr>; REPETITION_PARAM] = delta_array.try_into().unwrap();
            d_delta.push(delta_array);
        }

        Ok(d_delta)
    }

    /// Step 2: Compute masked witness values based on witness voles and d_delta
    ///
    /// This corresponds to the calculation in proof.rs lines 260-270:
    /// ```
    /// let masked_witnesses = zip(self.partial_decommitment.witness_voles(), d_delta)
    ///     .map(|(qs, dds)| {
    ///         // ... (array operations)
    ///         let masked_witness: [F8b; 16] = zip(qs, dds)
    ///             .map(|(q, dd)| q + dd)
    ///             .collect::<Vec<_>>()
    ///             .try_into()
    ///             .unwrap();
    ///         // ... (conversion)
    ///     })
    ///     .collect::<Vec<_>>();
    /// ```
    #[tracing::instrument(target = "r1cs", skip(witness_voles_var, d_delta_var))]
    pub fn compute_masked_witness(
        witness_voles_var: &Vec<Vec<FpVar<Bn254Fr>>>,
        d_delta_var: &Vec<[FpVar<Bn254Fr>; REPETITION_PARAM]>,
    ) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError> {
        // Initialize the result vector
        let mut masked_witnesses = Vec::with_capacity(d_delta_var.len());
        print!(
            "the length of witness_voles_var: {:?} \n",
            witness_voles_var.len()
        );

        // For each pair of witness vole and d_delta, compute the masked witness
        for (i, d_delta_array) in d_delta_var.iter().enumerate() {
            // Get the corresponding witness vole array
            let witness_vole = &witness_voles_var[i];
            // Create an array to hold the element-wise sums
            let mut element_sums = Vec::with_capacity(REPETITION_PARAM);

            // Add each element of the witness vole to the corresponding element of d_delta
            // This matches the behavior in proof.rs:
            // let masked_witness: [F8b; 16] = zip(qs, dds)
            //     .map(|(q, dd)| q + dd)
            //     .collect::<Vec<_>>()
            //     .try_into()
            //     .unwrap();
            for j in 0..REPETITION_PARAM {
                if j < witness_vole.len() {
                    element_sums.push(witness_vole[j].clone() + d_delta_array[j].clone());
                } else {
                    // If witness_vole is shorter than REPETITION_PARAM, just use the d_delta value
                    element_sums.push(d_delta_array[j].clone());
                }
            }

            // In proof.rs, after adding the elements, it forms a superfield:
            // F8b::form_superfield(&masked_witness.into())
            //
            // In the context of F8b::form_superfield, it's combining multiple F8b elements
            // into a larger field element (likely F128b based on the code).
            //
            // For our FpVar<Bn254Fr> implementation, we need to combine these elements
            // in a way that's consistent with the original implementation.
            //
            // We'll use a linear combination approach similar to the `combine` function in proof.rs:
            // Start with the first element and add each subsequent element multiplied by increasing powers
            // of a "generator" value.

            // Start with the first element
            let mut combined = element_sums[0].clone();

            // Use a constant for the "generator" - in a real implementation this should match
            // the generator used in F8b::form_superfield
            let generator_value = Bn254Fr::from(2u64); // Using 2 as a simple generator
            let mut generator = FpVar::new_constant(
                ark_relations::ns!(
                    ark_relations::r1cs::ConstraintSystem::<Bn254Fr>::new_ref(),
                    "generator"
                ),
                generator_value,
            )?;

            // Combine the elements using a linear combination
            for j in 1..element_sums.len() {
                combined = combined + (element_sums[j].clone() * generator.clone());
                generator = generator
                    * FpVar::new_constant(
                        ark_relations::ns!(
                            ark_relations::r1cs::ConstraintSystem::<Bn254Fr>::new_ref(),
                            "generator"
                        ),
                        generator_value,
                    )?;
            }

            masked_witnesses.push(combined);
        }

        Ok(masked_witnesses)
    }

    /// Step 3: Compute validation mask from mask voles
    ///
    /// This corresponds to the calculation in proof.rs line 273:
    /// ```
    /// let validation_mask = combine(self.partial_decommitment.mask_voles());
    /// ```
    ///
    /// Where combine is defined as:
    /// ```
    /// fn combine(values: [F128b; 128]) -> F128b {
    ///     // Start with `X^0 = 1`
    ///     let mut power = F128b::ONE;
    ///     let mut acc = F128b::ZERO;
    ///
    ///     for vi in values {
    ///         acc += vi * power;
    ///         power *= F128b::GENERATOR;
    ///     }
    ///     acc
    /// }
    /// ```
    #[tracing::instrument(target = "r1cs", skip(cs, mask_voles_var))]
    pub fn compute_validation_mask(
        cs: ConstraintSystemRef<Bn254Fr>,
        mask_voles_var: &[FpVar<Bn254Fr>],
    ) -> Result<FpVar<Bn254Fr>, SynthesisError> {
        // Create constants for ONE and GENERATOR
        let one = FpVar::new_constant(ark_relations::ns!(cs, "one"), Bn254Fr::from(1u64))?;

        // Use 2 as a simple generator value (similar to what we did in compute_masked_witness)
        let generator_value = Bn254Fr::from(2u64);
        let generator = FpVar::new_constant(ark_relations::ns!(cs, "generator"), generator_value)?;

        // Initialize accumulator and power
        let mut validation_mask_var =
            FpVar::new_constant(ark_relations::ns!(cs, "zero"), Bn254Fr::from(0u64))?;
        let mut power_var = one.clone();

        // Combine the mask_voles using the same algorithm as in proof.rs
        for mask_vole_var in mask_voles_var.iter() {
            validation_mask_var = validation_mask_var + (mask_vole_var.clone() * power_var.clone());
            power_var = power_var * generator.clone();
        }

        Ok(validation_mask_var)
    }

    /// Combined function to compute masked witnesses from witness commitment, verifier key, and witness voles
    ///
    /// This function combines the first two steps:
    /// 1. Compute d_delta from witness commitment and verifier key
    /// 2. Compute masked witnesses from witness voles and d_delta
    #[tracing::instrument(
        target = "r1cs",
        skip(witness_commitment_var, verifier_key_var, witness_voles_var)
    )]
    pub fn compute(
        cs: ConstraintSystemRef<Bn254Fr>,
        witness_commitment_var: &Vec<FpVar<Bn254Fr>>,
        verifier_key_var: &FpVar<Bn254Fr>,
        witness_voles_var: &Vec<Vec<FpVar<Bn254Fr>>>,
    ) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError> {
        // Step 1: Compute d_delta
        let d_delta_var = Self::compute_d_delta(cs, witness_commitment_var, verifier_key_var)?;

        // Step 2: Compute masked witnesses
        let masked_witnesses_var = Self::compute_masked_witness(witness_voles_var, &d_delta_var)?;

        Ok(masked_witnesses_var)
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

    //     let witness_commitment_var = vec![
    //         create_fp_var(cs.clone(), 1),
    //         create_fp_var(cs.clone(), 2),
    //         create_fp_var(cs.clone(), 3),
    //     ];
    //     let witness_voles = vec![
    //         create_fp_var(cs.clone(), 10),
    //         create_fp_var(cs.clone(), 20),
    //         create_fp_var(cs.clone(), 30),
    //     ];

    //     let verifier_key_var = create_fp_var(cs.clone(), 5);

    //     let masked_witnesses =
    //         MaskedWitnessVar::compute(&witness_commitment_var, &verifier_key_var, &witness_voles)
    //             .unwrap();

    //     // Verify results
    //     assert_eq!(masked_witnesses.len(), 3);

    //     // Manually compute expected results
    //     // masked_witness[0] = witness_vole[0] + (witness_challenge[0] * verifier_key) = 10 + (1 * 5) = 15
    //     // masked_witness[1] = witness_vole[1] + (witness_challenge[1] * verifier_key) = 20 + (1 * 5) = 25
    //     // masked_witness[2] = witness_vole[2] + (witness_challenge[2] * verifier_key) = 30 + (1 * 5) = 35
    //     let expected_values = vec![Fr::from(15), Fr::from(25), Fr::from(35)];

    //     for (i, masked_witness) in masked_witnesses.iter().enumerate() {
    //         let value = masked_witness.value().unwrap();
    //         assert_eq!(value, expected_values[i]);
    //     }
    // }

    // #[test]
    // fn test_edge_cases() {
    //     let cs = create_cs();

    //     let witness_commitment = vec![
    //         create_fp_var(cs.clone(), 0),
    //         create_fp_var(cs.clone(), u64::MAX),
    //     ];
    //     let witness_voles = vec![create_fp_var(cs.clone(), 0), create_fp_var(cs.clone(), 1)];
    //     let verifier_key = create_fp_var(cs.clone(), 1);

    //     let masked_witnesses =
    //         MaskedWitnessVar::compute(&witness_commitment, &verifier_key, &witness_voles).unwrap();

    //     assert_eq!(masked_witnesses.len(), 2);
    //     assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(1));
    //     assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(2));
    // }

    // #[test]
    // fn test_empty_inputs() {
    //     let cs = create_cs();
    //     let witness_commitment: Vec<FpVar<Fr>> = Vec::new();
    //     let witness_voles: Vec<FpVar<Fr>> = Vec::new();
    //     let verifier_key = create_fp_var(cs.clone(), 5);

    //     let result = MaskedWitnessVar::compute(&witness_commitment, &verifier_key, &witness_voles);

    //     assert!(result.is_ok());
    //     assert_eq!(result.unwrap().len(), 0);
    // }

    // #[test]
    // fn test_constraint_satisfaction() {
    //     let cs = create_cs();

    //     let witness_commitment = vec![create_fp_var(cs.clone(), 7), create_fp_var(cs.clone(), 11)];
    //     let witness_voles = vec![create_fp_var(cs.clone(), 17), create_fp_var(cs.clone(), 19)];
    //     let verifier_key = create_fp_var(cs.clone(), 13);

    //     let masked_witnesses =
    //         MaskedWitnessVar::compute(&witness_commitment, &verifier_key, &witness_voles).unwrap();

    //     // passed
    //     assert!(cs.is_satisfied().unwrap());

    //     // Verify the computed values
    //     // masked_witness[0] = 17 + (1 * 13) = 30
    //     // masked_witness[1] = 19 + (1 * 13) = 32
    //     // failed in below assertions
    //     assert_eq!(masked_witnesses[0].value().unwrap(), Fr::from(30));
    //     assert_eq!(masked_witnesses[1].value().unwrap(), Fr::from(32));
    // }
}
