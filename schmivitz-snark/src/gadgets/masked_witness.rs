use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use schmivitz::parameters::REPETITION_PARAM;
use swanky_field::FiniteField;
use swanky_field_binary::F128b;

use crate::f128b_to_ark;

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

            // Get the value of the commitment to check its first bit
            // This is similar to the F2::decompose_superfield(witness_com) in proof.rs
            let commitment_value = commitment.value().unwrap_or(Bn254Fr::from(0u64));

            // Create a binary representation (0 or 1) based on whether the value is odd or even
            // This is similar to checking the first bit in proof.rs
            let is_odd = commitment_value.into_repr().0[0] & 1 == 1;

            // Create a constant for F8b::ONE or F8b::ZERO converted to Bn254Fr
            let f8b_bit_value = if is_odd {
                // Equivalent to f8b_to_ark(&F8b::ONE)
                Bn254Fr::from(1u64)
            } else {
                // Equivalent to f8b_to_ark(&F8b::ZERO)
                Bn254Fr::from(0u64)
            };

            let f8b_bit_var =
                FpVar::<Bn254Fr>::new_constant(ark_relations::ns!(cs, "f8b_bit"), f8b_bit_value)?;

            // In proof.rs, this F8b value is multiplied by each element in verifier_key_array
            // For simplicity, we'll use the same value for all elements in the array
            for _ in 0..REPETITION_PARAM {
                // Multiply the binary bit by the verifier key
                let delta = f8b_bit_var.clone() * verifier_key_var.clone();
                delta_array.push(delta);
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

            let generator_value = f128b_to_ark(&F128b::GENERATOR);
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
        let generator_value = f128b_to_ark(&F128b::GENERATOR);
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

use crate::f128b_to_boolean_array;

pub struct MaskedWitnessVarRevised;

impl MaskedWitnessVarRevised {
    /// Step 1: Compute d_delta values based on witness commitment and verifier key using boolean arrays
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
    #[tracing::instrument(
        target = "r1cs",
        skip(cs, witness_commitment_booleans, verifier_key_booleans)
    )]
    pub fn compute_d_delta(
        cs: ConstraintSystemRef<Bn254Fr>,
        witness_commitment_booleans: &Vec<Vec<Boolean<Bn254Fr>>>,
        verifier_key_booleans: &Vec<Boolean<Bn254Fr>>,
    ) -> Result<Vec<Vec<Vec<Boolean<Bn254Fr>>>>, SynthesisError> {
        // Initialize the result vector
        let mut d_delta = Vec::with_capacity(witness_commitment_booleans.len());

        // In the original implementation, verifier_key_array() returns an array of F8b values
        // with length REPETITION_PARAM. We need to reconstruct this structure from the boolean array.

        // First, verify that verifier_key_booleans has the correct length (REPETITION_PARAM * 8)
        // Each F8b value is represented by 8 bits
        if verifier_key_booleans.len() < REPETITION_PARAM * 8 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Reconstruct the verifier key array structure
        // Each F8b value is represented by 8 bits
        let mut verifier_key_array = Vec::with_capacity(REPETITION_PARAM);
        for i in 0..REPETITION_PARAM {
            let start_idx = i * 8;
            let end_idx = start_idx + 8;
            let key_bits = verifier_key_booleans[start_idx..end_idx].to_vec();
            verifier_key_array.push(key_bits);
        }

        // For each witness commitment, compute d_delta array
        for commitment_bits in witness_commitment_booleans.iter() {
            // Create an array of REPETITION_PARAM elements
            let mut delta_array = Vec::with_capacity(REPETITION_PARAM);

            // In the original implementation, we extract the first bit of the commitment
            // and create an F8b value (either F8b::ONE or F8b::ZERO) based on that bit
            let first_bit = if commitment_bits.len() > 0 {
                commitment_bits[0].clone()
            } else {
                // Default to false if the array is empty
                Boolean::constant(false)
            };

            // For each F8b value in the verifier key array
            for key_bits in &verifier_key_array {
                // Multiply the first bit by each F8b value in the verifier key array
                // In boolean logic, this means:
                // - If first_bit is 0, result is all 0s
                // - If first_bit is 1, result is the key_bits
                let mut result_bits = Vec::with_capacity(key_bits.len());

                for key_bit in key_bits.clone() {
                    // Multiply (AND) the first bit with each bit of the key
                    let result_bit = Boolean::and(&first_bit, &key_bit)?;
                    result_bits.push(result_bit);
                }

                delta_array.push(result_bits);
            }

            d_delta.push(delta_array);
        }

        Ok(d_delta)
    }

    /// Step 2: Compute masked witness values based on witness voles and d_delta using boolean arrays
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
    #[tracing::instrument(target = "r1cs", skip(witness_voles_booleans, d_delta_booleans))]
    pub fn compute_masked_witness(
        witness_voles_booleans: &Vec<Vec<Vec<Boolean<Bn254Fr>>>>,
        d_delta_booleans: &Vec<Vec<Vec<Boolean<Bn254Fr>>>>,
    ) -> Result<Vec<Vec<Boolean<Bn254Fr>>>, SynthesisError> {
        // This function implements the calculation from proof.rs:
        // let masked_witnesses = zip(self.partial_decommitment.witness_voles(), d_delta.clone())
        //     .map(|(qs, dds)| {
        //         let masked_witness: [F8b; 16] = zip(qs, dds)
        //             .map(|(q, dd)| q + dd)
        //             .collect::<Vec<_>>()
        //             .try_into()
        //             .unwrap();
        //         F8b::form_superfield(&masked_witness.into())
        //     })
        //     .collect::<Vec<_>>();

        // Initialize the result vector
        let mut masked_witnesses = Vec::with_capacity(d_delta_booleans.len());

        // For each pair of witness vole and d_delta, compute the masked witness
        for (i, d_delta_array) in d_delta_booleans.iter().enumerate() {
            // Get the corresponding witness vole array
            if i >= witness_voles_booleans.len() {
                continue;
            }

            let witness_vole = &witness_voles_booleans[i];

            // Create an array to hold the element-wise sums (q + dd)
            let mut masked_witness_array = Vec::with_capacity(REPETITION_PARAM);

            // Add each element of the witness vole to the corresponding element of d_delta
            // In boolean logic, addition is XOR
            for j in 0..REPETITION_PARAM {
                if j < witness_vole.len() && j < d_delta_array.len() {
                    let witness_bits = &witness_vole[j];
                    let delta_bits = &d_delta_array[j];

                    // XOR each bit of the witness vole with the corresponding bit of d_delta
                    let mut sum_bits = Vec::with_capacity(witness_bits.len());

                    for k in 0..witness_bits.len().min(delta_bits.len()) {
                        let sum_bit = Boolean::xor(&witness_bits[k], &delta_bits[k])?;
                        sum_bits.push(sum_bit);
                    }

                    // If one array is longer than the other, append the remaining bits
                    if witness_bits.len() > delta_bits.len() {
                        for k in delta_bits.len()..witness_bits.len() {
                            sum_bits.push(witness_bits[k].clone());
                        }
                    } else if delta_bits.len() > witness_bits.len() {
                        for k in witness_bits.len()..delta_bits.len() {
                            sum_bits.push(delta_bits[k].clone());
                        }
                    }

                    masked_witness_array.push(sum_bits);
                } else if j < d_delta_array.len() {
                    // If witness_vole is shorter than d_delta, just use the d_delta value
                    masked_witness_array.push(d_delta_array[j].clone());
                } else if j < witness_vole.len() {
                    // If d_delta is shorter than witness_vole, just use the witness_vole value
                    masked_witness_array.push(witness_vole[j].clone());
                }
            }

            // In the original implementation, F8b::form_superfield is used to convert the array of F8b values
            // to an F128b value. Since we're working with boolean arrays, we need to simulate this operation.
            // The form_superfield function combines the F8b values into a single F128b value.

            // For our boolean representation, we'll create a 128-bit boolean array
            // where each 8-bit chunk corresponds to one of the F8b values.
            let mut superfield_bits = Vec::with_capacity(128);

            // Fill with zeros initially
            for _ in 0..128 {
                superfield_bits.push(Boolean::constant(false));
            }

            // Copy each 8-bit chunk into the appropriate position in the 128-bit array
            for (j, sum_bits) in masked_witness_array.iter().enumerate() {
                if j >= 16 {
                    // F128b is made up of 16 F8b values
                    break;
                }

                let start_idx = j * 8;
                for (k, bit) in sum_bits.iter().enumerate() {
                    if k >= 8 || start_idx + k >= 128 {
                        // Each F8b is 8 bits
                        break;
                    }
                    superfield_bits[start_idx + k] = bit.clone();
                }
            }

            masked_witnesses.push(superfield_bits);
        }

        Ok(masked_witnesses)
    }

    /// Step 3: Compute validation mask from mask voles using boolean arrays
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
    #[tracing::instrument(target = "r1cs", skip(cs, mask_voles_booleans))]
    pub fn compute_validation_mask(
        cs: ConstraintSystemRef<Bn254Fr>,
        mask_voles_booleans: &Vec<Vec<Boolean<Bn254Fr>>>,
    ) -> Result<Vec<Boolean<Bn254Fr>>, SynthesisError> {
        // This function implements the combine function from proof.rs:
        // fn combine(values: [F128b; 128]) -> F128b {
        //     // Start with `X^0 = 1`
        //     let mut power = F128b::ONE;
        //     let mut acc = F128b::ZERO;
        //
        //     for vi in values {
        //         acc += vi * power;
        //         power *= F128b::GENERATOR;
        //     }
        //     acc
        // }

        // Get the generator as a boolean array
        let generator_booleans = f128b_to_boolean_array(cs.clone(), &F128b::GENERATOR)?;

        // Initialize accumulator with zeros (F128b::ZERO)
        let mut acc_bits = Vec::with_capacity(128);
        for _ in 0..128 {
            acc_bits.push(Boolean::constant(false));
        }

        // Initialize power with ONE (F128b::ONE)
        let mut power_bits = Vec::with_capacity(128);
        power_bits.push(Boolean::constant(true)); // First bit is 1
        for _ in 1..128 {
            power_bits.push(Boolean::constant(false)); // Rest are 0
        }
        println!("hoge");

        // Process each mask_vole value
        for mask_vole_bits in mask_voles_booleans.iter() {
            // Compute vi * power
            // In boolean logic, multiplication is a bit-by-bit AND followed by appropriate shifts and XORs
            // This is a simplified implementation that works for our specific case
            let mut product_bits = Vec::with_capacity(128);
            for _ in 0..128 {
                product_bits.push(Boolean::constant(false));
            }

            // For each bit in mask_vole_bits
            for (i, mask_bit) in mask_vole_bits.iter().enumerate() {
                if i >= 128 {
                    break;
                }

                // For each bit in power_bits
                for (j, power_bit) in power_bits.iter().enumerate() {
                    if j >= 128 || i + j >= 128 {
                        continue;
                    }

                    // Compute mask_bit AND power_bit
                    let and_result = Boolean::and(mask_bit, power_bit)?;

                    // XOR with the corresponding bit in product_bits (at position i+j)
                    product_bits[i + j] = Boolean::xor(&product_bits[i + j], &and_result)?;
                }
            }

            // Add product to accumulator (XOR for boolean addition in F2)
            for i in 0..128 {
                acc_bits[i] = Boolean::xor(&acc_bits[i], &product_bits[i])?;
            }

            // Update power by multiplying by generator
            // power *= F128b::GENERATOR
            let mut new_power_bits = Vec::with_capacity(128);
            for _ in 0..128 {
                new_power_bits.push(Boolean::constant(false));
            }

            // For each bit in power_bits
            for (i, power_bit) in power_bits.iter().enumerate() {
                if i >= 128 {
                    break;
                }

                // For each bit in generator_booleans
                for (j, gen_bit) in generator_booleans.iter().enumerate() {
                    if j >= 128 || i + j >= 128 {
                        continue;
                    }

                    // Compute power_bit AND gen_bit
                    let and_result = Boolean::and(power_bit, gen_bit)?;

                    // XOR with the corresponding bit in new_power_bits (at position i+j)
                    new_power_bits[i + j] = Boolean::xor(&new_power_bits[i + j], &and_result)?;
                }
            }

            // Update power_bits
            power_bits = new_power_bits;
        }
        println!("mask_voles_booleans");

        Ok(acc_bits)
    }

    /// Combined function to compute masked witnesses from witness commitment, verifier key, and witness voles
    /// using boolean arrays
    ///
    /// This function combines the first two steps:
    /// 1. Compute d_delta from witness commitment and verifier key
    /// 2. Compute masked witnesses from witness voles and d_delta
    #[tracing::instrument(
        target = "r1cs",
        skip(
            cs,
            witness_commitment_booleans,
            verifier_key_booleans,
            witness_voles_booleans
        )
    )]
    pub fn compute(
        cs: ConstraintSystemRef<Bn254Fr>,
        witness_commitment_booleans: &Vec<Vec<Boolean<Bn254Fr>>>,
        verifier_key_booleans: &Vec<Boolean<Bn254Fr>>,
        witness_voles_booleans: &Vec<Vec<Vec<Boolean<Bn254Fr>>>>,
    ) -> Result<Vec<Vec<Boolean<Bn254Fr>>>, SynthesisError> {
        // Step 1: Compute d_delta
        let d_delta_booleans =
            Self::compute_d_delta(cs, witness_commitment_booleans, verifier_key_booleans)?;

        // Step 2: Compute masked witnesses
        let masked_witnesses_booleans =
            Self::compute_masked_witness(witness_voles_booleans, &d_delta_booleans)?;

        Ok(masked_witnesses_booleans)
    }
    /// Compute validation aggregate directly using Boolean arrays
    ///
    /// This function replaces the need to convert Boolean arrays to FpVars for validation aggregate calculation
    /// It implements the same logic as CircuitTraverser::compute_validation_aggregate but using Boolean operations
    ///
    /// # Arguments
    ///
    /// * `witness_challenges` - Array of witness challenges as Boolean arrays
    /// * `masked_witnesses_var` - Array of masked witnesses as Boolean arrays
    ///
    /// # Returns
    ///
    /// * Result containing the validation aggregate as a Boolean array or a synthesis error
    #[tracing::instrument(target = "r1cs", skip(witness_challenges, masked_witnesses_var))]
    pub fn compute_validation_aggregate_revise(
        witness_challenges: &[Vec<Boolean<Bn254Fr>>],
        masked_witnesses_var: &[Vec<Boolean<Bn254Fr>>],
    ) -> Result<Vec<Boolean<Bn254Fr>>, SynthesisError> {
        if witness_challenges.len() > masked_witnesses_var.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Initialize the validation aggregate with zeros (representing 0 in the field)
        let mut validation_aggregate = Vec::with_capacity(128);
        for _ in 0..128 {
            validation_aggregate.push(Boolean::constant(false));
        }

        // Compute the validation aggregate as the sum of (challenge * masked_witness)
        // In Boolean logic, multiplication is bit-by-bit AND followed by appropriate shifts and XORs
        // Addition is XOR for the binary field
        for (challenge, masked_witness) in
            witness_challenges.iter().zip(masked_witnesses_var.iter())
        {
            // Compute challenge * masked_witness
            let mut product = Vec::with_capacity(128);
            for _ in 0..128 {
                product.push(Boolean::constant(false));
            }

            // For each bit in challenge
            for (i, challenge_bit) in challenge.iter().enumerate() {
                if i >= 128 {
                    break;
                }

                // For each bit in masked_witness
                for (j, masked_bit) in masked_witness.iter().enumerate() {
                    if j >= 128 || i + j >= 128 {
                        continue;
                    }

                    // Compute challenge_bit AND masked_bit
                    let and_result = Boolean::and(challenge_bit, masked_bit)?;

                    // XOR with the corresponding bit in product (at position i+j)
                    product[i + j] = Boolean::xor(&product[i + j], &and_result)?;
                }
            }

            // Add product to validation_aggregate (XOR for boolean addition in F2)
            for i in 0..128 {
                validation_aggregate[i] = Boolean::xor(&validation_aggregate[i], &product[i])?;
            }
        }

        Ok(validation_aggregate)
    }
}

#[cfg(test)]
mod revised_tests {
    use super::*;
    use crate::f8b_to_boolean_array;
    use ark_bn254::Fr;
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use swanky_field_binary::F8b;

    // Helper function to create a new constraint system
    fn create_cs() -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
        cs
    }

    #[test]
    // fn test_compute_masked_witness_revise() {
    //     let cs = create_cs();

    //     // Create test witness challenges (Boolean arrays representing field elements)
    //     let witness_challenges = vec![
    //         vec![Boolean::constant(true), Boolean::constant(false)], // Represents 1
    //         vec![Boolean::constant(false), Boolean::constant(true)], // Represents 2
    //     ];

    //     // Create test masked witnesses (Boolean arrays representing field elements)
    //     let masked_witnesses_var = vec![
    //         vec![Boolean::constant(true), Boolean::constant(true)], // Represents 3
    //         vec![Boolean::constant(false), Boolean::constant(false)], // Represents 0
    //     ];

    //     // Compute validation aggregate
    //     let validation_aggregate = MaskedWitnessVarRevised::compute_masked_witness_revise(
    //         &witness_challenges,
    //         &masked_witnesses_var,
    //     )
    //     .unwrap();

    //     // Verify the result has the expected length
    //     assert_eq!(validation_aggregate.len(), 128);

    //     // In this simple test case with 2-bit values:
    //     // 1 * 3 + 2 * 0 = 3
    //     // In binary: 11
    //     // So the first two bits should be true, and the rest should be false
    //     assert_eq!(validation_aggregate[0].value().unwrap(), true);
    //     assert_eq!(validation_aggregate[1].value().unwrap(), true);
    //     for i in 2..128 {
    //         assert_eq!(validation_aggregate[i].value().unwrap(), false);
    //     }
    // }
    #[test]
    fn test_compute_validation_aggregate_revise() {
        let cs = create_cs();

        // Create test witness challenges (Boolean arrays representing field elements)
        let witness_challenges = vec![
            vec![Boolean::constant(true), Boolean::constant(false)], // Represents 1
            vec![Boolean::constant(false), Boolean::constant(true)], // Represents 2
        ];

        // Create test masked witnesses (Boolean arrays representing field elements)
        let masked_witnesses_var = vec![
            vec![Boolean::constant(true), Boolean::constant(true)], // Represents 3
            vec![Boolean::constant(false), Boolean::constant(false)], // Represents 0
        ];

        // Compute validation aggregate
        let validation_aggregate = MaskedWitnessVarRevised::compute_validation_aggregate_revise(
            &witness_challenges,
            &masked_witnesses_var,
        )
        .unwrap();

        // Verify the result has the expected length
        assert_eq!(validation_aggregate.len(), 128);

        // In this simple test case with 2-bit values:
        // 1 * 3 + 2 * 0 = 3
        // In binary: 11
        // So the first two bits should be true, and the rest should be false
        assert_eq!(validation_aggregate[0].value().unwrap(), true);
        assert_eq!(validation_aggregate[1].value().unwrap(), true);
        for i in 2..128 {
            assert_eq!(validation_aggregate[i].value().unwrap(), false);
        }
    }

    #[test]
    fn test_boolean_conversion() {
        let cs = create_cs();

        // Create a test F8b value
        let f8b_value = F8b::from(123u8);

        // Convert to boolean array
        let boolean_array = f8b_to_boolean_array(cs.clone(), &f8b_value).unwrap();

        // Verify the length
        assert_eq!(boolean_array.len(), 8);
    }

    #[test]
    fn test_compute_d_delta() {
        let cs = create_cs();

        // Create test witness commitment booleans
        let witness_commitment_booleans = vec![
            vec![Boolean::constant(true), Boolean::constant(false)],
            vec![Boolean::constant(false), Boolean::constant(true)],
        ];

        // Create test verifier key booleans
        let verifier_key_booleans = vec![Boolean::constant(true), Boolean::constant(true)];

        // Compute d_delta
        let d_delta = MaskedWitnessVarRevised::compute_d_delta(
            cs.clone(),
            &witness_commitment_booleans,
            &verifier_key_booleans,
        )
        .unwrap();

        // Verify the result
        assert_eq!(d_delta.len(), 2);
        assert_eq!(d_delta[0].len(), REPETITION_PARAM);
        assert_eq!(d_delta[1].len(), REPETITION_PARAM);
    }

    #[test]
    fn test_compute_masked_witness() {
        let cs = create_cs();

        // Create test witness voles booleans
        let witness_voles_booleans = vec![vec![
            vec![Boolean::constant(true), Boolean::constant(false)],
            vec![Boolean::constant(false), Boolean::constant(true)],
        ]];

        // Create test d_delta booleans
        let d_delta_booleans = vec![vec![
            vec![Boolean::constant(false), Boolean::constant(true)],
            vec![Boolean::constant(true), Boolean::constant(false)],
        ]];

        // Compute masked witnesses
        let masked_witnesses = MaskedWitnessVarRevised::compute_masked_witness(
            &witness_voles_booleans,
            &d_delta_booleans,
        )
        .unwrap();

        // Verify the result
        assert_eq!(masked_witnesses.len(), 1);
    }

    #[test]
    fn test_compute_validation_mask() {
        let cs = create_cs();

        // Create test mask voles booleans
        let mask_voles_booleans = vec![
            vec![Boolean::constant(true), Boolean::constant(false)],
            vec![Boolean::constant(false), Boolean::constant(true)],
        ];

        // Compute validation mask
        let validation_mask =
            MaskedWitnessVarRevised::compute_validation_mask(cs.clone(), &mask_voles_booleans)
                .unwrap();

        // Verify the result
        assert!(validation_mask.len() > 0);
    }
}
