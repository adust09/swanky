use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::R1CSVar;
use ark_relations::r1cs::SynthesisError;
use schmivitz::parameters::REPETITION_PARAM;
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F64b, F8b};

use crate::field_mappings::{
    f8b_to_field_var, from_bits_le_safe_f128b, from_bits_le_safe_f8b, xor_safe_f8b, BinaryFieldVar,
};

pub struct MaskedWitnessVar;

impl MaskedWitnessVar {
    /// Step 1: Compute d_delta values based on witness commitment and verifier key using boolean arrays
    #[tracing::instrument(
        target = "r1cs",
        skip(witness_commitment_booleans, verifier_key_booleans)
    )]
    pub fn compute_d_delta(
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

    /// Step 1 Optimized: Compute d_delta values based on witness commitment and verifier key using BinaryFieldVar
    #[tracing::instrument(target = "r1cs", skip(witness_commitment_vars, verifier_key_var))]
    pub fn compute_d_delta_optimized(
        witness_commitment_vars: &Vec<BinaryFieldVar<Bn254Fr, F64b>>,
        verifier_key_var: &BinaryFieldVar<Bn254Fr, F128b>,
    ) -> Result<Vec<Vec<BinaryFieldVar<Bn254Fr, F8b>>>, SynthesisError> {
        // Initialize the result vector
        let mut d_delta = Vec::with_capacity(witness_commitment_vars.len());

        // Extract the verifier key as Boolean array
        let verifier_key_bits = verifier_key_var.to_bits_le()?;

        // Reconstruct the verifier key array structure as BinaryFieldVar<F, F8b>
        let mut verifier_key_array = Vec::with_capacity(REPETITION_PARAM);
        for i in 0..REPETITION_PARAM {
            if i * 8 + 7 >= verifier_key_bits.len() {
                // Not enough bits for a complete F8b value
                continue;
            }

            let start_idx = i * 8;
            let end_idx = start_idx + 8;
            let key_bits = verifier_key_bits[start_idx..end_idx].to_vec();

            // Convert bits to BinaryFieldVar using from_bits_le_safe_f8b
            let key_var = from_bits_le_safe_f8b(&key_bits)?;
            verifier_key_array.push(key_var);
        }

        // For each witness commitment, compute d_delta array
        for commitment_var in witness_commitment_vars.iter() {
            // Create an array of REPETITION_PARAM elements
            let mut delta_array = Vec::with_capacity(REPETITION_PARAM);

            // Extract the first bit of the commitment
            let commitment_bits = commitment_var.to_bits_le()?;
            let first_bit = if commitment_bits.len() > 0 {
                commitment_bits[0].clone()
            } else {
                // Default to false if the array is empty
                Boolean::constant(false)
            };

            // For each F8b value in the verifier key array
            for key_var in &verifier_key_array {
                // If first_bit is 1, result is key_var, otherwise it's 0
                // Convert key_var to bits
                let key_bits = key_var.to_bits_le()?;
                let mut result_bits = Vec::with_capacity(key_bits.len());

                // For each bit in key_var, AND it with first_bit
                for key_bit in key_bits {
                    let result_bit = Boolean::and(&first_bit, &key_bit)?;
                    result_bits.push(result_bit);
                }

                // Convert result_bits back to BinaryFieldVar using from_bits_le_safe_f8b
                let result_var = from_bits_le_safe_f8b(&result_bits)?;

                delta_array.push(result_var);
            }

            d_delta.push(delta_array);
        }

        Ok(d_delta)
    }

    /// Step 2: Compute masked witness values based on witness voles and d_delta using boolean arrays
    ///
    /// This corresponds to the calculation in proof.rs lines 260-270:
    #[tracing::instrument(target = "r1cs", skip(witness_voles_booleans, d_delta_booleans))]
    pub fn compute_masked_witness(
        witness_voles_booleans: &Vec<Vec<Vec<Boolean<Bn254Fr>>>>,
        d_delta_booleans: &Vec<Vec<Vec<Boolean<Bn254Fr>>>>,
    ) -> Result<Vec<Vec<Boolean<Bn254Fr>>>, SynthesisError> {
        // This function implements the calculation from proof.rs:
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

    /// Step 2 Optimized: Compute masked witness values based on witness voles and d_delta using BinaryFieldVar
    ///
    /// This corresponds to the calculation in proof.rs lines 260-270:
    #[tracing::instrument(target = "r1cs", skip(witness_voles_vars, d_delta_vars))]
    pub fn compute_masked_witness_optimized(
        witness_voles_vars: &Vec<Vec<BinaryFieldVar<Bn254Fr, F8b>>>,
        d_delta_vars: &Vec<Vec<BinaryFieldVar<Bn254Fr, F8b>>>,
    ) -> Result<Vec<BinaryFieldVar<Bn254Fr, F128b>>, SynthesisError> {
        // Initialize the result vector
        let mut masked_witnesses = Vec::with_capacity(d_delta_vars.len());

        // For each pair of witness vole and d_delta, compute the masked witness
        for (i, d_delta_array) in d_delta_vars.iter().enumerate() {
            // Get the corresponding witness vole array
            if i >= witness_voles_vars.len() {
                continue;
            }

            let witness_vole = &witness_voles_vars[i];

            // Create an array to hold the element-wise sums (q + dd)
            let mut masked_witness_array = Vec::with_capacity(REPETITION_PARAM);

            // Add each element of the witness vole to the corresponding element of d_delta
            // In binary fields, addition is XOR
            for j in 0..REPETITION_PARAM {
                if j < witness_vole.len() && j < d_delta_array.len() {
                    // XOR the witness vole with the corresponding d_delta using xor_safe_f8b
                    let sum_var = xor_safe_f8b(&witness_vole[j], &d_delta_array[j])?;
                    masked_witness_array.push(sum_var);
                } else if j < d_delta_array.len() {
                    // If witness_vole is shorter than d_delta, just use the d_delta value
                    masked_witness_array.push(d_delta_array[j].clone());
                } else if j < witness_vole.len() {
                    // If d_delta is shorter than witness_vole, just use the witness_vole value
                    masked_witness_array.push(witness_vole[j].clone());
                }
            }

            // In the original implementation, F8b::form_superfield is used to convert the array of F8b values
            // to an F128b value. We need to simulate this operation with BinaryFieldVar.

            // Get the constraint system from the first element
            let _cs = if !masked_witness_array.is_empty() {
                masked_witness_array[0].value.cs()
            } else {
                // If the array is empty, we can't proceed
                return Err(SynthesisError::Unsatisfiable);
            };

            // Convert each F8b to bits and combine them into a 128-bit array
            let mut all_bits = Vec::with_capacity(128);

            // Fill with zeros initially
            for _ in 0..128 {
                all_bits.push(Boolean::constant(false));
            }

            // Copy each 8-bit chunk into the appropriate position in the 128-bit array
            for (j, sum_var) in masked_witness_array.iter().enumerate() {
                if j >= 16 {
                    // F128b is made up of 16 F8b values
                    break;
                }

                let sum_bits = sum_var.to_bits_le()?;
                let start_idx = j * 8;

                for (k, bit) in sum_bits.iter().enumerate() {
                    if k >= 8 || start_idx + k >= 128 {
                        // Each F8b is 8 bits
                        break;
                    }
                    all_bits[start_idx + k] = bit.clone();
                }
            }

            // Convert the 128 bits to a F128b BinaryFieldVar using from_bits_le_safe_f128b
            let superfield_var = from_bits_le_safe_f128b(&all_bits)?;

            masked_witnesses.push(superfield_var);
        }

        Ok(masked_witnesses)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_mappings::{f128b_to_field_var, f64b_to_field_var};
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_compute_d_delta() {
        // Create test witness commitment booleans
        let witness_commitment_booleans = vec![
            vec![Boolean::constant(true), Boolean::constant(false)],
            vec![Boolean::constant(false), Boolean::constant(true)],
        ];

        // Create test verifier key booleans
        let mut verifier_key_booleans = Vec::new();
        for _ in 0..REPETITION_PARAM * 8 {
            verifier_key_booleans.push(Boolean::constant(true));
        }

        // Compute d_delta
        let d_delta =
            MaskedWitnessVar::compute_d_delta(&witness_commitment_booleans, &verifier_key_booleans)
                .unwrap();

        // Verify the result
        assert_eq!(d_delta.len(), 2);
        assert_eq!(d_delta[0].len(), REPETITION_PARAM);
        assert_eq!(d_delta[1].len(), REPETITION_PARAM);
    }

    #[test]
    fn test_compute_masked_witness() {
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
        let masked_witnesses =
            MaskedWitnessVar::compute_masked_witness(&witness_voles_booleans, &d_delta_booleans)
                .unwrap();

        // Verify the result
        assert_eq!(masked_witnesses.len(), 1);
    }

    #[test]
    fn test_compute_d_delta_optimized() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create test witness commitment values
        let f64b_1 = F64b::from_uniform_bytes(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let f64b_2 = F64b::from_uniform_bytes(&[0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Create test verifier key value
        let f128b =
            F128b::from_uniform_bytes(&[0x0F, 0x0F, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Convert to BinaryFieldVar
        let witness_commitment_vars = vec![
            f64b_to_field_var(cs.clone(), &f64b_1).unwrap(),
            f64b_to_field_var(cs.clone(), &f64b_2).unwrap(),
        ];
        let verifier_key_var = f128b_to_field_var(cs.clone(), &f128b).unwrap();

        // Compute d_delta using the optimized method
        let d_delta_optimized = MaskedWitnessVar::compute_d_delta_optimized(
            &witness_commitment_vars,
            &verifier_key_var,
        )
        .unwrap();

        // Verify the result
        assert_eq!(d_delta_optimized.len(), 2);

        // Convert the first witness commitment to boolean array
        let commitment_bits = witness_commitment_vars[0].to_bits_le().unwrap();
        let first_bit = commitment_bits[0].clone();

        // Convert the first element of d_delta_optimized to boolean array
        let result_bits = d_delta_optimized[0][0].to_bits_le().unwrap();

        // Check if the computation is correct
        // If the first bit of the commitment is 1, the result should not be all zeros
        // If the first bit of the commitment is 0, the result should be all zeros
        if first_bit.value().unwrap() {
            // The first bit is 1, so the result should not be all zeros
            assert!(result_bits.iter().any(|bit| bit.value().unwrap()));
        } else {
            // The first bit is 0, so the result should be all zeros
            assert!(result_bits.iter().all(|bit| !bit.value().unwrap()));
        }
    }

    #[test]
    fn test_compute_masked_witness_optimized() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create test witness voles values
        let f8b_1 = F8b::from_uniform_bytes(&[0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let f8b_2 = F8b::from_uniform_bytes(&[0x0B, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Create test d_delta values
        let f8b_3 = F8b::from_uniform_bytes(&[0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let f8b_4 = F8b::from_uniform_bytes(&[0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        // Convert to BinaryFieldVar
        let witness_voles_vars = vec![vec![
            f8b_to_field_var(cs.clone(), &f8b_1).unwrap(),
            f8b_to_field_var(cs.clone(), &f8b_2).unwrap(),
        ]];

        let d_delta_vars = vec![vec![
            f8b_to_field_var(cs.clone(), &f8b_3).unwrap(),
            f8b_to_field_var(cs.clone(), &f8b_4).unwrap(),
        ]];

        // Compute masked witnesses using the optimized method
        let masked_witnesses_optimized =
            MaskedWitnessVar::compute_masked_witness_optimized(&witness_voles_vars, &d_delta_vars)
                .unwrap();

        // Verify the result
        assert_eq!(masked_witnesses_optimized.len(), 1);

        // Convert to bits to check the computation
        let masked_witness_bits = masked_witnesses_optimized[0].to_bits_le().unwrap();

        // The first 8 bits should be the XOR of f8b_1 and f8b_3
        // The expected result is 0x0A ^ 0x05 = 0x0F
        let expected_first_byte = 0x0F;

        // Convert the first 8 bits of masked_witness_bits to a byte
        let mut first_byte = 0u8;
        for i in 0..8 {
            if masked_witness_bits[i].value().unwrap() {
                first_byte |= 1 << i;
            }
        }

        // Check if the computation is correct
        assert_eq!(first_byte, expected_first_byte);

        // The second 8 bits should be the XOR of f8b_2 and f8b_4
        // The expected result is 0x0B ^ 0x06 = 0x0D
        let expected_second_byte = 0x0D;

        // Convert the second 8 bits of masked_witness_bits to a byte
        let mut second_byte = 0u8;
        for i in 0..8 {
            if masked_witness_bits[8 + i].value().unwrap() {
                second_byte |= 1 << i;
            }
        }

        // Check if the computation is correct
        assert_eq!(second_byte, expected_second_byte);
    }
}
