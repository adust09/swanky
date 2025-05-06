use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::r1cs::SynthesisError;
use schmivitz::parameters::REPETITION_PARAM;

pub struct MaskedWitnessVarRevised;

impl MaskedWitnessVarRevised {
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

    /// Step 3: Compute validation mask from mask voles using boolean arrays
    ///
    /// This corresponds to the calculation in proof.rs line 273:
    #[tracing::instrument(target = "r1cs", skip(mask_voles_booleans))]
    pub fn combine(
        mask_voles_booleans: &Vec<Vec<Boolean<Bn254Fr>>>,
    ) -> Result<Vec<Boolean<Bn254Fr>>, SynthesisError> {
        // This function implements the combine function from proof.rs:

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
            witness_commitment_booleans,
            verifier_key_booleans,
            witness_voles_booleans
        )
    )]
    pub fn compute(
        witness_commitment_booleans: &Vec<Vec<Boolean<Bn254Fr>>>,
        verifier_key_booleans: &Vec<Boolean<Bn254Fr>>,
        witness_voles_booleans: &Vec<Vec<Vec<Boolean<Bn254Fr>>>>,
    ) -> Result<Vec<Vec<Boolean<Bn254Fr>>>, SynthesisError> {
        // Step 1: Compute d_delta
        let d_delta_booleans =
            Self::compute_d_delta(witness_commitment_booleans, verifier_key_booleans)?;

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
    use ark_r1cs_std::R1CSVar;

    #[test]
    fn test_compute_validation_aggregate_revise() {
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
    fn test_compute_d_delta() {
        // Create test witness commitment booleans
        let witness_commitment_booleans = vec![
            vec![Boolean::constant(true), Boolean::constant(false)],
            vec![Boolean::constant(false), Boolean::constant(true)],
        ];

        // Create test verifier key booleans
        let verifier_key_booleans = vec![Boolean::constant(true), Boolean::constant(true)];

        // Compute d_delta
        let d_delta = MaskedWitnessVarRevised::compute_d_delta(
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
    fn test_combine() {
        // Create test mask voles booleans
        let mask_voles_booleans = vec![
            vec![Boolean::constant(true), Boolean::constant(false)],
            vec![Boolean::constant(false), Boolean::constant(true)],
        ];

        // Compute validation mask
        let validation_mask = MaskedWitnessVarRevised::combine(&mask_voles_booleans).unwrap();

        // Verify the result
        assert!(validation_mask.len() > 0);
    }
}
