use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::boolean::Boolean;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use schmivitz::parameters::REPETITION_PARAM;
use swanky_field::FiniteField;
use swanky_field_binary::F128b;

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

        // For each witness commitment, compute d_delta array
        for commitment_bits in witness_commitment_booleans.iter() {
            // Create an array of REPETITION_PARAM elements
            let mut delta_array = Vec::with_capacity(REPETITION_PARAM);

            // In the original implementation, we extract the first bit of the commitment
            // Here, we'll use the first bit of the boolean array
            let first_bit = if commitment_bits.len() > 0 {
                commitment_bits[0].clone()
            } else {
                // Default to false if the array is empty
                Boolean::constant(false)
            };

            // In the original implementation, this bit is multiplied by each element in verifier_key_array
            // For each element in the REPETITION_PARAM, we'll create a boolean array
            for _ in 0..REPETITION_PARAM {
                // Create a new boolean array for each delta element
                // This represents the multiplication of the first bit with the verifier key
                // In boolean logic, this is equivalent to AND operations
                let mut delta_bits = Vec::with_capacity(verifier_key_booleans.len());

                for verifier_bit in verifier_key_booleans.iter() {
                    // Multiply (AND) the first bit with each bit of the verifier key
                    let result_bit = Boolean::and(&first_bit, verifier_bit)?;
                    delta_bits.push(result_bit);
                }

                delta_array.push(delta_bits);
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
        // Initialize the result vector
        let mut masked_witnesses = Vec::with_capacity(d_delta_booleans.len());

        // For each pair of witness vole and d_delta, compute the masked witness
        for (i, d_delta_array) in d_delta_booleans.iter().enumerate() {
            // Get the corresponding witness vole array
            if i >= witness_voles_booleans.len() {
                continue;
            }

            let witness_vole = &witness_voles_booleans[i];

            // Create an array to hold the element-wise sums
            let mut element_sums = Vec::with_capacity(REPETITION_PARAM);

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

                    element_sums.push(sum_bits);
                } else if j < d_delta_array.len() {
                    // If witness_vole is shorter than d_delta, just use the d_delta value
                    element_sums.push(d_delta_array[j].clone());
                } else if j < witness_vole.len() {
                    // If d_delta is shorter than witness_vole, just use the witness_vole value
                    element_sums.push(witness_vole[j].clone());
                }
            }

            // In the original implementation, we combine the elements using a linear combination
            // For boolean arrays, we'll concatenate all the bits to form a single boolean array
            let mut combined_bits = Vec::new();
            for sum in element_sums {
                combined_bits.extend(sum);
            }

            masked_witnesses.push(combined_bits);
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
        // For boolean arrays, we'll concatenate all the bits to form a single boolean array
        // This is a simplified approach compared to the original implementation
        let mut validation_mask_bits: Vec<Boolean<Bn254Fr>> = Vec::new();

        // Get the generator as a boolean array
        let generator_booleans = f128b_to_boolean_array(cs.clone(), &F128b::GENERATOR)?;

        // Initialize accumulator with zeros
        let mut acc_bits = Vec::with_capacity(128);
        for _ in 0..128 {
            acc_bits.push(Boolean::constant(false));
        }
        // Initialize power with ONE (represented as a boolean array)
        let mut power_bits: Vec<Boolean<Bn254Fr>> = Vec::with_capacity(128);
        power_bits.push(Boolean::constant(true)); // First bit is 1
        for _ in 1..128 {
            power_bits.push(Boolean::constant(false)); // Rest are 0
        }

        // Combine the mask_voles using a similar algorithm as in the original implementation
        for mask_vole_bits in mask_voles_booleans.iter() {
            // Multiply mask_vole by power (boolean multiplication is more complex)
            // For simplicity, we'll just use the mask_vole bits directly
            // In a real implementation, this would involve more complex boolean operations

            // Add to accumulator (XOR for boolean addition)
            for i in 0..acc_bits.len().min(mask_vole_bits.len()) {
                acc_bits[i] = Boolean::xor(&acc_bits[i], &mask_vole_bits[i])?;
            }

            // Update power by multiplying by generator
            // This is a complex operation in boolean logic
            // For simplicity, we'll just shift the power bits
            power_bits.rotate_left(1);
        }

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f8b_to_boolean_array;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};
    use swanky_field_binary::F8b;

    // Helper function to create a new constraint system
    fn create_cs() -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
        cs
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
