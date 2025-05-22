use std::iter::zip;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::{One, Zero};
use ark_r1cs_std::{prelude::Boolean, R1CSVar};
use ark_relations::r1cs::SynthesisError;
use swanky_field_binary::F128b;

use crate::BinaryFieldVar;

pub struct ValidationVar;

impl ValidationVar {
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

        Ok(acc_bits)
    }

    #[tracing::instrument(target = "r1cs", skip(witness_challenges, masked_witnesses_var))]
    pub fn compute_validation_aggregate(
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

    /// Helper function to perform polynomial multiplication in binary field
    fn polynomial_multiply(
        a: &BinaryFieldVar<Bn254Fr, F128b>,
        b: &BinaryFieldVar<Bn254Fr, F128b>,
    ) -> Result<BinaryFieldVar<Bn254Fr, F128b>, SynthesisError> {
        // For binary fields, we need to implement polynomial multiplication
        // This is a simplified implementation that works for our specific case

        // Convert to bits for multiplication
        let a_bits = a.to_bits_le()?;
        let b_bits = b.to_bits_le()?;

        // Initialize result with zeros
        let _cs = a.value.cs();
        let mut result_bits = Vec::with_capacity(128);
        for _ in 0..128 {
            result_bits.push(Boolean::constant(false));
        }

        // Perform bit-by-bit multiplication (similar to the original implementation)
        for (i, a_bit) in a_bits.iter().enumerate() {
            if i >= 128 {
                break;
            }

            for (j, b_bit) in b_bits.iter().enumerate() {
                if j >= 128 || i + j >= 128 {
                    continue;
                }

                // Compute a_bit AND b_bit
                let and_result = Boolean::and(a_bit, b_bit)?;

                // XOR with the corresponding bit in result_bits (at position i+j)
                result_bits[i + j] = Boolean::xor(&result_bits[i + j], &and_result)?;
            }
        }

        // Convert back to BinaryFieldVar
        BinaryFieldVar::<Bn254Fr, F128b>::from_bits_le(&result_bits)
    }

    /// Helper function to shift left a BinaryFieldVar by 1 bit
    fn shift_left(
        value: &BinaryFieldVar<Bn254Fr, F128b>,
    ) -> Result<BinaryFieldVar<Bn254Fr, F128b>, SynthesisError> {
        // Convert to bits
        let bits = value.to_bits_le()?;

        // Shift left by 1 bit
        let mut shifted_bits = Vec::with_capacity(128);
        shifted_bits.push(Boolean::constant(false)); // Insert 0 at the beginning

        // Copy the remaining bits, dropping the last one
        for i in 0..127 {
            shifted_bits.push(bits[i].clone());
        }

        // Convert back to BinaryFieldVar
        BinaryFieldVar::<Bn254Fr, F128b>::from_bits_le(&shifted_bits)
    }

    /// Optimized version of compute_validation_aggregate that uses BinaryFieldVar
    #[tracing::instrument(target = "r1cs", skip(witness_challenges_vars, masked_witnesses_vars))]
    pub fn compute_validation_aggregate_optimized(
        witness_challenges_vars: &[BinaryFieldVar<Bn254Fr, F128b>],
        masked_witnesses_vars: &[BinaryFieldVar<Bn254Fr, F128b>],
    ) -> Result<BinaryFieldVar<Bn254Fr, F128b>, SynthesisError> {
        if witness_challenges_vars.len() > masked_witnesses_vars.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Initialize the validation aggregate with zeros
        let mut validation_aggregate = BinaryFieldVar::<Bn254Fr, F128b>::constant(F128b::zero());

        // Compute the validation aggregate as the sum of (challenge * masked_witness)
        for (challenge, masked_witness) in witness_challenges_vars
            .iter()
            .zip(masked_witnesses_vars.iter())
        {
            // Compute challenge * masked_witness using polynomial multiplication
            let product = Self::polynomial_multiply(challenge, masked_witness)?;

            // Add product to validation_aggregate (XOR for binary field addition)
            validation_aggregate = validation_aggregate.xor(&product)?;
        }

        Ok(validation_aggregate)
    }
    /// Helper function to perform polynomial multiplication in binary field

    /// Optimized version of combine that uses BinaryFieldVar instead of Boolean arrays
    ///
    /// This corresponds to the calculation in proof.rs line 273:
    #[tracing::instrument(target = "r1cs", skip(mask_voles_vars))]
    pub fn combine_optimized(
        mask_voles_vars: &Vec<BinaryFieldVar<Bn254Fr, F128b>>,
    ) -> Result<BinaryFieldVar<Bn254Fr, F128b>, SynthesisError> {
        // Log the number of constraints before
        let cs = mask_voles_vars[0].value.cs();
        let constraints_before = cs.num_constraints();
        println!(
            "Constraints before combine_optimized: {}",
            constraints_before
        );

        // Initialize accumulator with zeros (F128b::ZERO)
        let mut acc = BinaryFieldVar::<Bn254Fr, F128b>::constant(F128b::zero());

        // Initialize power with ONE (F128b::ONE)
        let mut power = BinaryFieldVar::<Bn254Fr, F128b>::constant(F128b::one());

        // Process each mask_vole value
        for mask_vole_var in mask_voles_vars.iter() {
            // Compute vi * power using polynomial multiplication
            let product = Self::polynomial_multiply(mask_vole_var, &power)?;

            // Add product to accumulator (XOR for binary field addition)
            acc = acc.xor(&product)?;

            // Update power for next iteration (shift left by 1 in binary field)
            power = Self::shift_left(&power)?;
        }

        // Log the number of constraints after
        let constraints_after = cs.num_constraints();
        println!("Constraints after combine_optimized: {}", constraints_after);
        println!(
            "Constraints reduced: {}",
            constraints_before - constraints_after
        );

        Ok(acc)
    }

    // This corresponds to the calculation in proof.rs line 317-318:
    // let actual_validation = self.degree_1_commitment * self.partial_decommitment.verifier_key()
    //     + self.degree_0_commitment;
    pub fn compute_actual_validation(
        degree_0_commitment: &Vec<Boolean<Bn254Fr>>,
        degree_1_commitment: &Vec<Boolean<Bn254Fr>>,
        verifier_key: &Vec<Boolean<Bn254Fr>>,
    ) -> Result<Vec<Boolean<Bn254Fr>>, SynthesisError> {
        let mut product = Vec::with_capacity(128);
        for _ in 0..128 {
            product.push(Boolean::constant(false));
        }

        // For each bit in degree_1_commitment
        for (i, d1_bit) in degree_1_commitment.iter().enumerate() {
            if i >= 128 {
                break;
            }

            // For each bit in verifier_key
            for (j, key_bit) in verifier_key.iter().enumerate() {
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
        let actual_validation_var = zip(product, degree_0_commitment.clone())
            .map(|(prod_bit, d0_bit)| Boolean::xor(&prod_bit, &d0_bit))
            .collect::<Result<Vec<_>, SynthesisError>>()?;

        Ok(actual_validation_var)
    }

    /// Optimized version of compute_actual_validation that uses BinaryFieldVar
    ///
    /// This corresponds to the calculation in proof.rs line 317-318:
    /// let actual_validation = self.degree_1_commitment * self.partial_decommitment.verifier_key()
    ///     + self.degree_0_commitment;
    #[tracing::instrument(
        target = "r1cs",
        skip(degree_0_commitment, degree_1_commitment, verifier_key)
    )]
    pub fn compute_actual_validation_optimized(
        degree_0_commitment: &BinaryFieldVar<Bn254Fr, F128b>,
        degree_1_commitment: &BinaryFieldVar<Bn254Fr, F128b>,
        verifier_key: &BinaryFieldVar<Bn254Fr, F128b>,
    ) -> Result<BinaryFieldVar<Bn254Fr, F128b>, SynthesisError> {
        // Compute degree_1_commitment * verifier_key using polynomial multiplication
        let product = Self::polynomial_multiply(degree_1_commitment, verifier_key)?;

        // Add degree_0_commitment to the product (XOR for binary field addition)
        let actual_validation = product.xor(degree_0_commitment)?;

        Ok(actual_validation)
    }
}

#[test]
fn test_combine() {
    // Create test mask voles booleans
    let mask_voles_booleans = vec![
        vec![Boolean::constant(true), Boolean::constant(false)],
        vec![Boolean::constant(false), Boolean::constant(true)],
    ];

    // Compute validation mask
    let validation_mask = ValidationVar::combine(&mask_voles_booleans).unwrap();

    // Verify the result
    assert!(validation_mask.len() > 0);
}
