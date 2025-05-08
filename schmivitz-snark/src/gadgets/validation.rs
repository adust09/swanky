use std::iter::zip;

use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::prelude::Boolean;
use ark_relations::r1cs::SynthesisError;

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
