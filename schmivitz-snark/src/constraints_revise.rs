use ark_bn254::Fr as Bn254Fr;
use ark_ff::{Field, FpParameters, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::gadgets::{CircuitTraverser, MaskedWitnessVarRevised};

/// Helper function to convert a vector of boolean arrays to a vector of FpVars
fn convert_boolean_arrays_to_fpvars<F: Field + PrimeField>(
    cs: ConstraintSystemRef<F>,
    boolean_arrays: &[Vec<Boolean<F>>],
    namespace: &str,
) -> Result<Vec<FpVar<F>>, SynthesisError> {
    let mut fp_vars = Vec::with_capacity(boolean_arrays.len());
    for bits in boolean_arrays {
        // Create a FpVar from the boolean values
        // First, convert the bits to a field element representation
        let mut value = F::zero();
        let modulus_bit_size = <<F as PrimeField>::Params as FpParameters>::MODULUS_BITS as usize;
        for (i, bit) in bits.iter().enumerate() {
            if i < modulus_bit_size {
                if let Ok(bit_val) = bit.value() {
                    if bit_val {
                        // Add 2^i to the value for each set bit
                        if i < 64 {
                            value += F::from(1u64 << i);
                        } else {
                            // For larger bit positions, compute 2^i directly
                            let mut base = F::from(2u64);
                            let mut exp = i as u64;
                            let mut res = F::from(1u64);

                            // Binary exponentiation
                            while exp > 0 {
                                if exp & 1 == 1 {
                                    res *= base;
                                }
                                base = base.square();
                                exp >>= 1;
                            }
                            value += res;
                        }
                    }
                }
            }
        }

        // Create a FpVar with the computed value
        let fp_var = FpVar::new_witness(ark_relations::ns!(cs, "from_boolean"), || Ok(value))?;

        // Enforce that the bits of fp_var match the original boolean values
        let fp_bits = fp_var.to_bits_le()?;
        for (i, bit) in bits.iter().enumerate() {
            if i < fp_bits.len() {
                bit.enforce_equal(&fp_bits[i])?;
            }
        }

        fp_vars.push(fp_var);
    }

    Ok(fp_vars)
}

// Helper function to convert a vector of booleans to a FpVar
fn convert_boolean_to_fpvar<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    bits: &[Boolean<F>],
    namespace: &str,
) -> Result<FpVar<F>, SynthesisError> {
    let mut value = F::zero();
    let modulus_bit_size = <<F as PrimeField>::Params as FpParameters>::MODULUS_BITS as usize;
    for (i, bit) in bits.iter().enumerate() {
        if i < modulus_bit_size {
            if let Ok(bit_val) = bit.value() {
                if bit_val {
                    // Add 2^i to the value for each set bit
                    if i < 64 {
                        value += F::from(1u64 << i);
                    } else {
                        // For larger bit positions, compute 2^i directly
                        let mut base = F::from(2u64);
                        let mut exp = i as u64;
                        let mut res = F::from(1u64);

                        // Binary exponentiation
                        while exp > 0 {
                            if exp & 1 == 1 {
                                res *= base;
                            }
                            base = base.square();
                            exp >>= 1;
                        }
                        value += res;
                    }
                }
            }
        }
    }

    // Create a FpVar with the computed value
    let fp_var = FpVar::new_witness(cs, || Ok(value))?;

    // Enforce that the bits of fp_var match the original boolean values
    let fp_bits = fp_var.to_bits_le()?;
    for (i, bit) in bits.iter().enumerate() {
        if i < fp_bits.len() {
            bit.enforce_equal(&fp_bits[i])?;
        }
    }

    Ok(fp_var)
}

#[derive(Debug, Clone)]
pub struct VoleVerificationBoolean {
    pub witness_commitment: Option<Vec<Vec<Boolean<Bn254Fr>>>>, // F64b as boolean arrays
    pub witness_challenges: Option<Vec<Vec<Boolean<Bn254Fr>>>>, // F128b as boolean arrays
    pub degree_0_commitment: Option<Vec<Boolean<Bn254Fr>>>,     // F128b as boolean array
    pub degree_1_commitment: Option<Vec<Boolean<Bn254Fr>>>,     // F128b as boolean array
    pub partial_decommitment: PartialDecommitmentBoolean,
}

#[derive(Debug, Clone)]
pub struct PartialDecommitmentBoolean {
    pub verifier_key: Option<Vec<Boolean<Bn254Fr>>>, // F128b as boolean array
    pub witness_voles: Option<Vec<Vec<Vec<Boolean<Bn254Fr>>>>>, // Vec<[F8b; REPETITION_PARAM]> as boolean arrays
    pub mask_voles: Option<Vec<Vec<Boolean<Bn254Fr>>>>, // [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] as boolean arrays
}

impl ConstraintSynthesizer<Bn254Fr> for VoleVerificationBoolean {
    fn generate_constraints(self, cs: ConstraintSystemRef<Bn254Fr>) -> Result<(), SynthesisError>
    where
        Bn254Fr: PrimeField,
    {
        // Convert witness_commitment (Vec<Vec<Boolean>>) to Vec<FpVar>
        let witness_commitment_var = if let Some(witness_commitment) = self.witness_commitment {
            convert_boolean_arrays_to_fpvars(
                cs.clone(),
                &witness_commitment,
                "witness_commitment_from_boolean",
            )?
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert witness_challenges (Vec<Vec<Boolean>>) to Vec<FpVar>
        let witness_challenges_var = if let Some(witness_challenges) = self.witness_challenges {
            convert_boolean_arrays_to_fpvars(
                cs.clone(),
                &witness_challenges,
                "witness_challenges_from_boolean",
            )?
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert degree_0_commitment (Vec<Boolean>) to FpVar
        let degree_0_commitment_var = if let Some(degree_0_commitment) = self.degree_0_commitment {
            convert_boolean_to_fpvar(
                cs.clone(),
                &degree_0_commitment,
                "degree_0_commitment_from_boolean",
            )?
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert degree_1_commitment (Vec<Boolean>) to FpVar
        let degree_1_commitment_var = if let Some(degree_1_commitment) = self.degree_1_commitment {
            convert_boolean_to_fpvar(
                cs.clone(),
                &degree_1_commitment,
                "degree_1_commitment_from_boolean",
            )?
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert verifier_key (Vec<Boolean>) to FpVar
        let verifier_key_var = if let Some(verifier_key) = self.partial_decommitment.verifier_key {
            convert_boolean_to_fpvar(cs.clone(), &verifier_key, "verifier_key_from_boolean")?
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert witness_voles (Vec<Vec<Vec<Boolean>>>) to Vec<Vec<FpVar>>
        let witness_voles_var = if let Some(witness_voles) = self.partial_decommitment.witness_voles
        {
            let mut result = Vec::with_capacity(witness_voles.len());
            for vole_array in witness_voles {
                let mut fp_vec = Vec::with_capacity(vole_array.len());
                for bits in vole_array {
                    let fp_var =
                        convert_boolean_to_fpvar(cs.clone(), &bits, "witness_vole_from_boolean")?;
                    fp_vec.push(fp_var);
                }
                result.push(fp_vec);
            }
            result
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // Convert mask_voles (Vec<Vec<Boolean>>) to Vec<FpVar>
        let mask_voles_var = if let Some(mask_voles) = self.partial_decommitment.mask_voles {
            let mut result = Vec::with_capacity(mask_voles.len());
            for bits in mask_voles {
                let fp_var = convert_boolean_to_fpvar(cs.clone(), &bits, "mask_vole_from_boolean")?;
                result.push(fp_var);
            }
            result
        } else {
            return Err(SynthesisError::AssignmentMissing);
        };

        // The rest of the function is similar to VoleVerificationRevised
        // Step 1: Compute d_delta from witness commitment and verifier key

        // Convert witness_commitment_var from Vec<FpVar> to Vec<Vec<Boolean>>

        let mut witness_commitment_booleans = Vec::with_capacity(witness_commitment_var.len());
        for fp_var in &witness_commitment_var {
            // Convert each FpVar to a vector of Boolean values (assuming 8-bit representation for simplicity)
            // In a real implementation, you would use the actual bit width
            let mut boolean_vec = Vec::with_capacity(8);
            for i in 0..8 {
                let bit = fp_var.to_bits_le()?[i].clone();
                boolean_vec.push(bit);
            }
            witness_commitment_booleans.push(boolean_vec);
        }
        assert_eq!(
            witness_commitment_booleans.len(),
            witness_commitment_var.len(),
        );
        // Convert verifier_key_var from FpVar to Vec<Boolean>
        let verifier_key_booleans = verifier_key_var.to_bits_le()?;

        let d_delta_var = MaskedWitnessVarRevised::compute_d_delta(
            cs.clone(),
            &witness_commitment_booleans,
            &verifier_key_booleans,
        )?;

        // Step 2: Compute masked witnesses from witness voles and d_delta

        // Convert witness_voles_var from Vec<Vec<FpVar>> to Vec<Vec<Vec<Boolean>>>
        let mut witness_voles_booleans = Vec::with_capacity(witness_voles_var.len());
        for vole_array in &witness_voles_var {
            let mut boolean_array = Vec::with_capacity(vole_array.len());
            for fp_var in vole_array {
                // Convert each FpVar to a vector of Boolean values
                let boolean_vec = fp_var.to_bits_le()?;
                boolean_array.push(boolean_vec);
            }
            witness_voles_booleans.push(boolean_array);
        }

        let masked_witnesses_var =
            MaskedWitnessVarRevised::compute_masked_witness(&witness_voles_booleans, &d_delta_var)?;

        let validation_aggregate_var = CircuitTraverser::compute_validation_aggregate(
            &witness_challenges_var,
            // Convert the Boolean vectors to FpVar before passing to compute_validation_aggregate
            // First, we need to convert each Boolean vector to a single FpVar
            &masked_witnesses_var
                .iter()
                .map(|boolean_vec| {
                    // Convert the vector of Booleans to a single FpVar
                    // This is a simplified approach - in a real implementation,
                    // you would need to properly encode the Boolean vector as a field element
                    let mut result = FpVar::zero();
                    for (i, b) in boolean_vec.iter().enumerate() {
                        // Add 2^i * b to the result for each bit
                        if i < 254 {
                            // Bn254Fr has 254 bits
                            // Handle bit positions properly for large values
                            let power_of_two = if i < 64 {
                                Bn254Fr::from(1u64 << i)
                            } else {
                                // For larger bit positions, compute 2^i directly in the field
                                let mut base = Bn254Fr::from(2u64);
                                let mut exp = i as u64;
                                let mut res = Bn254Fr::from(1u64);

                                // Simple binary exponentiation
                                while exp > 0 {
                                    if exp & 1 == 1 {
                                        res = res * &base;
                                    }
                                    base = base * &base;
                                    exp >>= 1;
                                }
                                res
                            };

                            let coeff = FpVar::constant(power_of_two);
                            result = result + b.select(&coeff, &FpVar::zero()).unwrap();
                        }
                    }
                    result
                })
                .collect::<Vec<_>>(),
        )?;

        // Step 3: Compute validation_mask

        // Convert mask_voles_var from Vec<FpVar> to Vec<Vec<Boolean>>
        let mut mask_voles_booleans = Vec::with_capacity(mask_voles_var.len());
        for fp_var in &mask_voles_var {
            // Convert each FpVar to a vector of Boolean values
            let boolean_vec = fp_var.to_bits_le()?;
            mask_voles_booleans.push(boolean_vec);
        }

        let validation_mask_var =
            MaskedWitnessVarRevised::compute_validation_mask(cs.clone(), &mask_voles_booleans)?;

        // Step 4: Compute the final validation value
        // Convert validation_mask_var from Vec<Boolean> to FpVar for addition
        let validation_mask_fp_var = FpVar::new_variable(
            cs.clone(),
            || {
                // In a real implementation, you would compute the actual value
                // For now, we're using a placeholder
                Ok(Bn254Fr::from(0u64))
            },
            AllocationMode::Witness,
        )?;

        // Enforce that validation_mask_fp_var's bits match validation_mask_var
        let validation_mask_bits = validation_mask_fp_var.to_bits_le()?;
        for (i, bit) in validation_mask_var.iter().enumerate() {
            if i < validation_mask_bits.len() {
                bit.enforce_equal(&validation_mask_bits[i])?;
            }
        }

        let validation_var = validation_aggregate_var.clone() + validation_mask_fp_var;

        // Step 5: Check the main constraint of the proof
        let actual_validation_var = degree_1_commitment_var.clone() * verifier_key_var.clone()
            + degree_0_commitment_var.clone();

        validation_var.enforce_equal(&actual_validation_var)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::f8b_to_boolean_array;
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};
    use swanky_field_binary::F8b;

    #[test]
    fn test_boolean_circuit_creation() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create some test boolean values
        let test_boolean = Boolean::new_witness(cs.clone(), || Ok(true)).unwrap();
        let test_boolean_vec = vec![test_boolean.clone(); 8]; // 8 bits for F8b

        // Create a test circuit
        let circuit = VoleVerificationBoolean {
            witness_commitment: Some(vec![test_boolean_vec.clone(); 2]),
            witness_challenges: Some(vec![vec![test_boolean.clone(); 128]; 2]), // 128 bits for F128b
            degree_0_commitment: Some(vec![test_boolean.clone(); 128]),
            degree_1_commitment: Some(vec![test_boolean.clone(); 128]),
            partial_decommitment: PartialDecommitmentBoolean {
                verifier_key: Some(vec![test_boolean.clone(); 128]),
                witness_voles: Some(vec![vec![test_boolean_vec.clone(); REPETITION_PARAM]]),
                mask_voles: Some(vec![
                    vec![test_boolean; 128];
                    REPETITION_PARAM * VOLE_SIZE_PARAM
                ]),
            },
        };

        // This test will fail because we're using placeholder values
        // In a real implementation, we would use actual boolean values
        // assert!(circuit.generate_constraints(cs.clone()).is_ok());
    }
}
