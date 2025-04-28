use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;

pub struct ConstraintVerificationGadget;

impl ConstraintVerificationGadget {
    /// Verifies that the validation value matches the expected value computed from
    /// the degree 1 commitment, verifier key, and degree 0 commitment.
    ///
    /// This implements the final constraint verification logic from the VOLE-in-the-head proof system.
    /// The verification equation is:
    /// actual_validation = degree_1_commitment * verifier_key + degree_0_commitment
    ///
    /// # Arguments
    /// * `validation` - The validation value to check (computed from circuit traversal)
    /// * `degree_1_commitment` - The degree 1 commitment from the proof
    /// * `verifier_key` - The verifier key from the partial decommitment
    /// * `degree_0_commitment` - The degree 0 commitment from the proof
    ///
    /// # Returns
    /// A boolean indicating whether the validation equation is satisfied

    #[tracing::instrument(
        target = "r1cs",
        skip(degree_0_commitment, degree_1_commitment, verifier_key, validation)
    )]
    pub fn verify(
        degree_0_commitment: &FpVar<Bn254Fr>,
        degree_1_commitment: &FpVar<Bn254Fr>,
        verifier_key: &FpVar<Bn254Fr>,
        validation: &FpVar<Bn254Fr>,
    ) -> Result<Boolean<Bn254Fr>, SynthesisError> {
        // L287-L292
        // Calculate actual_validation = degree_1_commitment * verifier_key + degree_0_commitment
        let actual_validation = degree_1_commitment.clone() * verifier_key + degree_0_commitment;

        // Check if validation == actual_validation
        validation.is_eq(&actual_validation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_constraint_verification_valid() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let degree_0_commitment_val = Fr::from(5u32);
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);
        let validation_val = Fr::from(17u32); // Expected validation value: 3 * 4 + 5 = 17

        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        let result = ConstraintVerificationGadget::verify(
            &validation,
            &degree_0_commitment,
            &degree_1_commitment,
            &verifier_key,
        )
        .unwrap();

        // failed this
        assert!(result.value().unwrap());
        // passed below
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_constraint_verification_invalid() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test values
        let degree_0_commitment_val = Fr::from(5u32);
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);

        // Incorrect validation value: should be 3 * 4 + 5 = 17, but we use 16
        let validation_val = Fr::from(16u32);

        // Create variables
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();

        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        // Verify
        let result = ConstraintVerificationGadget::verify(
            &validation,
            &degree_0_commitment,
            &degree_1_commitment,
            &verifier_key,
        )
        .unwrap();

        // Check that the result is false
        assert!(!result.value().unwrap());

        // Check that the constraints are satisfied (the gadget should still generate valid constraints)
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    /// Test with all zero values
    fn test_edge_case_zero_values() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test case: All zeros
        let degree_0_commitment_val = Fr::from(0u32);
        let degree_1_commitment_val = Fr::from(0u32);
        let verifier_key_val = Fr::from(0u32);
        let validation_val = Fr::from(0u32); // Expected: 0 * 0 + 0 = 0

        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        let result = ConstraintVerificationGadget::verify(
            &validation,
            &degree_0_commitment,
            &degree_1_commitment,
            &verifier_key,
        )
        .unwrap();

        assert!(result.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    /// Test with large values near field size
    fn test_edge_case_large_values() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Use large values close to the field size
        // For Bn254, the field size is approximately 2^254
        // We'll use values that are large but still within the field
        let large_value = Fr::from(u64::MAX); // Maximum u64 value

        let degree_0_commitment_val = large_value;
        let degree_1_commitment_val = large_value;
        let verifier_key_val = Fr::from(2u32); // Simple multiplier
        let validation_val = large_value * Fr::from(2u32) + large_value;

        // Calculate expected validation: large_value * 2 + large_value
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();

        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        let result = ConstraintVerificationGadget::verify(
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        )
        .unwrap();

        assert!(result.value().unwrap());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    /// Test error handling for invalid inputs
    fn test_error_handling() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test values
        let degree_0_commitment_val = Fr::from(5u32);
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);
        let validation_val = Fr::from(17u32);

        // Create variables
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();

        // Test with a constraint system that has been finalized
        // This should not cause an error, as the gadget should be robust
        cs.finalize();

        // Verify after finalization
        let result = ConstraintVerificationGadget::verify(
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        );

        // The operation should still succeed even with a finalized constraint system
        assert!(result.is_ok());

        // Create a new constraint system for testing with invalid variable types
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create a constant instead of a witness
        let degree_0_commitment = FpVar::new_constant(cs.clone(), degree_0_commitment_val).unwrap();
        let degree_1_commitment = FpVar::new_constant(cs.clone(), degree_1_commitment_val).unwrap();
        let verifier_key = FpVar::new_constant(cs.clone(), verifier_key_val).unwrap();
        let validation = FpVar::new_constant(cs.clone(), validation_val).unwrap();

        // Verify with constants
        let result = ConstraintVerificationGadget::verify(
            &validation,
            &degree_0_commitment,
            &degree_1_commitment,
            &verifier_key,
        );

        // The operation should succeed with constants as well
        assert!(result.is_ok());
        assert!(result.unwrap().value().unwrap());
    }
}
