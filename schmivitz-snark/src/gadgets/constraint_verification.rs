use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

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
    /// * `cs` - Constraint system reference
    /// * `validation` - The validation value to check (computed from circuit traversal)
    /// * `degree_1_commitment` - The degree 1 commitment from the proof
    /// * `verifier_key` - The verifier key from the partial decommitment
    /// * `degree_0_commitment` - The degree 0 commitment from the proof
    ///
    /// # Returns
    /// A boolean indicating whether the validation equation is satisfied
    pub fn verify(
        _cs: ConstraintSystemRef<Bn254Fr>,
        validation: &FpVar<Bn254Fr>,
        degree_1_commitment: &FpVar<Bn254Fr>,
        verifier_key: &FpVar<Bn254Fr>,
        degree_0_commitment: &FpVar<Bn254Fr>,
    ) -> Result<Boolean<Bn254Fr>, SynthesisError> {
        // Calculate actual_validation = degree_1_commitment * verifier_key + degree_0_commitment
        let product = degree_1_commitment.clone() * verifier_key;
        let actual_validation = product.clone() + degree_0_commitment;

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
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test values
        let degree_0_commitment_val = Fr::from(5u32);
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);
        let validation_val = Fr::from(17u32); // Expected validation value: 3 * 4 + 5 = 17

        // Create variables
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        // Verify
        let result = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        )
        .unwrap();

        // Check that the result is true
        assert!(result.value().unwrap());

        // Check that the constraints are satisfied
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
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        // Verify
        let result = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        )
        .unwrap();

        // Check that the result is false
        assert!(!result.value().unwrap());

        // Check that the constraints are satisfied (the gadget should still generate valid constraints)
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    /// Test with edge cases (zero values, maximum field values)
    fn test_edge_cases() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Test case 1: All zeros
        let degree_0_commitment_val = Fr::from(0u32);
        let degree_1_commitment_val = Fr::from(0u32);
        let verifier_key_val = Fr::from(0u32);
        let validation_val = Fr::from(0u32); // Expected: 0 * 0 + 0 = 0

        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        let result = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        )
        .unwrap();

        assert!(result.value().unwrap());
        assert!(cs.is_satisfied().unwrap());

        // Test case 2: Large values (near field size)
        // Create a new constraint system for the second test
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Use large values close to the field size
        // For Bn254, the field size is approximately 2^254
        // We'll use values that are large but still within the field
        let large_value = Fr::from(u64::MAX); // Maximum u64 value

        let degree_0_commitment_val = large_value;
        let degree_1_commitment_val = large_value;
        let verifier_key_val = Fr::from(2u32); // Simple multiplier

        // Calculate expected validation: large_value * 2 + large_value
        let validation_val = large_value * Fr::from(2u32) + large_value;

        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        let result = ConstraintVerificationGadget::verify(
            cs.clone(),
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
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        // Test with a constraint system that has been finalized
        // This should not cause an error, as the gadget should be robust
        cs.finalize();

        // Verify after finalization
        let result = ConstraintVerificationGadget::verify(
            cs.clone(),
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
        let degree_1_commitment = FpVar::new_constant(cs.clone(), degree_1_commitment_val).unwrap();
        let verifier_key = FpVar::new_constant(cs.clone(), verifier_key_val).unwrap();
        let degree_0_commitment = FpVar::new_constant(cs.clone(), degree_0_commitment_val).unwrap();
        let validation = FpVar::new_constant(cs.clone(), validation_val).unwrap();

        // Verify with constants
        let result = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        );

        // The operation should succeed with constants as well
        assert!(result.is_ok());
        assert!(result.unwrap().value().unwrap());
    }

    #[test]
    /// Benchmark constraint count for the verification operation
    fn benchmark_constraint_count() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);

        // Create test values
        let degree_0_commitment_val = Fr::from(5u32);
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);
        let validation_val = Fr::from(17u32);

        // Create variables
        let degree_1_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_1_commitment_val)).unwrap();
        let verifier_key = FpVar::new_witness(cs.clone(), || Ok(verifier_key_val)).unwrap();
        let degree_0_commitment =
            FpVar::new_witness(cs.clone(), || Ok(degree_0_commitment_val)).unwrap();
        let validation = FpVar::new_witness(cs.clone(), || Ok(validation_val)).unwrap();

        // Record the constraint count before verification
        let constraints_before = cs.num_constraints();

        // Verify
        let _ = ConstraintVerificationGadget::verify(
            cs.clone(),
            &validation,
            &degree_1_commitment,
            &verifier_key,
            &degree_0_commitment,
        )
        .unwrap();

        // Record the constraint count after verification
        let constraints_after = cs.num_constraints();

        // Calculate the number of constraints added
        let constraints_added = constraints_after - constraints_before;

        // Print the benchmark results
        println!("Constraints added by verification: {}", constraints_added);

        // The verification should add a small, constant number of constraints
        // Typically, it should add constraints for:
        // 1. Multiplication: degree_1_commitment * verifier_key
        // 2. Addition: product + degree_0_commitment
        // 3. Equality check: validation == actual_validation
        assert!(constraints_added <= 10); // Assuming at most 10 constraints
    }
}
