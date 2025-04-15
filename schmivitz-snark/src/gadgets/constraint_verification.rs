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
    use ark_r1cs_std::R1CSVar;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_constraint_verification_valid() {
        // Create a new constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Create test values
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);
        let degree_0_commitment_val = Fr::from(5u32);

        // Expected validation value: 3 * 4 + 5 = 17
        let validation_val = Fr::from(17u32);

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
        let degree_1_commitment_val = Fr::from(3u32);
        let verifier_key_val = Fr::from(4u32);
        let degree_0_commitment_val = Fr::from(5u32);

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
}
