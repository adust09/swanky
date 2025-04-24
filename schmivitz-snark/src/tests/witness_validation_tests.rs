#[cfg(test)]
mod tests {

    use crate::constraints::VoleVerificationCircuit;
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
    use ark_std::One;
    use ark_std::Zero;

    /// Helper function to create a test circuit with default values
    fn create_test_circuit() -> VoleVerificationCircuit {
        VoleVerificationCircuit {
            // Public inputs
            degree_0_commitment: Bn254Fr::from(1u64),
            degree_1_commitment: Bn254Fr::from(2u64),
            verifier_key: Bn254Fr::from(3u64),

            // Private inputs (witness)
            witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)],
            partial_decommitment: vec![Bn254Fr::from(6u64), Bn254Fr::from(7u64)],
            witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)],

            // Circuit description
            circuit_gates: Vec::new(),
        }
    }

    /// Helper function to create a new constraint system
    fn create_cs() -> ConstraintSystemRef<Bn254Fr> {
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
        cs
    }

    #[test]
    fn test_witness_validation_boundary_values() {
        let mut circuit = create_test_circuit();

        // Set witness values to boundary values
        circuit.witness_commitment = vec![Bn254Fr::zero(), Bn254Fr::one(), Bn254Fr::from(u64::MAX)];

        // Adjust other vectors to match the size
        circuit.partial_decommitment = vec![
            Bn254Fr::from(10u64),
            Bn254Fr::from(11u64),
            Bn254Fr::from(12u64),
        ];

        circuit.witness_challenges = vec![
            Bn254Fr::from(13u64),
            Bn254Fr::from(14u64),
            Bn254Fr::from(15u64),
        ];

        let cs = create_cs();

        // Generate constraints
        let result = circuit.generate_constraints(cs.clone());

        // Check that constraint generation succeeds with boundary values
        assert!(
            result.is_ok(),
            "Constraint generation should succeed with boundary values"
        );

        // Check that constraints were generated
        let num_constraints = cs.num_constraints();
        println!(
            "Number of constraints with boundary values: {}",
            num_constraints
        );
        assert!(
            num_constraints > 0,
            "Expected constraints to be generated with boundary values, but got {}",
            num_constraints
        );

        // Note: We're not checking if the constraints are satisfied yet
        // This will be done in a future implementation
    }

    #[test]
    fn test_witness_validation_invalid_field_elements() {
        let mut circuit = create_test_circuit();

        // In a real implementation, we would create invalid field elements
        // For now, we'll use valid field elements but note that this test
        // should be updated when proper validation is implemented

        // Set witness values to potentially problematic values
        circuit.witness_commitment = vec![
            // These are actually valid field elements, but in a real implementation
            // we would use invalid field elements if possible
            Bn254Fr::from(u64::MAX),
            Bn254Fr::from(u64::MAX - 1),
        ];

        let cs = create_cs();

        // Generate constraints
        let result = circuit.generate_constraints(cs.clone());

        // In a real implementation with proper validation, this should fail
        // For now, we expect it to succeed since we're using valid field elements
        assert!(
            result.is_ok(),
            "Constraint generation should succeed with valid field elements"
        );

        // Note: This test should be updated when proper validation is implemented
        // to check that invalid field elements are properly rejected
        println!("Note: This test should be updated when proper validation is implemented");
    }

    #[test]
    fn test_witness_validation_missing_values() {
        let mut circuit = create_test_circuit();

        // Set witness values to an empty vector (missing values)
        circuit.witness_commitment = vec![];

        let cs = create_cs();

        // Generate constraints
        let result = circuit.generate_constraints(cs.clone());

        // In a real implementation with proper validation, this should fail
        // For now, we expect it to fail since the circuit implementation likely
        // assumes that the witness vectors have the expected size
        assert!(
            result.is_err(),
            "Constraint generation should fail with missing witness values"
        );

        // Note: This test should be updated when proper validation is implemented
        println!("Note: This test should be updated when proper validation is implemented");
    }

    #[test]
    fn test_witness_validation_extra_values() {
        let mut circuit = create_test_circuit();

        // Set witness values to a vector with extra values
        circuit.witness_commitment = vec![
            Bn254Fr::from(4u64),
            Bn254Fr::from(5u64),
            Bn254Fr::from(6u64),
            Bn254Fr::from(7u64),
            Bn254Fr::from(8u64),
        ];

        // Keep other vectors at their original size to create a mismatch

        let cs = create_cs();

        // Generate constraints
        let result = circuit.generate_constraints(cs.clone());

        // In a real implementation with proper validation, this should fail
        // For now, we expect it to fail since the circuit implementation likely
        // assumes that the witness vectors have the expected size
        assert!(
            result.is_err(),
            "Constraint generation should fail with extra witness values"
        );

        // Note: This test should be updated when proper validation is implemented
        println!("Note: This test should be updated when proper validation is implemented");
    }

    #[test]
    fn test_witness_validation_mismatched_sizes() {
        let mut circuit = create_test_circuit();

        // Set witness vectors to different sizes
        circuit.witness_commitment = vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)];
        circuit.partial_decommitment = vec![Bn254Fr::from(6u64)]; // One element short
        circuit.witness_challenges = vec![
            Bn254Fr::from(8u64),
            Bn254Fr::from(9u64),
            Bn254Fr::from(10u64),
        ]; // One element extra

        let cs = create_cs();

        // Generate constraints
        let result = circuit.generate_constraints(cs.clone());

        // In a real implementation with proper validation, this should fail
        // For now, we expect it to fail since the circuit implementation likely
        // assumes that the witness vectors have the expected size
        assert!(
            result.is_err(),
            "Constraint generation should fail with mismatched vector sizes"
        );

        // Note: This test should be updated when proper validation is implemented
        println!("Note: This test should be updated when proper validation is implemented");
    }
}
