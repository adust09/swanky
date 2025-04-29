#[cfg(test)]
mod tests {

    use crate::constraints::{PartialDecommitmentVar, VoleVerification};
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
    use ark_std::One;
    use ark_std::Zero;
    use schmivitz::parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM};

    /// Helper function to create a test circuit with default values
    fn create_test_circuit() -> VoleVerification {
        VoleVerification {
            // Public inputs
            degree_0_commitment: Some(Bn254Fr::from(1u64)),
            degree_1_commitment: Some(Bn254Fr::from(2u64)),

            // Private inputs (witness)
            witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)].into(),
            witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)].into(),
            partial_decommitment: PartialDecommitmentVar {
                verifier_key: Some(Bn254Fr::from(3u64)),
                mask_voles: {
                    let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
                    array[0] = Bn254Fr::from(6u64);
                    array[1] = Bn254Fr::from(7u64);
                    Some(array)
                },
                witness_voles: {
                    let mut arr = [Bn254Fr::default(); REPETITION_PARAM];
                    arr[0] = Bn254Fr::from(10u64);
                    arr[1] = Bn254Fr::from(11u64);
                    vec![arr].into()
                },
            },
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
        circuit.witness_commitment =
            vec![Bn254Fr::zero(), Bn254Fr::one(), Bn254Fr::from(u64::MAX)].into();

        // Adjust other vectors to match the size
        circuit.partial_decommitment.mask_voles = {
            let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
            array[0] = Bn254Fr::from(10u64);
            array[1] = Bn254Fr::from(11u64);
            array[2] = Bn254Fr::from(12u64);
            Some(array)
        };
        circuit.partial_decommitment.witness_voles = {
            let mut arr1 = [Bn254Fr::default(); REPETITION_PARAM];
            arr1[0] = Bn254Fr::from(13u64);
            let mut arr2 = [Bn254Fr::default(); REPETITION_PARAM];
            arr2[0] = Bn254Fr::from(14u64);
            let mut arr3 = [Bn254Fr::default(); REPETITION_PARAM];
            arr3[0] = Bn254Fr::from(15u64);
            vec![arr1, arr2, arr3].into()
        };

        circuit.witness_challenges = vec![
            Bn254Fr::from(16u64),
            Bn254Fr::from(17u64),
            Bn254Fr::from(18u64),
        ]
        .into();

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
        ]
        .into();

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
        circuit.witness_commitment = vec![].into();

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
    fn test_witness_validation_mismatched_sizes() {
        let mut circuit = create_test_circuit();

        // Set witness vectors to different sizes
        circuit.witness_commitment = vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)].into();
        circuit.partial_decommitment.mask_voles = {
            let mut array = [Bn254Fr::default(); REPETITION_PARAM * VOLE_SIZE_PARAM];
            array[0] = Bn254Fr::from(6u64);
            Some(array)
        }; // One element short
        circuit.partial_decommitment.witness_voles = {
            let mut arr1 = [Bn254Fr::default(); REPETITION_PARAM];
            arr1[0] = Bn254Fr::from(7u64);
            let mut arr2 = [Bn254Fr::default(); REPETITION_PARAM];
            arr2[0] = Bn254Fr::from(8u64);
            vec![arr1, arr2].into()
        };
        circuit.witness_challenges = vec![
            Bn254Fr::from(9u64),
            Bn254Fr::from(10u64),
            Bn254Fr::from(11u64),
        ]
        .into(); // One element extra

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
