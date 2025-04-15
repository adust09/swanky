use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::ops::{Add, Mul};

/// CircuitTraversalGadget is responsible for traversing the circuit structure
/// and computing the validation aggregate based on witness challenges and masked witnesses.
pub struct CircuitTraversalGadget;

impl CircuitTraversalGadget {
    /// Computes the validation aggregate by traversing the circuit structure.
    ///
    /// # Arguments
    ///
    /// * `cs` - Constraint system reference
    /// * `witness_challenge` - Array of witness challenges
    /// * `verifier_key` - Verifier key
    /// * `masked_witnesses` - Array of masked witnesses computed from witness commitments
    ///
    /// # Returns
    ///
    /// * Result containing the validation aggregate or a synthesis error
    pub fn compute_validation_aggregate(
        _cs: ConstraintSystemRef<Bn254Fr>,
        witness_challenge: &[FpVar<Bn254Fr>],
        _verifier_key: &FpVar<Bn254Fr>,
        masked_witnesses: &[FpVar<Bn254Fr>],
    ) -> Result<FpVar<Bn254Fr>, SynthesisError> {
        // Ensure we have the same number of challenges as masked witnesses
        if witness_challenge.len() != masked_witnesses.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Initialize the validation aggregate with zero
        let mut validation_aggregate = FpVar::zero();

        // Traverse the circuit structure and compute the validation aggregate
        // The validation aggregate is computed as the sum of (challenge * masked_witness)
        // for each wire in the circuit
        for (challenge, masked_witness) in witness_challenge.iter().zip(masked_witnesses.iter()) {
            // Compute challenge * masked_witness
            let term = challenge.mul(masked_witness);

            // Add to the validation aggregate
            validation_aggregate = validation_aggregate.add(&term);
        }

        Ok(validation_aggregate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    // Helper function to create a new constraint system
    fn create_cs() -> ConstraintSystemRef<Fr> {
        let cs = ConstraintSystem::<Fr>::new_ref();
        cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
        cs
    }

    // Helper function to create FpVar values
    fn create_fp_var(cs: ConstraintSystemRef<Fr>, value: u64) -> FpVar<Fr> {
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(value))).unwrap()
    }

    #[test]
    /// Test validation aggregate computation with simple circuit structures
    fn test_simple_validation_aggregate() {
        let cs = create_cs();

        // Create test inputs for a simple circuit
        // Witness challenges
        let witness_challenges = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
        ];

        // Verifier key
        let verifier_key = create_fp_var(cs.clone(), 5);

        // Masked witnesses
        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        // Compute validation aggregate
        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 1*10 + 2*20 + 3*30 = 10 + 40 + 90 = 140
        let expected = Fr::from(140u64);

        // Check the result
        assert_eq!(validation_aggregate.value().unwrap(), expected);

        // Check that constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    /// Test with different witness challenge patterns
    fn test_different_challenge_patterns() {
        let cs = create_cs();

        // Test case 1: Alternating challenges (1, 0, 1, 0, ...)
        let witness_challenges = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 0),
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 0),
        ];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
            create_fp_var(cs.clone(), 40),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 1*10 + 0*20 + 1*30 + 0*40 = 10 + 0 + 30 + 0 = 40
        let expected = Fr::from(40u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());

        // Test case 2: Increasing challenges (1, 2, 3, ...)
        let cs = create_cs();

        let witness_challenges = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
            create_fp_var(cs.clone(), 4),
        ];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 5),
            create_fp_var(cs.clone(), 5),
            create_fp_var(cs.clone(), 5),
            create_fp_var(cs.clone(), 5),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 1*5 + 2*5 + 3*5 + 4*5 = 5 + 10 + 15 + 20 = 50
        let expected = Fr::from(50u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    /// Test with edge cases (zero challenges, maximum field values)
    fn test_edge_cases() {
        let cs = create_cs();

        // Test case 1: All zeros
        let witness_challenges = vec![
            create_fp_var(cs.clone(), 0),
            create_fp_var(cs.clone(), 0),
            create_fp_var(cs.clone(), 0),
        ];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 0*10 + 0*20 + 0*30 = 0
        let expected = Fr::from(0u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());

        // Test case 2: Large values (near field size)
        let cs = create_cs();

        // Use large values close to the field size
        let large_value = Fr::from(u64::MAX); // Maximum u64 value

        let witness_challenges = vec![create_fp_var(cs.clone(), 1), create_fp_var(cs.clone(), 1)];

        let verifier_key = create_fp_var(cs.clone(), 5);

        // Create masked witnesses with large values
        let masked_witness1 = FpVar::new_witness(cs.clone(), || Ok(large_value)).unwrap();
        let masked_witness2 = FpVar::new_witness(cs.clone(), || Ok(large_value)).unwrap();

        let masked_witnesses = vec![masked_witness1, masked_witness2];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 1*large_value + 1*large_value = 2*large_value
        let expected = large_value + large_value;

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());

        // Test case 3: Empty inputs
        let cs = create_cs();

        let witness_challenges: Vec<FpVar<Fr>> = vec![];
        let verifier_key = create_fp_var(cs.clone(), 5);
        let masked_witnesses: Vec<FpVar<Fr>> = vec![];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 0 (empty sum)
        let expected = Fr::from(0u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    /// Test error handling for invalid inputs
    fn test_error_handling() {
        let cs = create_cs();

        // Test case: Mismatched lengths
        let witness_challenges = vec![create_fp_var(cs.clone(), 1), create_fp_var(cs.clone(), 2)];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30), // One more than challenges
        ];

        let result = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        );

        // Should return an error
        assert!(result.is_err());

        // Check that the error is SynthesisError::Unsatisfiable
        match result {
            Err(SynthesisError::Unsatisfiable) => {}
            _ => panic!("Expected SynthesisError::Unsatisfiable"),
        }
    }

    #[test]
    /// Test constraint satisfaction for different circuit structures
    fn test_constraint_satisfaction() {
        // Test case 1: Simple linear circuit
        let cs = create_cs();

        let witness_challenges = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
        ];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        let _ = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Check that constraints are satisfied
        assert!(cs.is_satisfied().unwrap());

        // Test case 2: More complex circuit with more variables
        let cs = create_cs();

        let witness_challenges = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
            create_fp_var(cs.clone(), 4),
            create_fp_var(cs.clone(), 5),
        ];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
            create_fp_var(cs.clone(), 40),
            create_fp_var(cs.clone(), 50),
        ];

        let _ = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
            &verifier_key,
            &masked_witnesses,
        )
        .unwrap();

        // Check that constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    /// Benchmark constraint count for circuits of varying complexity
    fn benchmark_constraint_count() {
        // Test with different circuit sizes
        let sizes = vec![1, 10, 100];

        for size in sizes {
            let cs = create_cs();

            // Create test inputs of the specified size
            let mut witness_challenges = Vec::new();
            let mut masked_witnesses = Vec::new();

            for i in 0..size {
                witness_challenges.push(create_fp_var(cs.clone(), i as u64));
                masked_witnesses.push(create_fp_var(cs.clone(), (i + size) as u64));
            }

            let verifier_key = create_fp_var(cs.clone(), 5);

            // Record the constraint count before computation
            let constraints_before = cs.num_constraints();

            // Compute validation aggregate
            let _ = CircuitTraversalGadget::compute_validation_aggregate(
                cs.clone(),
                &witness_challenges,
                &verifier_key,
                &masked_witnesses,
            )
            .unwrap();

            // Record the constraint count after computation
            let constraints_after = cs.num_constraints();

            // Calculate the number of constraints added
            let constraints_added = constraints_after - constraints_before;

            // Print the benchmark results
            println!(
                "Circuit size: {}, Constraints added: {}",
                size, constraints_added
            );

            // Verify that the number of constraints scales linearly with circuit size
            // Each term in the sum should add a constant number of constraints
            assert!(constraints_added <= size * 10); // Assuming at most 10 constraints per element
        }
    }
}
