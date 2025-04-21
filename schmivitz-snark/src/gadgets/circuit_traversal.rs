use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::collections::HashMap;
use std::ops::{Add, Mul};

/// Type alias for wire identifiers in the circuit
pub type WireId = u64;

/// Represents a range of wires in the circuit
#[derive(Clone, Copy, Debug)]
pub struct WireRange {
    pub start: WireId,
    pub end: WireId,
}

/// CircuitTraversalGadget is responsible for traversing the circuit structure
/// and computing the validation aggregate based on witness challenges and masked witnesses.
///
/// This gadget implements a similar functionality to the VerifierTraverser in the original
/// schmivitz implementation, but adapted for use with R1CS constraints.
pub struct CircuitTraversalGadget {
    /// Constraint system reference
    cs: ConstraintSystemRef<Bn254Fr>,

    /// Fiat-Shamir challenges. There should be one for each polynomial (non-linear gate).
    challenges: Vec<FpVar<Bn254Fr>>,

    /// Number of challenges that have been assigned to a wire, so far.
    challenge_count: usize,

    /// Verifier's chosen random VOLE key (Δ in the paper).
    verifier_key: FpVar<Bn254Fr>,

    /// The masked witness commitments (q' in the paper).
    masked_witnesses: Vec<FpVar<Bn254Fr>>,

    /// Assignment of masked witnesses to specific wires in the circuit.
    assigned_masked_witnesses: HashMap<WireId, FpVar<Bn254Fr>>,

    /// Count of how many of the provided masked witnesses have been assigned.
    assigned_witness_count: usize,

    /// Partial aggregation of the value c~ from the protocol.
    aggregate: FpVar<Bn254Fr>,
}

impl CircuitTraversalGadget {
    /// Creates a new CircuitTraversalGadget instance.
    ///
    /// # Arguments
    ///
    /// * `cs` - Constraint system reference
    /// * `challenges` - Array of witness challenges
    /// * `verifier_key` - Verifier key
    /// * `masked_witnesses` - Array of masked witnesses computed from witness commitments
    ///
    /// # Returns
    ///
    /// * Result containing the CircuitTraversalGadget or a synthesis error
    pub fn new(
        cs: ConstraintSystemRef<Bn254Fr>,
        challenges: Vec<FpVar<Bn254Fr>>,
        verifier_key: FpVar<Bn254Fr>,
        masked_witnesses: Vec<FpVar<Bn254Fr>>,
    ) -> Result<Self, SynthesisError> {
        if challenges.len() > masked_witnesses.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(Self {
            cs,
            challenges,
            challenge_count: 0,
            verifier_key,
            masked_witnesses,
            assigned_masked_witnesses: HashMap::new(),
            assigned_witness_count: 0,
            aggregate: FpVar::zero(),
        })
    }

    /// Assign a wire ID to a specific masked witness.
    ///
    /// This should be called with the destination WireId for each linear gate encountered.
    /// The correct masked witness is determined by the specific gate type; for example, the
    /// correct witness for an addition gate is the sum of the witnesses of the two input wires.
    ///
    /// # Arguments
    ///
    /// * `wid` - Wire ID to assign the masked witness to
    /// * `masked_witness` - The masked witness value to assign
    ///
    /// # Returns
    ///
    /// * Result containing () or a synthesis error
    fn save_computed_masked_witness(
        &mut self,
        wid: WireId,
        masked_witness: FpVar<Bn254Fr>,
    ) -> Result<(), SynthesisError> {
        if self.assigned_masked_witnesses.contains_key(&wid) {
            return Err(SynthesisError::Unsatisfiable);
        }

        self.assigned_masked_witnesses.insert(wid, masked_witness);
        Ok(())
    }

    /// Assign a wire ID to the next unused masked witness.
    ///
    /// This should be called with the destination WireId for each non-linear gate.
    /// It should not be used with linear gates! Use save_computed_masked_witness to
    /// assign a specific witness value to a linear gate.
    ///
    /// # Arguments
    ///
    /// * `wid` - Wire ID to assign the masked witness to
    ///
    /// # Returns
    ///
    /// * Result containing () or a synthesis error
    fn assign_masked_witness(&mut self, wid: WireId) -> Result<(), SynthesisError> {
        let next_index = self.assigned_witness_count;
        self.assigned_witness_count += 1;

        if next_index >= self.masked_witnesses.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        self.save_computed_masked_witness(wid, self.masked_witnesses[next_index].clone())
    }

    /// Retrieves the next unused challenge.
    ///
    /// # Returns
    ///
    /// * Result containing the next challenge or a synthesis error
    fn next_challenge(&mut self) -> Result<FpVar<Bn254Fr>, SynthesisError> {
        let next_index = self.challenge_count;
        self.challenge_count += 1;

        if next_index >= self.challenges.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(self.challenges[next_index].clone())
    }

    /// Retrieve the masked witness associated with the WireId.
    ///
    /// # Arguments
    ///
    /// * `wid` - Wire ID to retrieve the masked witness for
    ///
    /// # Returns
    ///
    /// * Result containing the masked witness or a synthesis error
    fn masked_witness(&self, wid: WireId) -> Result<FpVar<Bn254Fr>, SynthesisError> {
        match self.assigned_masked_witnesses.get(&wid) {
            Some(witness) => Ok(witness.clone()),
            None => Err(SynthesisError::Unsatisfiable),
        }
    }

    /// Process an addition gate in the circuit.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination wire ID
    /// * `left` - Left input wire ID
    /// * `right` - Right input wire ID
    ///
    /// # Returns
    ///
    /// * Result containing () or a synthesis error
    pub fn process_add(
        &mut self,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> Result<(), SynthesisError> {
        // Compute the correct masked witness for the output wire
        let left_witness = self.masked_witness(left)?;
        let right_witness = self.masked_witness(right)?;
        let output_witness = left_witness + right_witness;

        // Save the computed masked witness
        self.save_computed_masked_witness(dst, output_witness)

        // Linear gates don't contribute to the aggregate being computed
    }

    /// Process a multiplication gate in the circuit.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination wire ID
    /// * `left` - Left input wire ID
    /// * `right` - Right input wire ID
    ///
    /// # Returns
    ///
    /// * Result containing () or a synthesis error
    pub fn process_mul(
        &mut self,
        dst: WireId,
        left: WireId,
        right: WireId,
    ) -> Result<(), SynthesisError> {
        // Assign the next masked witness to the destination wire
        self.assign_masked_witness(dst)?;
        let challenge = self.next_challenge()?;

        // Compute the contribution to the aggregate: ci(Δ) = q_left * q_right - q_dst * Δ
        let left_witness = self.masked_witness(left)?;
        let right_witness = self.masked_witness(right)?;
        let dst_witness = self.masked_witness(dst)?;

        let eval = left_witness * right_witness - (dst_witness * self.verifier_key.clone());

        // Add to the aggregate
        self.aggregate = self.aggregate.clone() + (challenge * eval);

        Ok(())
    }

    /// Process a private input gate in the circuit.
    ///
    /// # Arguments
    ///
    /// * `dst_range` - Range of destination wire IDs
    ///
    /// # Returns
    ///
    /// * Result containing () or a synthesis error
    pub fn process_private_input(&mut self, dst_range: WireRange) -> Result<(), SynthesisError> {
        // For each of the output wires
        for wid in dst_range.start..=dst_range.end {
            // Assign a fresh masked witness to the wire
            self.assign_masked_witness(wid)?;

            // Private input gates don't define a polynomial that would contribute to the aggregate
            // being computed, so we ignore the challenge
        }

        Ok(())
    }

    /// Computes the validation aggregate by traversing the circuit structure.
    ///
    /// This simplified version just computes the dot product of witness challenges and masked witnesses,
    /// similar to the original implementation. For a full circuit traversal, use the process_* methods
    /// to handle different gate types.
    ///
    /// # Arguments
    ///
    /// * `cs` - Constraint system reference
    /// * `witness_challenge` - Array of witness challenges
    /// * `masked_witnesses` - Array of masked witnesses computed from witness commitments
    ///
    /// # Returns
    ///
    /// * Result containing the validation aggregate or a synthesis error
    pub fn compute_validation_aggregate(
        _cs: ConstraintSystemRef<Bn254Fr>,
        witness_challenge: &[FpVar<Bn254Fr>],
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

    /// Computes the validation aggregate by traversing a circuit with the given gates.
    ///
    /// # Arguments
    ///
    /// * `cs` - Constraint system reference
    /// * `challenges` - Array of witness challenges
    /// * `verifier_key` - Verifier key
    /// * `masked_witnesses` - Array of masked witnesses computed from witness commitments
    /// * `gates` - Array of gates in the circuit
    ///
    /// # Returns
    ///
    /// * Result containing the validation aggregate or a synthesis error
    pub fn compute_validation_aggregate_with_circuit(
        cs: ConstraintSystemRef<Bn254Fr>,
        challenges: Vec<FpVar<Bn254Fr>>,
        verifier_key: FpVar<Bn254Fr>,
        masked_witnesses: Vec<FpVar<Bn254Fr>>,
        gates: &[Gate],
    ) -> Result<FpVar<Bn254Fr>, SynthesisError> {
        let mut traverser = Self::new(cs, challenges, verifier_key, masked_witnesses)?;

        // Process each gate in the circuit
        for gate in gates {
            match gate {
                Gate::Add { dst, left, right } => {
                    traverser.process_add(*dst, *left, *right)?;
                }
                Gate::Mul { dst, left, right } => {
                    traverser.process_mul(*dst, *left, *right)?;
                }
                Gate::PrivateInput { dst_range } => {
                    traverser.process_private_input(dst_range.clone())?;
                } // Add other gate types as needed
            }
        }

        // Check that all challenges and masked witnesses were used
        if traverser.challenge_count != traverser.challenges.len() {
            return Err(SynthesisError::Unsatisfiable);
        }
        if traverser.assigned_witness_count != traverser.masked_witnesses.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(traverser.aggregate)
    }
}

/// Represents a gate in the circuit
#[derive(Clone)]
pub enum Gate {
    /// Addition gate: dst = left + right
    Add {
        dst: WireId,
        left: WireId,
        right: WireId,
    },
    /// Multiplication gate: dst = left * right
    Mul {
        dst: WireId,
        left: WireId,
        right: WireId,
    },
    /// Private input gate: assigns values to a range of wires
    PrivateInput { dst_range: WireRange },
    // Add other gate types as needed
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
        let _verifier_key = create_fp_var(cs.clone(), 5);

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
    /// Test circuit traversal with a simple circuit
    fn test_circuit_traversal() {
        let cs = create_cs();

        // Create test inputs
        let challenges = vec![
            create_fp_var(cs.clone(), 2), // For the multiplication gate
        ];

        let verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10), // For wire 0 (private input)
            create_fp_var(cs.clone(), 20), // For wire 1 (private input)
            create_fp_var(cs.clone(), 30), // For wire 3 (multiplication output)
        ];

        // Create a simple circuit:
        // Wire 0: private input = 10
        // Wire 1: private input = 20
        // Wire 2: add(0, 1) = 10 + 20 = 30
        // Wire 3: mul(0, 1) = 10 * 20 = 200, but masked witness is 30
        let gates = vec![
            Gate::PrivateInput {
                dst_range: WireRange { start: 0, end: 1 },
            },
            Gate::Add {
                dst: 2,
                left: 0,
                right: 1,
            },
            Gate::Mul {
                dst: 3,
                left: 0,
                right: 1,
            },
        ];

        // Compute validation aggregate
        let validation_aggregate =
            CircuitTraversalGadget::compute_validation_aggregate_with_circuit(
                cs.clone(),
                challenges,
                verifier_key.clone(),
                masked_witnesses,
                &gates,
            )
            .unwrap();

        // Expected calculation:
        // - Wire 0 gets masked_witness[0] = 10
        // - Wire 1 gets masked_witness[1] = 20
        // - Wire 2 gets 10 + 20 = 30 (computed)
        // - Wire 3 gets masked_witness[2] = 30
        // - For mul gate: challenge * (left * right - dst * verifier_key)
        //   = 2 * (10 * 20 - 30 * 5)
        //   = 2 * (200 - 150)
        //   = 2 * 50
        //   = 100
        let expected = Fr::from(100u64);

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

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
            create_fp_var(cs.clone(), 40),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 5),
            create_fp_var(cs.clone(), 5),
            create_fp_var(cs.clone(), 5),
            create_fp_var(cs.clone(), 5),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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

        let _verifier_key = create_fp_var(cs.clone(), 5);

        // Create masked witnesses with large values
        let masked_witness1 = FpVar::new_witness(cs.clone(), || Ok(large_value)).unwrap();
        let masked_witness2 = FpVar::new_witness(cs.clone(), || Ok(large_value)).unwrap();

        let masked_witnesses = vec![masked_witness1, masked_witness2];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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
        let masked_witnesses: Vec<FpVar<Fr>> = vec![];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30), // One more than challenges
        ];

        let result = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        let _ = CircuitTraversalGadget::compute_validation_aggregate(
            cs.clone(),
            &witness_challenges,
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

            // Record the constraint count before computation
            let constraints_before = cs.num_constraints();

            // Compute validation aggregate
            let _ = CircuitTraversalGadget::compute_validation_aggregate(
                cs.clone(),
                &witness_challenges,
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
