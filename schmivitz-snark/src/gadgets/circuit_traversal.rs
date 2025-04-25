use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;
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
        challenges: Vec<FpVar<Bn254Fr>>,
        verifier_key: FpVar<Bn254Fr>,
        masked_witnesses: Vec<FpVar<Bn254Fr>>,
    ) -> Result<Self, SynthesisError> {
        if challenges.len() > masked_witnesses.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(Self {
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
    #[tracing::instrument(target = "r1cs", skip(witness_challenge, masked_witnesses))]
    pub fn compute_validation_aggregate(
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    fn create_fp_var(cs: ConstraintSystemRef<Fr>, value: u64) -> FpVar<Fr> {
        FpVar::new_witness(cs.clone(), || Ok(Fr::from(value))).unwrap()
    }

    #[test]
    fn test_simple_validation_aggregate() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let witness_challenges = vec![
            create_fp_var(cs.clone(), 1),
            create_fp_var(cs.clone(), 2),
            create_fp_var(cs.clone(), 3),
        ];

        let _verifier_key = create_fp_var(cs.clone(), 5);

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30),
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
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
    fn test_circuit_traversal() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let witness_challenges = vec![
            // test_constraint_satisfactionとの違いはベクトルの数
            create_fp_var(cs.clone(), 2), // For the multiplication gate
        ];

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10), // For wire 0 (private input)
            create_fp_var(cs.clone(), 20), // For wire 1 (private input)
            create_fp_var(cs.clone(), 30), // For wire 3 (multiplication output)
        ];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            &witness_challenges,
            &masked_witnesses,
        )
        .unwrap();

        let expected = Fr::from(100u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_alternating_challenge_patterns() {
        let cs = ConstraintSystem::<Fr>::new_ref();

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
            &witness_challenges,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 1*10 + 0*20 + 1*30 + 0*40 = 10 + 0 + 30 + 0 = 40
        let expected = Fr::from(40u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_increasing_challenge_patterns() {
        let cs = ConstraintSystem::<Fr>::new_ref();

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
    fn test_all_zero_cases() {
        let cs = ConstraintSystem::<Fr>::new_ref();

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
            &witness_challenges,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 0*10 + 0*20 + 0*30 = 0
        let expected = Fr::from(0u64);

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn test_large_value_cases() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        // Use large values close to the field size
        let large_value = Fr::from(u64::MAX); // Maximum u64 value

        let witness_challenges = vec![create_fp_var(cs.clone(), 1), create_fp_var(cs.clone(), 1)];

        let _verifier_key = create_fp_var(cs.clone(), 5);

        // Create masked witnesses with large values
        let masked_witness1 = FpVar::new_witness(cs.clone(), || Ok(large_value)).unwrap();
        let masked_witness2 = FpVar::new_witness(cs.clone(), || Ok(large_value)).unwrap();

        let masked_witnesses = vec![masked_witness1, masked_witness2];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
            &witness_challenges,
            &masked_witnesses,
        )
        .unwrap();

        // Expected result: 1*large_value + 1*large_value = 2*large_value
        let expected = large_value + large_value;

        assert_eq!(validation_aggregate.value().unwrap(), expected);
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_empty_input_cases() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let witness_challenges: Vec<FpVar<Fr>> = vec![];
        let masked_witnesses: Vec<FpVar<Fr>> = vec![];

        let validation_aggregate = CircuitTraversalGadget::compute_validation_aggregate(
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
    fn test_error_handling() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let witness_challenges = vec![create_fp_var(cs.clone(), 1), create_fp_var(cs.clone(), 2)];

        let masked_witnesses = vec![
            create_fp_var(cs.clone(), 10),
            create_fp_var(cs.clone(), 20),
            create_fp_var(cs.clone(), 30), // One more than challenges
        ];

        let result = CircuitTraversalGadget::compute_validation_aggregate(
            &witness_challenges,
            &masked_witnesses,
        );

        assert!(result.is_err());

        match result {
            Err(SynthesisError::Unsatisfiable) => {}
            _ => panic!("Expected SynthesisError::Unsatisfiable"),
        }
    }

    #[test]
    fn test_constraint_satisfaction() {
        let cs = ConstraintSystem::<Fr>::new_ref();

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
            &witness_challenges,
            &masked_witnesses,
        )
        .unwrap();

        assert!(cs.is_satisfied().unwrap());
    }
}
