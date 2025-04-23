use crate::circuit::VoleVerificationCircuit;
use crate::gadgets::{Gate, WireRange};
use ark_bn254::Fr as Bn254Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
use ark_std::test_rng;

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
#[ignore]
fn test_constraint_generation_add_gate() {
    let mut circuit = create_test_circuit();

    // Add a single Add gate
    circuit.circuit_gates = vec![Gate::Add {
        dst: 2,
        left: 0,
        right: 1,
    }];

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated
    let num_constraints = cs.num_constraints();
    println!("Number of constraints for Add gate: {}", num_constraints);
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for Add gate, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}

#[test]
#[ignore]
fn test_constraint_generation_mul_gate() {
    let mut circuit = create_test_circuit();

    // Add a single Mul gate
    circuit.circuit_gates = vec![Gate::Mul {
        dst: 2,
        left: 0,
        right: 1,
    }];

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated
    let num_constraints = cs.num_constraints();
    println!("Number of constraints for Mul gate: {}", num_constraints);
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for Mul gate, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}

#[test]
#[ignore]
fn test_constraint_generation_private_input_gate() {
    let mut circuit = create_test_circuit();

    // Add a single PrivateInput gate
    circuit.circuit_gates = vec![Gate::PrivateInput {
        dst_range: WireRange { start: 2, end: 3 },
    }];

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated
    let num_constraints = cs.num_constraints();
    println!(
        "Number of constraints for PrivateInput gate: {}",
        num_constraints
    );
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for PrivateInput gate, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}

#[test]
#[ignore]
fn test_constraint_generation_multiple_gates() {
    let mut circuit = create_test_circuit();

    // Add multiple gates
    circuit.circuit_gates = vec![
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

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated
    let num_constraints = cs.num_constraints();
    println!(
        "Number of constraints for multiple gates: {}",
        num_constraints
    );
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for multiple gates, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}

#[test]
fn test_constraint_generation_empty_circuit() {
    let circuit = create_test_circuit();

    // Circuit has no gates
    assert!(circuit.circuit_gates.is_empty());

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated (even for empty circuit)
    let num_constraints = cs.num_constraints();
    println!(
        "Number of constraints for empty circuit: {}",
        num_constraints
    );
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for empty circuit, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}

#[test]
#[ignore]
fn test_constraint_generation_single_gate_circuit() {
    let mut circuit = create_test_circuit();

    // Add a single gate
    circuit.circuit_gates = vec![Gate::Add {
        dst: 2,
        left: 0,
        right: 1,
    }];

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated
    let num_constraints = cs.num_constraints();
    println!(
        "Number of constraints for single gate circuit: {}",
        num_constraints
    );
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for single gate circuit, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}

#[test]
#[ignore]
fn test_constraint_violation_detection() {
    let mut circuit = create_test_circuit();

    // Add a Mul gate
    circuit.circuit_gates = vec![Gate::Mul {
        dst: 2,
        left: 0,
        right: 1,
    }];

    // Create a constraint system
    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());
    assert!(result.is_ok(), "Constraint generation should succeed");

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );

    // Create a new circuit with invalid inputs
    let mut invalid_circuit = create_test_circuit();

    // Add the same Mul gate
    invalid_circuit.circuit_gates = vec![Gate::Mul {
        dst: 2,
        left: 0,
        right: 1,
    }];

    // Modify the witness to make it invalid
    // In a real scenario, we would need to ensure the witness values don't satisfy the circuit constraints
    // For example, if q_dst should equal q_left * q_right / Δ, we make it different
    invalid_circuit.witness_commitment = vec![Bn254Fr::from(100u64), Bn254Fr::from(200u64)];

    // Create a new constraint system
    let cs_invalid = create_cs();

    // Generate constraints
    let result_invalid = invalid_circuit.generate_constraints(cs_invalid.clone());
    assert!(
        result_invalid.is_ok(),
        "Constraint generation should succeed even with invalid inputs"
    );

    // Note: In a real test, we would check that the constraints are not satisfied
    // However, this requires careful setup of the invalid witness values
    // This is just a placeholder to demonstrate the concept
    println!("Note: In a real test, we would check that the constraints are not satisfied with invalid inputs");
}

#[test]
#[ignore]
fn test_constraint_generation_random_inputs() {
    let _rng = test_rng();

    // Create a circuit with random gates
    let mut circuit = create_test_circuit();

    // Add random gates
    circuit.circuit_gates = vec![
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

    let cs = create_cs();

    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());

    // Check that constraint generation succeeds
    assert!(result.is_ok(), "Constraint generation should succeed");

    // Check that constraints were generated
    let num_constraints = cs.num_constraints();
    println!(
        "Number of constraints for random inputs: {}",
        num_constraints
    );
    assert!(
        num_constraints > 0,
        "Expected constraints to be generated for random inputs, but got {}",
        num_constraints
    );

    assert!(
        cs.is_satisfied().unwrap(),
        "Constraints should be satisfied"
    );
}
