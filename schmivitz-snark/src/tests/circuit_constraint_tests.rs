// #[cfg(test)]
// mod tests {
//     use crate::constraints::VoleVerification;
//     use ark_bn254::Fr as Bn254Fr;
//     use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
//     /// Helper function to create a test circuit with default values
//     fn create_test_circuit() -> VoleVerification {
//         VoleVerification {
//             // Public inputs
//             degree_0_commitment: Bn254Fr::from(1u64),
//             degree_1_commitment: Bn254Fr::from(2u64),
//             verifier_key: Bn254Fr::from(3u64),

//             // Private inputs (witness)
//             witness_commitment: vec![Bn254Fr::from(4u64), Bn254Fr::from(5u64)],
//             partial_decommitment: vec![Bn254Fr::from(6u64), Bn254Fr::from(7u64)],
//             witness_challenges: vec![Bn254Fr::from(8u64), Bn254Fr::from(9u64)],
//         }
//     }

//     /// Helper function to create a new constraint system
//     fn create_cs() -> ConstraintSystemRef<Bn254Fr> {
//         let cs = ConstraintSystem::<Bn254Fr>::new_ref();
//         cs.set_optimization_goal(ark_relations::r1cs::OptimizationGoal::Constraints);
//         cs
//     }

//     #[test]
//     fn test_constraint_generation_empty_circuit() {
//         let circuit = create_test_circuit();

//         let cs = create_cs();
//         let result = circuit.generate_constraints(cs.clone());

//         assert!(result.is_ok(), "Constraint generation should succeed");

//         let num_constraints = cs.num_constraints();
//         println!(
//             "Number of constraints for empty circuit: {}",
//             num_constraints
//         );
//         assert!(
//             num_constraints > 0,
//             "Expected constraints to be generated for empty circuit, but got {}",
//             num_constraints
//         );

//         assert!(
//             cs.is_satisfied().unwrap(),
//             "Constraints should be satisfied"
//         );
//     }
// }
