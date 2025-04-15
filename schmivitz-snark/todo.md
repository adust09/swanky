# schmivitz-snark Gadget Implementation Todo List

## MaskedWitnessGadget Implementation

- [x] Implement the compute method in MaskedWitnessGadget
- [x] Handle multiplication of witness commitment with verifier key
- [x] Handle addition with partial decommitment
- [ ] Optimize constraint generation for masked witness computation
- [ ] Add proper error handling for SynthesisError cases
- [ ] Document the implementation with comments explaining the math

### Unit Tests for MaskedWitnessGadget

- [x] Test basic computation with simple inputs
- [x] Test with edge cases (zero values, maximum field values)
- [x] Test error handling for invalid inputs
- [x] Test constraint satisfaction with various input combinations
- [x] Benchmark constraint count for different input sizes

## CircuitTraversalGadget Implementation

- [x] Define the CircuitTraversalGadget structure with necessary fields
- [x] Implement compute_validation_aggregate function
- [x] Handle witness challenges in the circuit traversal
- [ ] Implement logic for traversing the circuit structure
- [ ] Optimize constraint generation for circuit traversal
- [x] Document the implementation with comments explaining the traversal algorithm

### Unit Tests for CircuitTraversalGadget

- [x] Test validation aggregate computation with simple circuit structures
- [x] Test with different witness challenge patterns
- [x] Test with edge cases (zero challenges, maximum field values)
- [x] Test error handling for invalid inputs
- [x] Test constraint satisfaction for different circuit structures
- [x] Benchmark constraint count for circuits of varying complexity

## ConstraintVerificationGadget Implementation

- [x] Implement the verify method in ConstraintVerificationGadget
- [x] Implement the final constraint verification logic (degree_1_commitment * verifier_key + degree_0_commitment)
- [x] Return Boolean result for constraint satisfaction
- [ ] Optimize constraint generation for verification
- [x] Document the implementation with comments explaining the verification equation

### Unit Tests for ConstraintVerificationGadget

- [x] Test verification with valid inputs that should pass
- [x] Test verification with invalid inputs that should fail
- [x] Test with edge cases (zero values, maximum field values)
- [x] Test constraint generation and satisfaction
- [x] Test error handling for invalid inputs
- [x] Benchmark constraint count for the verification operation

## Integration and Testing

- [x] Create unit tests for MaskedWitnessGadget
- [x] Create unit tests for CircuitTraversalGadget
- [x] Create unit tests for ConstraintVerificationGadget
- [ ] Create integration tests for the complete circuit
- [x] Test with small example circuits
- [ ] Test with larger, more complex circuits
- [ ] Test edge cases and error handling

## Optimization and Refinement

- [ ] Profile constraint count for each gadget
- [ ] Identify bottlenecks in constraint generation
- [ ] Optimize gadget implementations to reduce constraint count
- [ ] Refactor code for better readability and maintainability
- [ ] Ensure consistent error handling across all gadgets
- [ ] Review and improve documentation

## Additional Features

- [x] Implement support for different field types
- [ ] Add support for custom gates if needed
- [ ] Implement any additional gadgets identified during development
- [ ] Create helper functions for common operations
- [ ] Add debugging utilities for gadget development

## Documentation and Examples

- [ ] Write comprehensive documentation for each gadget
- [ ] Create example usage patterns for each gadget
- [ ] Document the mathematical background for the gadgets
- [ ] Create a guide for extending the gadget system
- [ ] Document performance characteristics and constraints

## Implementation Discrepancies with schmivitz

### Witness Challenges Handling

- [ ] Fix witness challenges implementation in prover.rs
- [ ] Currently, witness challenges are hardcoded as constant values (all set to 1)
- [ ] Should be derived from the transcript as in the original schmivitz implementation
- [ ] Update the prove function to properly derive witness challenges from transcript
- [ ] Ensure challenges are verified against expected values as in the original implementation

### Circuit Traversal Logic

- [ ] Enhance CircuitTraversalGadget to properly traverse circuit structure
- [ ] Current implementation is simplified to a dot product of witness challenges and masked witnesses
- [ ] Should implement full circuit traversal similar to VerifierTraverser in the original implementation
- [ ] Add support for processing actual circuit gates and constraints
- [ ] Ensure the traversal logic matches the original implementation's behavior

### Partial Decommitment Structure

- [ ] Enhance PartialDecommitment structure to match the original implementation
- [ ] Current implementation is simplified to just contain verifier key and witness voles
- [ ] Should include all necessary information as in the original implementation
- [ ] Update related functions to work with the enhanced structure
- [ ] Ensure compatibility with the verification process

### Proof Structure Alignment and Conversion Interface

- [x] Enhance VoleProof structure to more closely match schmivitz's Proof structure
- [x] Add witness_challenges field to VoleProof
- [x] Add vole_challenge field to VoleProof
- [x] Add decommitment_challenge field to VoleProof
- [x] Update PartialDecommitment structure to match schmivitz's Decommitment structure
- [x] After structure alignment, implement a direct function to convert schmivitz's Proof<InsecureVole> to schmivitz-snark's VoleProof
- [x] Extract all necessary components from schmivitz Proof with minimal transformation
- [ ] Implement validation_aggregate computation function based on schmivitz's verification logic
- [ ] Ensure validation_aggregate is computed in the prove function and not stored in VoleProof
- [ ] Implement the four steps of validation_aggregate computation:
  - [ ] Compute masked witnesses
  - [ ] Combine mask VOLEs to get validation mask
  - [ ] Run circuit traversal to get validation aggregate
  - [ ] Compute final validation value (aggregate + mask)
- [ ] Add error handling for invalid or incompatible Proof structures
- [ ] Document the enhanced VoleProof structure and conversion process
- [ ] Create unit tests for the conversion function with various Proof inputs
- [ ] Ensure the enhanced VoleProof structure is compatible with the existing prove function
- [ ] Update the prove function if necessary to work with the enhanced VoleProof structure
