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
- [ ] Test edge cases and error handling

## Implementation Discrepancies with schmivitz

### Witness Challenges Handling

- [x] Fix witness challenges implementation in prover.rs
- [x] Currently, witness challenges are hardcoded as constant values (all set to 1)
- [x] Should be derived from the transcript as in the original schmivitz implementation
- [x] Update the prove function to properly derive witness challenges from transcript
- [ ] Ensure challenges are verified against expected values as in the original implementation

### Circuit Traversal Logic

- [x] Enhance CircuitTraversalGadget to properly traverse circuit structure
- [x] Current implementation is simplified to a dot product of witness challenges and masked witnesses
- [x] Should implement full circuit traversal similar to VerifierTraverser in the original implementation
- [x] Add support for processing actual circuit gates and constraints
- [x] Ensure the traversal logic matches the original implementation's behavior

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

## Field Conversion and Constraint System Handling

### Field Conversion Implementation

- [x] Implement proper field conversion between F128b and Bn254Fr
  - [x] Create a robust f128b_to_ark function that handles the full 128-bit value
  - [x] Implement ark_to_f128b function using GenericArray for proper type conversion
  - [x] Add unit tests for field conversion functions with various input values
  - [x] Document the mathematical relationship between the two field types

### Constraint System Value Extraction

- [ ] Implement proper value extraction from constraint system variables
  - [ ] Create a mechanism to extract values from FpVar after constraint satisfaction
  - [ ] Implement a solution for the FpVar::value() issue in circuit traversal
  - [ ] Add proper error handling for constraint system operations
  - [ ] Document the constraint system value extraction process

### Example Files Enhancement

- [x] Update example files to use actual field conversion and constraint system handling
  - [x] Replace simplified approaches with proper implementations
  - [x] Ensure examples demonstrate best practices for constraint system usage
  - [x] Add comments explaining the mathematical operations being performed
