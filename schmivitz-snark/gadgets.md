# Schmivitz-SNARK Gadgets Documentation

This document describes the purpose, specifications, and design of the three core gadgets used in the schmivitz-snark implementation of the VOLE-in-the-head proof system.

## Overview

The schmivitz-snark crate implements a SNARK for the VOLE-in-the-head proof system described in the schmivitz crate. The implementation uses three primary gadgets that work together to create and verify zero-knowledge proofs:

1. **MaskedWitnessGadget**: Computes masked witnesses from witness commitments
2. **CircuitTraversalGadget**: Traverses the circuit to compute validation aggregates
3. **ConstraintVerificationGadget**: Verifies the final constraint equation

These gadgets are implemented using the arkworks R1CS (Rank-1 Constraint System) framework, which allows for efficient zero-knowledge proof generation and verification.

## MaskedWitnessGadget

### Purpose

The MaskedWitnessGadget is responsible for computing masked witnesses from witness commitments, verifier keys, and partial decommitments. This is a crucial step in the VOLE-in-the-head protocol, as it allows the prover to reveal information about the witness without exposing the actual witness values.

### Specification

```rust
pub fn compute<CS: ConstraintSystemRef>(
    cs: CS,
    witness_commitment: &[FpVar<Bn254Fr>],
    verifier_key: &FpVar<Bn254Fr>,
    partial_decommitment: &[FpVar<Bn254Fr>],
) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError>
```

#### Inputs:
- `cs`: The constraint system reference
- `witness_commitment`: Array of witness commitments (d in the paper)
- `verifier_key`: The verifier's key (Delta in the paper)
- `partial_decommitment`: Array of partial decommitments (Q in the paper)

#### Output:
- Vector of masked witnesses (Q' in the paper)

#### Algorithm:
For each witness commitment and corresponding partial decommitment:
1. Multiply the witness commitment by the verifier key: `witness_com * verifier_key`
2. Add the result to the partial decommitment: `(witness_com * verifier_key) + partial_decommitment`
3. Return the resulting vector of masked witnesses

### Mathematical Background

In the VOLE-in-the-head protocol, the masked witness computation corresponds to the equation:
```
Q'[i] = d[i] * Delta + Q[i]
```

Where:
- Q'[i] is the masked witness
- d[i] is the witness commitment
- Delta is the verifier key
- Q[i] is the partial decommitment

This operation allows the verifier to check the consistency of the proof without learning the actual witness values.

## CircuitTraversalGadget

### Purpose

The CircuitTraversalGadget is responsible for traversing the circuit structure and computing a validation aggregate. This aggregate represents the evaluation of all constraints in the circuit using the masked witnesses and witness challenges.

### Specification

```rust
pub fn compute_validation_aggregate<CS: ConstraintSystemRef>(
    cs: CS,
    witness_challenge: &[FpVar<Bn254Fr>],
    verifier_key: &FpVar<Bn254Fr>,
    masked_witnesses: &[FpVar<Bn254Fr>],
) -> Result<FpVar<Bn254Fr>, SynthesisError>
```

#### Inputs:
- `cs`: The constraint system reference
- `witness_challenge`: Array of challenges for each polynomial (r in the paper)
- `verifier_key`: The verifier's key (Delta in the paper)
- `masked_witnesses`: Array of masked witnesses (Q' in the paper)

#### Output:
- Validation aggregate (c~ in the paper)

#### Algorithm:
1. Initialize an accumulator for the validation aggregate
2. For each gate in the circuit:
   a. Compute the gate's contribution based on the masked witnesses
   b. Weight the contribution by the corresponding witness challenge
   c. Add the weighted contribution to the accumulator
3. Return the final validation aggregate

### Mathematical Background

The circuit traversal computes the validation aggregate according to:
```
validation_aggregate = Σ(r[i] * gate_evaluation(Q'[...]))
```

Where:
- r[i] are the witness challenges
- gate_evaluation is the evaluation of each gate using the masked witnesses

This aggregate is later used in the final constraint verification.

## ConstraintVerificationGadget

### Purpose

The ConstraintVerificationGadget is responsible for verifying the final constraint equation of the VOLE-in-the-head proof. It checks that the validation aggregate is consistent with the degree-0 and degree-1 commitments.

### Specification

```rust
pub fn verify<CS: ConstraintSystemRef>(
    cs: CS,
    validation: &FpVar<Bn254Fr>,
    degree_1_commitment: &FpVar<Bn254Fr>,
    verifier_key: &FpVar<Bn254Fr>,
    degree_0_commitment: &FpVar<Bn254Fr>,
) -> Result<Boolean<Bn254Fr>, SynthesisError>
```

#### Inputs:
- `cs`: The constraint system reference
- `validation`: The validation aggregate (c~ in the paper)
- `degree_1_commitment`: The degree-1 term commitment (a~ in the paper)
- `verifier_key`: The verifier's key (Delta in the paper)
- `degree_0_commitment`: The degree-0 term commitment (b~ in the paper)

#### Output:
- Boolean indicating whether the constraint is satisfied

#### Algorithm:
1. Compute the expected validation: `degree_1_commitment * verifier_key + degree_0_commitment`
2. Compare the computed validation with the provided validation
3. Return a boolean indicating whether they are equal

### Mathematical Background

The final constraint verification checks the equation:
```
validation == degree_1_commitment * verifier_key + degree_0_commitment
```

This equation verifies that the prover's commitments are consistent with the circuit evaluation, without revealing the actual witness values.

## Integration in the SNARK Circuit

These three gadgets are integrated in the `VoleVerificationCircuit` to create a complete SNARK for the VOLE-in-the-head proof system:

1. The circuit takes as input:
   - Public inputs: degree_0_commitment, degree_1_commitment, verifier_key, validation_aggregate
   - Private inputs: witness_commitment, partial_decommitment

2. The circuit execution flow:
   a. Compute masked witnesses using MaskedWitnessGadget
   b. Verify the final constraint using ConstraintVerificationGadget
   c. Enforce that the verification passes

The CircuitTraversalGadget is used by the verifier to compute the validation aggregate, which is then provided as a public input to the circuit.

## Security Considerations

The security of these gadgets relies on:

1. The security of the underlying VOLE-in-the-head protocol
2. The correct implementation of the R1CS constraints
3. The security of the BN254 elliptic curve

The gadgets must be implemented carefully to ensure that no information about the witness is leaked beyond what is intended by the protocol.

## Performance Considerations

The efficiency of these gadgets directly impacts the performance of the SNARK:

1. The number of constraints generated by each gadget affects proof generation time
2. The complexity of the circuit traversal affects verification time
3. Optimizations in the masked witness computation can significantly improve overall performance

Careful implementation and optimization of these gadgets is essential for creating an efficient SNARK for the VOLE-in-the-head proof system.

## Correspondence with schmivitz/src/proof.rs

Each gadget in schmivitz-snark corresponds to specific sections in the original implementation in schmivitz/src/proof.rs. Below are the specific correspondences:

### MaskedWitnessGadget

The MaskedWitnessGadget corresponds to the masked witness computation in the `verify` method of `Proof<InsecureVole>` in proof.rs, specifically lines 235-268:

```rust
// Compute masked witnesses Q' = Q[..l] + d * Delta
let d_delta = self
    .witness_commitment
    .iter()
    .map(|witness_com| {
        // Convert F64b to F8b for compatibility with the verifier key
        // First convert F64b to array of F2 values
        let witness_com_bits = F2::decompose_superfield(witness_com);
        // Then take first 8 bits to create F8b
        // Create a GenericArray directly from the first 8 bits
        // Create F8b from the first bit of F64b
        // For simplicity, we'll just use the first bit to determine if it's 0 or 1
        let witness_com_f8b = if witness_com_bits[0] == F2::ONE {
            F8b::ONE
        } else {
            F8b::ZERO
        };

        self.partial_decommitment
            .verifier_key_array()
            .map(|key| witness_com_f8b * key)
    })
    .collect::<Vec<_>>();
let masked_witnesses = zip(self.partial_decommitment.witness_voles(), d_delta)
    .map(|(qs, dds)| {
        // NB: This unwrap is safe because we know the two input arrays are each exactly length 16.
        let masked_witness: [F8b; 16] = zip(qs, dds)
            .map(|(q, dd)| q + dd)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        F8b::form_superfield(&masked_witness.into())
    })
    .collect::<Vec<_>>();
```

This code computes the masked witnesses by combining the witness commitments with the verifier key and partial decommitments, which is exactly what the MaskedWitnessGadget needs to implement in the R1CS framework.

### CircuitTraversalGadget

The CircuitTraversalGadget corresponds to the circuit traversal in the `verify` method of `Proof<InsecureVole>` in proof.rs, specifically lines 273-281:

```rust
// Run circuit traversal and get the aggregate value (part of c~)
let mut verifier_traverser = VerifierTraverser::new(
    self.witness_challenges.clone(),
    self.partial_decommitment.verifier_key(),
    masked_witnesses,
)?;
let reader = RelationReader::new(circuit)?;
reader.read(&mut verifier_traverser)?;
let validation_aggregate = verifier_traverser.into_parts()?;
```

This code traverses the circuit using the VerifierTraverser, which computes the validation aggregate based on the witness challenges, verifier key, and masked witnesses. The CircuitTraversalGadget needs to implement this traversal logic in the R1CS framework.

### ConstraintVerificationGadget

The ConstraintVerificationGadget corresponds to the final constraint verification in the `verify` method of `Proof<InsecureVole>` in proof.rs, specifically lines 284-292:

```rust
// Finally, compute c~ = aggregate + q*
let validation = validation_aggregate + validation_mask;

// Check the main constraint of the proof!!
let actual_validation = self.degree_1_commitment * self.partial_decommitment.verifier_key()
    + self.degree_0_commitment;
if validation != actual_validation {
    bail!("Verification failed: proof responses were not consistent with decommited VOLEs and masked witnesses");
}
Ok(())
```

This code verifies the final constraint equation by checking that the validation aggregate (plus the validation mask) equals the expected value computed from the degree-1 commitment, verifier key, and degree-0 commitment. The ConstraintVerificationGadget needs to implement this verification logic in the R1CS framework.
