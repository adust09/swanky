mod constraints;
mod field_mappings;
mod gadgets;
mod prover;
#[cfg(test)]
mod tests;
mod transcript;

pub use prover::{
    convert_proof, prove, setup, verify, PartialDecommitment, SnarkKeys, SnarkProof, VoleProof,
};

// Re-export gadgets for use in other crates
pub use gadgets::{
    CircuitTraversalGadget, ConstraintVerificationGadget, Gate, MaskedWitnessGadget, WireId,
    WireRange,
};

// Re-export field conversion functions
pub use field_mappings::{ark_to_f128b, f128b_to_ark, f64b_to_ark, f8b_to_ark};
