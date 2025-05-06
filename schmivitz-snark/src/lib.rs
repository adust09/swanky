pub mod constraints;
mod field_mappings;
mod gadgets;
mod prover;
pub mod serializable;
#[cfg(test)]
mod tests;

pub use prover::{SnarkKeys, SnarkProof};

// Re-export gadgets for use in other crates
pub use gadgets::{CircuitTraverser, MaskedWitnessVar, TranscriptWrapper, WireId, WireRange};

pub use constraints::{PartialDecommitmentBoolean, VoleVerificationBoolean};

// Re-export field conversion functions
pub use field_mappings::{
    ark_to_f128b,
    boolean_array_to_f128b,
    boolean_array_to_f64b,
    boolean_array_to_f8b,
    f128b_to_ark,
    f128b_to_boolean_array,
    f64b_to_ark,
    f64b_to_boolean_array,
    f8b_to_ark,
    // Boolean array conversion functions
    f8b_to_boolean_array,
};
pub use serializable::save_variables_to_json;
