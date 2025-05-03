pub mod constraints;
mod constraints_revise;
pub mod constraints_revised;
mod field_mappings;
mod gadgets;
mod prover;
pub mod serializable;
#[cfg(test)]
mod tests;
pub mod vole_verification_revised;

pub use prover::{SnarkKeys, SnarkProof};

// Re-export gadgets for use in other crates
pub use gadgets::{CircuitTraverser, MaskedWitnessVar, TranscriptWrapper, WireId, WireRange};

pub use constraints::{SchmivitzValues, VoleVerification};
pub use constraints_revised::VoleVerificationRevised as VoleVerificationRevised2;
pub use vole_verification_revised::{PartialDecommitmentVar, VoleVerificationRevised};

// Re-export field conversion functions
pub use field_mappings::{ark_to_f128b, f128b_to_ark, f64b_to_ark, f8b_to_ark};
pub use serializable::{save_variables_to_json, serialize_bn254fr_revised};
