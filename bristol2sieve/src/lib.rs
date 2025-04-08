//! Bristol Fashion to SIEVE IR Transpiler Library
//!
//! This library provides functionality to convert circuit descriptions from Bristol Fashion format
//! to SIEVE IR format, enabling the use of Bristol Fashion circuits with zero-knowledge proof systems.

// Re-export the transpiler module
pub mod transpiler;

// Re-export the main transpile function for convenience
pub use transpiler::transpile;
