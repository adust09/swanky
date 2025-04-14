use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

pub struct CircuitTraversalGadget;

impl CircuitTraversalGadget {}
pub fn compute_validation_aggregate(
    cs: ConstraintSystemRef<Bn254Fr>,
    witness_challenge: &[FpVar<Bn254Fr>],
    verifier_key: &FpVar<Bn254Fr>,
    masked_witnesses: &[FpVar<Bn254Fr>],
) -> Result<FpVar<Bn254Fr>, SynthesisError> {
    todo!()
}
