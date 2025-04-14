use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::ops::{Add, Mul};

pub struct MaskedWitnessGadget;

impl MaskedWitnessGadget {
    pub fn compute(
        _cs: ConstraintSystemRef<Bn254Fr>,
        witness_commitment: &[FpVar<Bn254Fr>],
        verifier_key: &FpVar<Bn254Fr>,
        partial_decommitment: &[FpVar<Bn254Fr>],
    ) -> Result<Vec<FpVar<Bn254Fr>>, SynthesisError> {
        let mut masked_witnesses = Vec::new();
        for (i, witness) in witness_commitment.iter().enumerate() {
            let masked_witness = witness.mul(verifier_key).add(&partial_decommitment[i]);
            masked_witnesses.push(masked_witness);
        }
        Ok(masked_witnesses)
    }
}
