use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, Rng};
use eyre::Result;
use swanky_field_binary::{F128b, F64b, F8b};

use crate::{
    circuit::VoleVerificationCircuit,
    field_mappings::{f128b_to_ark, f64b_to_ark, f8b_to_ark},
};

pub struct VoleProof {
    pub degree_0_commitment: F128b,
    pub degree_1_commitment: F128b,
    pub witness_commitment: Vec<F64b>,
    pub partial_decommitment: PartialDecommitment,
}

pub struct PartialDecommitment {
    pub verifier_key: F128b,
    pub witness_voles: Vec<Vec<F8b>>,
}

impl PartialDecommitment {
    pub fn verifier_key(&self) -> F128b {
        self.verifier_key
    }

    pub fn witness_voles(&self) -> &[Vec<F8b>] {
        &self.witness_voles
    }
}

pub struct SnarkProof {
    pub proof: Groth16Proof<Bn254>,
    pub inputs: Vec<Bn254Fr>,
}

pub struct SnarkKeys {
    pub proving_key: ProvingKey<Bn254>,
    pub verification_key: VerifyingKey<Bn254>,
}

pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<SnarkKeys> {
    // Create a dummy circuit for setup
    let dummy_circuit = VoleVerificationCircuit {
        // Initialize with dummy values
        degree_1_commitment: Bn254Fr::from(0),
        degree_0_commitment: Bn254Fr::from(0),
        verifier_key: Bn254Fr::from(0),
        validation_aggregate: Bn254Fr::from(0),
        witness_commitment: Vec::new(),
        partial_decommitment: Vec::new(),
    };

    let (proving_key, verification_key) =
        Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;

    Ok(SnarkKeys {
        proving_key,
        verification_key,
    })
}

pub fn prove<R: Rng + CryptoRng>(
    vole_proof: &VoleProof,
    validation_aggregate: &F128b,
    keys: &SnarkKeys,
    rng: &mut R,
) -> Result<SnarkProof> {
    // Convert VOLE proof to circuit inputs
    let circuit = VoleVerificationCircuit {
        degree_0_commitment: f128b_to_ark(&vole_proof.degree_0_commitment),
        degree_1_commitment: f128b_to_ark(&vole_proof.degree_1_commitment),
        verifier_key: f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
        validation_aggregate: f128b_to_ark(validation_aggregate),
        // Private Inputs
        witness_commitment: vole_proof
            .witness_commitment
            .iter()
            .map(f64b_to_ark)
            .collect(),
        partial_decommitment: vole_proof
            .partial_decommitment
            .witness_voles()
            .iter()
            .flat_map(|arr| arr.iter().map(f8b_to_ark))
            .collect(),
    };

    let proof = Groth16::<Bn254>::prove(&keys.proving_key, circuit, rng)?;

    // todo: convert from proof.json?
    let inputs = vec![
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
        f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
        f128b_to_ark(validation_aggregate),
    ];

    Ok(SnarkProof { proof, inputs })
}

pub fn verify(snark_proof: &SnarkProof, keys: &SnarkKeys) -> Result<bool> {
    Ok(Groth16::<Bn254>::verify(
        &keys.verification_key,
        &snark_proof.inputs,
        &snark_proof.proof,
    )
    .is_ok())
}
