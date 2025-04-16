use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, Rng};
use arkworks_solidity_verifier::SolidityVerifier;
use eyre::{Ok, Result};
use merlin::Transcript;
use schmivitz::{
    insecure::InsecureVole,
    {Proof, RandomVole},
};
use std::{fs, path::Path};
use swanky_field_binary::{F128b, F64b, F8b};
use swanky_serialization::CanonicalSerialize;

use crate::{
    circuit::VoleVerificationCircuit,
    field_mappings::{f128b_to_ark, f64b_to_ark, f8b_to_ark},
    transcript::{self, TranscriptWrapper},
};

pub struct VoleProof {
    pub vole_challenge: F128b,
    pub witness_commitment: Vec<F64b>,
    pub witness_challenges: Vec<F128b>,
    pub degree_0_commitment: F128b,
    pub degree_1_commitment: F128b,
    pub deccomitment_challenge: F128b,
    pub partial_decommitment: PartialDecommitment,
}

pub struct PartialDecommitment {
    pub verifier_key: F128b,
    pub witness_voles: Vec<Vec<F8b>>,
    pub mask_voles: [F128b; 128],
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

// todo: implement the conversion from the Schmivitz proof to the VoleProof
pub fn convert_proof(schmivitz_proof: &Proof<InsecureVole>) -> Result<VoleProof> {
    let vole_proof = VoleProof {
        vole_challenge: convert_challenge(schmivitz_proof.vole_challenge)?,
        witness_commitment: schmivitz_proof.witness_commitment.clone(),
        witness_challenges: schmivitz_proof.witness_challenges.clone(),
        degree_0_commitment: schmivitz_proof.degree_0_commitment,
        degree_1_commitment: schmivitz_proof.degree_1_commitment,
        deccomitment_challenge: convert_challenge(schmivitz_proof.decommitment_challenge)?,
        partial_decommitment: convert_decommitment(&schmivitz_proof.partial_decommitment)?,
    };
    Ok(vole_proof)
}

fn convert_decommitment(
    decommitment: &<InsecureVole as RandomVole>::Decommitment,
) -> Result<PartialDecommitment> {
    let partial_decommitment = PartialDecommitment {
        verifier_key: decommitment.verifier_key(),
        witness_voles: decommitment
            .witness_voles()
            .iter()
            .map(|vole| vole.to_vec())
            .collect(),
        mask_voles: decommitment.mask_voles(),
    };
    Ok(partial_decommitment)
}

fn convert_challenge(challenge: [u8; 16]) -> Result<F128b> {
    let converted_challenge = F128b::from_bytes((&challenge).into());
    Ok(converted_challenge?)
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
        witness_challenges: Vec::new(), // Empty vector for setup
    };

    let (proving_key, verification_key) =
        Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;

    // Generate and output Solidity verifier at setup time
    let output_dir = Path::new("solidity_output");
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    // Generate the Solidity verifier using the SolidityVerifier trait
    let solidity_verifier = Groth16::<Bn254>::export(&verification_key);
    // todo: deploy contract

    // Write the Solidity verifier to a file
    let output_path = output_dir.join("vole_verifier.sol");
    fs::write(&output_path, solidity_verifier)?;
    println!("Solidity verifier generated at: {}", output_path.display());

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
    let mut transcript = Transcript::new(b"schmivitz-snark");
    let mut transcript_wrapper = TranscriptWrapper::from(&mut transcript);

    transcript_wrapper.append_public_values();

    let witness_commitment_ark: Vec<Bn254Fr> = vole_proof
        .witness_commitment
        .iter()
        .map(f64b_to_ark)
        .collect();
    transcript_wrapper.append_witness_commitment(&witness_commitment_ark);

    let witness_challenge =
        transcript_wrapper.extract_witness_challenges(vole_proof.witness_commitment.len());

    transcript_wrapper.append_polynomial_commitments(
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
    );

    // Convert VOLE proof to circuit inputs
    let circuit = VoleVerificationCircuit {
        // Public Inputs
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
        // Generate witness challenges based on the validation aggregate
        // In a real implementation, these would be derived from a transcript
        witness_challenges: witness_challenge,
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

pub fn verify(snark_proof: &SnarkProof, keys: &SnarkKeys, vole_proof: &VoleProof) -> Result<bool> {
    let mut transcript = Transcript::new(b"schmivitz-snark");
    let mut transcript_wrapper = TranscriptWrapper::from(&mut transcript);

    transcript_wrapper.append_public_values();

    let witness_commitment_ark: Vec<Bn254Fr> = vole_proof
        .witness_commitment
        .iter()
        .map(f64b_to_ark)
        .collect();
    transcript_wrapper.append_witness_commitment(&witness_commitment_ark);

    let expected_witness_challenges =
        transcript_wrapper.extract_witness_challenges(vole_proof.witness_commitment.len());
    if expected_witness_challenges
        != vole_proof
            .witness_challenges
            .iter()
            .map(f128b_to_ark)
            .collect::<Vec<_>>()
    {
        return Ok(false);
    }

    Ok(Groth16::<Bn254>::verify(
        &keys.verification_key,
        &snark_proof.inputs,
        &snark_proof.proof,
    )
    .is_ok())
}
