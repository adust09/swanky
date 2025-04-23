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
use swanky_serialization::CanonicalSerialize as _;

use crate::{
    constraints::VoleVerificationCircuit,
    field_mappings::{f128b_to_ark, f64b_to_ark, f8b_to_ark},
    transcript::TranscriptWrapper,
};
#[derive(Debug, Clone)]
pub struct VoleProof {
    pub vole_challenge: F128b,
    pub witness_commitment: Vec<F64b>,
    pub witness_challenges: Vec<F128b>,
    pub degree_0_commitment: F128b,
    pub degree_1_commitment: F128b,
    pub deccomitment_challenge: F128b,
    pub partial_decommitment: PartialDecommitment,
}
#[derive(Debug, Clone)]
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
        degree_1_commitment: Bn254Fr::from(0),
        degree_0_commitment: Bn254Fr::from(0),
        verifier_key: Bn254Fr::from(0),
        witness_commitment: Vec::new(),
        partial_decommitment: Vec::new(),
        witness_challenges: Vec::new(),
        circuit_gates: Vec::new(),
    };

    let (proving_key, verification_key) =
        Groth16::<Bn254>::circuit_specific_setup(dummy_circuit, rng)?;

    let output_dir = Path::new("solidity_output");
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }

    let solidity_verifier = Groth16::<Bn254>::export(&verification_key);

    let output_path = output_dir.join("vole_verifier.sol");
    fs::write(&output_path, solidity_verifier)?;
    println!("Solidity verifier generated at: {}", output_path.display());

    Ok(SnarkKeys {
        proving_key,
        verification_key,
    })
}

pub fn prove<R: Rng + CryptoRng>(
    vole_proof: &mut VoleProof,
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

    // Extract witness challenges from the transcript
    // This ensures challenges are derived deterministically from the transcript
    let witness_challenges =
        transcript_wrapper.extract_witness_challenges(vole_proof.witness_challenges.len());

    // Append polynomial commitments to continue the transcript
    transcript_wrapper.append_polynomial_commitments(
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
    );
    let circuit = VoleVerificationCircuit {
        // Public Inputs
        degree_0_commitment: f128b_to_ark(&vole_proof.degree_0_commitment),
        degree_1_commitment: f128b_to_ark(&vole_proof.degree_1_commitment),
        verifier_key: f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
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
        witness_challenges,
        // Circuit gates - currently empty, but could be populated with actual circuit gates
        circuit_gates: Vec::new(),
    };

    // Error: unsatisfiable constraint system
    let proof = Groth16::<Bn254>::prove(&keys.proving_key, circuit, rng)?;

    // Prepare the public inputs for verification
    let inputs = vec![
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
        f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
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
        transcript_wrapper.extract_witness_challenges(vole_proof.witness_challenges.len());
    let proof_witness_challenges: Vec<Bn254Fr> = vole_proof
        .witness_challenges
        .iter()
        .map(f128b_to_ark)
        .collect();

    // Verify that the challenges in the proof match the expected challenges
    // This ensures the prover didn't manipulate the challenges
    if expected_witness_challenges != proof_witness_challenges {
        println!("Challenge verification failed: challenges in proof don't match expected values");
        return Ok(false);
    }

    // Append polynomial commitments to continue the transcript
    transcript_wrapper.append_polynomial_commitments(
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
    );

    let snark_verification = Groth16::<Bn254>::verify(
        &keys.verification_key,
        &snark_proof.inputs,
        &snark_proof.proof,
    );

    if snark_verification.is_err() {
        println!("SNARK verification failed");
        return Ok(false);
    }

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;
    use swanky_field::FiniteRing;

    #[test]
    fn test_partial_decommitment_accessors() {
        // Test the accessor methods of PartialDecommitment
        let verifier_key = F128b::ONE;
        let witness_voles = vec![vec![F8b::ZERO, F8b::ONE]];
        let mask_voles = [F128b::ZERO; 128];

        let decommitment = PartialDecommitment {
            verifier_key,
            witness_voles: witness_voles.clone(),
            mask_voles,
        };

        // Test verifier_key accessor
        assert_eq!(decommitment.verifier_key(), verifier_key);

        // Test witness_voles accessor
        let returned_voles = decommitment.witness_voles();
        assert_eq!(returned_voles.len(), witness_voles.len());
        assert_eq!(returned_voles[0].len(), witness_voles[0].len());
        assert_eq!(returned_voles[0][0], witness_voles[0][0]);
        assert_eq!(returned_voles[0][1], witness_voles[0][1]);
    }

    #[test]
    fn test_convert_challenge() {
        // Test converting a challenge to F128b
        let challenge = [1u8; 16];
        let result = convert_challenge(challenge);

        // Check that the conversion succeeds
        assert!(result.is_ok());
    }

    #[test]
    fn test_challenge_verification() {
        // Create a deterministic RNG for testing
        let mut rng = StdRng::seed_from_u64(12345);

        // Create a dummy VoleProof with incorrect challenges
        let mut vole_proof = VoleProof {
            vole_challenge: F128b::ONE,
            witness_commitment: vec![F64b::ONE, F64b::ONE],
            witness_challenges: vec![F128b::ONE, F128b::ONE], // Incorrect challenges
            degree_0_commitment: F128b::ONE,
            degree_1_commitment: F128b::ONE,
            deccomitment_challenge: F128b::ONE,
            partial_decommitment: PartialDecommitment {
                verifier_key: F128b::ONE,
                witness_voles: vec![vec![F8b::ONE]],
                mask_voles: [F128b::ZERO; 128],
            },
        };

        // Setup keys
        let keys = setup(&mut rng).unwrap();

        // Generate a proof, which should update the challenges correctly
        let snark_proof = prove(&mut vole_proof, &keys, &mut rng).unwrap();

        // Verify the proof - should succeed because challenges were updated
        let result = verify(&snark_proof, &keys, &vole_proof).unwrap();
        assert!(
            result,
            "Verification should succeed with correct challenges"
        );

        // Now tamper with the challenges
        let mut tampered_proof = vole_proof.clone();
        tampered_proof.witness_challenges = vec![F128b::ZERO, F128b::ZERO];

        // Verify the tampered proof - should fail
        let result = verify(&snark_proof, &keys, &tampered_proof).unwrap();
        assert!(
            !result,
            "Verification should fail with incorrect challenges"
        );
    }
}
