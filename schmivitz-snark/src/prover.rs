use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, Rng};
use eyre::{Ok, Result};
use merlin::Transcript;
use schmivitz::{
    insecure::InsecureVole,
    parameters::{REPETITION_PARAM, VOLE_SIZE_PARAM},
    {Proof, RandomVole},
};
use serde::Serialize;
use swanky_field::IsSubFieldOf;
use swanky_field_binary::{F128b, F64b, F8b};
use swanky_serialization::CanonicalSerialize as _;

use crate::{
    constraints::{PartialDecommitmentVar, VoleVerification},
    field_mappings::{f128b_to_ark, f64b_to_ark, f8b_to_ark},
    transcript::TranscriptWrapper,
};
#[derive(Debug, Clone, Serialize)]
pub struct VoleProof {
    pub vole_challenge: F128b,
    pub witness_commitment: Vec<F64b>,
    pub witness_challenges: Vec<F128b>,
    pub degree_0_commitment: F128b,
    pub degree_1_commitment: F128b,
    pub deccomitment_challenge: F128b,
    pub partial_decommitment: PartialDecommitment,
}

#[derive(Debug, Clone, Serialize)]
pub struct PartialDecommitment {
    /// Number of VOLEs requested.
    pub extended_witness_length: usize,

    /// Verifier's chosen random key $`\bf \Delta`$.
    pub verifier_key: [F8b; REPETITION_PARAM],

    /// Commitments $`\bf Q`$ to the random values using the specified key and masks.
    pub verifier_commitments: Vec<[F8b; 16]>,
}

impl PartialDecommitment {
    /// Validate that the partial decommitment is correctly formed.
    pub fn validate_commitments(&self) -> Result<()> {
        let expected_num_commitments =
            self.extended_witness_length + REPETITION_PARAM * VOLE_SIZE_PARAM;
        if self.verifier_commitments.len() != expected_num_commitments {
            return Err(eyre::eyre!(
                "Invalid partial vole decommit: expected {} commitments, got {}",
                expected_num_commitments,
                self.verifier_commitments.len()
            ));
        }

        Ok(())
    }
    /// Get the length of the extended witness (e.g. the number of VOLEs requested).
    pub fn extended_witness_length(&self) -> usize {
        self.extended_witness_length
    }

    /// Get the verifier key.
    pub fn verifier_key_array(&self) -> [F8b; REPETITION_PARAM] {
        self.verifier_key
    }

    pub fn verifier_key(&self) -> F128b {
        F8b::form_superfield(&self.verifier_key.into())
    }
    /// Get the VOLEs corresponding to the witness ($`\bf Q_{[1..\ell]}`$ in the paper).
    ///
    /// The output is guaranteed to be [`Self::extended_witness_length()`].
    pub fn witness_voles(&self) -> &[[F8b; REPETITION_PARAM]] {
        &self.verifier_commitments[0..self.extended_witness_length]
    }
    /// Get the lifted VOLEs corresponding to the mask for the aggregate commitment
    /// ($`q_{\ell+1}, \dots, q_{\ell + r\tau}`$ in the paper).
    pub fn mask_voles(&self) -> [F128b; REPETITION_PARAM * VOLE_SIZE_PARAM] {
        // Lift the commitments -- we only want the last $`r\tau`$ of them, so we skip the first ones.
        // This will panic if we constructed the type with the wrong length.
        self.verifier_commitments
            .iter()
            .skip(self.extended_witness_length)
            .map(|q| -> F128b { F8b::form_superfield(q.into()) })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}

pub struct SnarkProof {
    pub proof: Groth16Proof<Bn254>,
    pub public_input: Vec<Bn254Fr>,
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
        extended_witness_length: decommitment.extended_witness_length(),
        verifier_key: *decommitment.verifier_key_array(),
        verifier_commitments: decommitment
            .witness_voles()
            .iter()
            .map(|vole| vole.clone())
            .collect(),
    };
    Ok(partial_decommitment)
}

fn convert_challenge(challenge: [u8; 16]) -> Result<F128b> {
    let converted_challenge = F128b::from_bytes((&challenge).into());
    Ok(converted_challenge?)
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
    // PartialDecommitmentVarの出力形式を確認する
    // var形式にコンバートする
    let circuit = VoleVerification {
        // Public Inputs
        degree_0_commitment: f128b_to_ark(&vole_proof.degree_0_commitment),
        degree_1_commitment: f128b_to_ark(&vole_proof.degree_1_commitment),

        // Private Inputs
        witness_commitment: vole_proof
            .witness_commitment
            .iter()
            .map(f64b_to_ark)
            .collect(),
        witness_challenges,
        partial_decommitment: PartialDecommitmentVar {
            verifier_key: f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
            mask_voles: vole_proof
                .partial_decommitment
                .mask_voles()
                .iter()
                .map(|arg0: &F128b| f128b_to_ark(arg0))
                .collect(),
            witness_voles: vole_proof
                .partial_decommitment
                .witness_voles()
                .iter()
                .map(|vole| f8b_to_ark(&vole[0]))
                .collect(),
        },
    };

    let proof = Groth16::<Bn254>::prove(&keys.proving_key, circuit, rng)?;

    // Prepare the public inputs for verification
    let public_input = vec![
        f128b_to_ark(&vole_proof.degree_0_commitment),
        f128b_to_ark(&vole_proof.degree_1_commitment),
        f128b_to_ark(&vole_proof.partial_decommitment.verifier_key()),
    ];

    Ok(SnarkProof {
        proof,
        public_input,
    })
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
        &snark_proof.public_input,
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
    use swanky_field::FiniteRing;

    #[test]
    fn test_partial_decommitment_accessors() {
        // Test the accessor methods of PartialDecommitment
        let verifier_key = [F8b::ONE; 16];

        let decommitment = PartialDecommitment {
            extended_witness_length: 1,
            verifier_key,
            verifier_commitments: vec![[F8b::ZERO; 16]],
        };

        // Convert the array to F128b by combining all 16 elements
        let f128b_key = F8b::form_superfield(&verifier_key.into());

        // Convert F128b to Bn254Fr (arkworks field element)
        f128b_to_ark(&f128b_key);

        // Test verifier_key accessor
        assert_eq!(decommitment.verifier_key(), f128b_key);
    }

    #[test]
    fn test_convert_challenge() {
        // Test converting a challenge to F128b
        let challenge = [1u8; 16];
        let result = convert_challenge(challenge);

        // Check that the conversion succeeds
        assert!(result.is_ok());
    }
}
