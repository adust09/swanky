use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_groth16::{Proof as Groth16Proof, ProvingKey, VerifyingKey};

pub struct SnarkProof {
    pub proof: Groth16Proof<Bn254>,
    pub public_input: Vec<Bn254Fr>,
}

pub struct SnarkKeys {
    pub proving_key: ProvingKey<Bn254>,
    pub verification_key: VerifyingKey<Bn254>,
}
