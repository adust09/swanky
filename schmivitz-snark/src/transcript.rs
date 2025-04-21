use ark_bn254::Fr as Bn254Fr;
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;

pub struct TranscriptWrapper<'a>(&'a mut Transcript);

impl<'a> From<&'a mut Transcript> for TranscriptWrapper<'a> {
    fn from(transcript: &'a mut Transcript) -> Self {
        Self(transcript)
    }
}

impl<'a> TranscriptWrapper<'a> {
    pub fn append_public_values(&mut self) {
        const SECURITY_PARM: u64 = 128;
        const FIELD_SIZE: u64 = 254;
        const VOLE_SIZE_PARAM: u64 = 128;
        const REPETITION_PARAM: u64 = 40;

        self.0
            .append_message(b"lambda: security parameter", &SECURITY_PARM.to_le_bytes());

        self.0
            .append_message(b"p:field size", &FIELD_SIZE.to_le_bytes());

        self.0
            .append_message(b"r: VOLE size parameter", &VOLE_SIZE_PARAM.to_le_bytes());

        self.0.append_message(
            b"tau: repetition parameter",
            &REPETITION_PARAM.to_le_bytes(),
        );
    }

    pub fn append_witness_commitment(&mut self, witness_commitment: &[Bn254Fr]) {
        let mut bytes = Vec::new();
        for commitment in witness_commitment {
            let mut commitment_bytes = [0u8; 32];
            commitment
                .serialize_uncompressed(&mut commitment_bytes[..])
                .unwrap();
            bytes.extend_from_slice(&commitment_bytes);
        }
        self.0.append_message(b"d: commitment to witness", &bytes);
    }

    pub fn extract_witness_challenges(&mut self, polynomial_count: usize) -> Vec<Bn254Fr> {
        use ark_ff::UniformRand;
        use rand::{rngs::StdRng, SeedableRng};
        use std::iter::repeat_with;

        repeat_with(|| {
            let mut seed_bytes = [0u8; 32];
            self.0
                .challenge_bytes(b"chi_i: witness challenge", &mut seed_bytes);

            // Use the challenge bytes as a seed for a deterministic RNG
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&seed_bytes[0..32]);

            // Create a deterministic RNG from the seed
            let mut rng = StdRng::from_seed(seed);

            // Generate a random field element using the seeded RNG
            // This ensures we get a valid field element within the correct range
            Bn254Fr::rand(&mut rng)
        })
        .take(polynomial_count)
        .collect()
    }

    pub fn append_polynomial_commitments(
        &mut self,
        degree_0_commitment: Bn254Fr,
        degree_1_commitment: Bn254Fr,
    ) {
        let mut degree_0_bytes = [0u8; 32];
        degree_0_commitment
            .serialize_uncompressed(&mut degree_0_bytes[..])
            .unwrap();
        let mut degree_1_bytes = [0u8; 32];
        degree_1_commitment
            .serialize_uncompressed(&mut degree_1_bytes[..])
            .unwrap();

        self.0.append_message(b"b~:", &degree_0_bytes);
        self.0.append_message(b"a~:", &degree_1_bytes);
    }
}
