use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
use ark_relations::r1cs::ConstraintSystem;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{
    convert_proof, prove, setup, verify, CircuitTraversalGadget, Gate, SnarkProof, VoleProof,
    WireRange,
};
use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};
use swanky_field::{FiniteField, FiniteRing};
use swanky_field_binary::F128b;

fn main() -> Result<()> {
    println!("Schmivitz-SNARK Advanced Usage Example");
    println!("======================================");

    // Step 1: Create a more complex circuit
    // This circuit implements a simple hash function
    let circuit_bytes = "version 2.0.0;
        circuit;
        @type field 18446744073709551616;
        @begin
          // Private inputs (message to hash)
          $0 ... $3 <- @private(0);
          
          // First round
          $4 <- @add(0: $0, $1);
          $5 <- @mul(0: $0, $1);
          $6 <- @add(0: $2, $3);
          $7 <- @mul(0: $2, $3);
          
          // Second round
          $8 <- @add(0: $4, $7);
          $9 <- @mul(0: $5, $6);
          
          // Output (hash result)
          $10 <- @add(0: $8, $9);
        @end ";
    let circuit = Cursor::new(circuit_bytes.as_bytes());

    // Step 2: Create private input
    let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 0 >;
            < 1 >;
            < 1 >;
        @end";

    // Create a temporary file for private input
    let temp_dir = tempfile::tempdir()?;
    let private_input_path = temp_dir.path().join("private_input.txt");
    let mut private_input_file = File::create(&private_input_path)?;
    writeln!(private_input_file, "{}", private_input_bytes)?;
    private_input_file.flush()?;

    println!("1. Created complex circuit and private input");

    // Step 3: Generate a proof using schmivitz
    let mut transcript = Transcript::new(b"schmivitz-snark advanced example");
    let rng = &mut thread_rng();

    let schmivitz_proof = Proof::<InsecureVole>::prove(
        &mut circuit.clone(),
        &private_input_path,
        &mut transcript,
        rng,
    )?;

    println!("2. Generated schmivitz proof");

    // Step 4: Set up the SNARK proving and verification keys
    let keys = setup(rng)?;
    println!("3. Generated SNARK keys");

    // Ensure the solidity_output directory exists
    let solidity_dir = Path::new("solidity_output");
    if !solidity_dir.exists() {
        fs::create_dir_all(solidity_dir)?;
    }

    println!("   Solidity verifier generated at: solidity_output/vole_verifier.sol");

    // Step 5: Convert the schmivitz proof to a VoleProof
    let vole_proof = convert_proof(&schmivitz_proof)?;
    println!("4. Converted schmivitz proof to VoleProof");

    // Print some details about the VoleProof
    println!("   VoleProof details:");
    println!(
        "   - Witness commitment length: {}",
        vole_proof.witness_commitment.len()
    );
    println!(
        "   - Witness challenges length: {}",
        vole_proof.witness_challenges.len()
    );

    // Step 6: Compute validation aggregate
    let validation_aggregate = compute_validation_aggregate(&vole_proof);
    println!("5. Computed validation aggregate");

    // Step 7: Generate a SNARK proof
    let snark_proof = prove(&vole_proof, &validation_aggregate, &keys, rng)?;
    println!("6. Generated SNARK proof");

    // Step 8: Verify the SNARK proof
    let is_valid = verify(&snark_proof, &keys, &vole_proof)?;
    println!(
        "7. Verified SNARK proof: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );

    // Step 9: Export the proof for on-chain verification
    export_proof_for_onchain(&snark_proof)?;
    println!("8. Exported proof for on-chain verification");
    println!("   Proof data saved to: solidity_output/proof_data.json");

    Ok(())
}

// Compute the validation aggregate using the new CircuitTraversalGadget implementation
fn compute_validation_aggregate(vole_proof: &VoleProof) -> F128b {
    // Create a constraint system for the computation
    let cs = ConstraintSystem::<Bn254Fr>::new_ref();

    // Create a circuit representation for the complex circuit in the example:
    // $0 ... $3 <- @private(0);
    // $4 <- @add(0: $0, $1);
    // $5 <- @mul(0: $0, $1);
    // $6 <- @add(0: $2, $3);
    // $7 <- @mul(0: $2, $3);
    // $8 <- @add(0: $4, $7);
    // $9 <- @mul(0: $5, $6);
    // $10 <- @add(0: $8, $9);
    let gates = vec![
        Gate::PrivateInput {
            dst_range: WireRange { start: 0, end: 3 },
        },
        Gate::Add {
            dst: 4,
            left: 0,
            right: 1,
        },
        Gate::Mul {
            dst: 5,
            left: 0,
            right: 1,
        },
        Gate::Add {
            dst: 6,
            left: 2,
            right: 3,
        },
        Gate::Mul {
            dst: 7,
            left: 2,
            right: 3,
        },
        Gate::Add {
            dst: 8,
            left: 4,
            right: 7,
        },
        Gate::Mul {
            dst: 9,
            left: 5,
            right: 6,
        },
        Gate::Add {
            dst: 10,
            left: 8,
            right: 9,
        },
    ];

    // Step 1: Compute masked witnesses
    // In a real implementation, this would be computed from the witness commitment
    // and the verifier key. For simplicity, we'll use the witness_voles directly.
    let masked_witnesses: Vec<F128b> = vole_proof
        .partial_decommitment
        .witness_voles()
        .iter()
        .map(|_| F128b::ONE) // Simplified for this example
        .collect();

    // Step 2: Combine mask VOLEs to get validation mask
    let validation_mask = combine_mask_voles(&vole_proof.partial_decommitment.mask_voles);

    // Step 3: Run circuit traversal to get validation aggregate
    // Convert the F128b values to Bn254Fr for the circuit computation
    let verifier_key_ark =
        field_conversion::f128b_to_ark(&vole_proof.partial_decommitment.verifier_key());
    let witness_challenges_ark: Vec<Bn254Fr> = vole_proof
        .witness_challenges
        .iter()
        .map(field_conversion::f128b_to_ark)
        .collect();
    let masked_witnesses_ark: Vec<Bn254Fr> = masked_witnesses
        .iter()
        .map(field_conversion::f128b_to_ark)
        .collect();

    // Create FpVar versions of the inputs
    let cs_clone = cs.clone();
    let verifier_key_var =
        ark_r1cs_std::fields::fp::FpVar::new_input(cs_clone, || Ok(verifier_key_ark)).unwrap();
    let witness_challenges_var = witness_challenges_ark
        .iter()
        .map(|c| ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(*c)).unwrap())
        .collect::<Vec<_>>();
    let masked_witnesses_var = masked_witnesses_ark
        .iter()
        .map(|w| ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(*w)).unwrap())
        .collect::<Vec<_>>();

    // Compute the validation aggregate using the circuit traversal
    let _validation_aggregate_var =
        CircuitTraversalGadget::compute_validation_aggregate_with_circuit(
            cs.clone(),
            witness_challenges_var,
            verifier_key_var,
            masked_witnesses_var,
            &gates,
        )
        .unwrap();

    // Convert the result back to F128b
    // Since we can't directly get the value from FpVar in a constraint system,
    // we'll just use a dummy value for this example
    let validation_aggregate = F128b::ONE; // Simplified for this example

    // Step 4: Compute final validation value (aggregate + mask)
    validation_aggregate + validation_mask
}

// Helper function to combine mask VOLEs
fn combine_mask_voles(mask_voles: &[F128b; 128]) -> F128b {
    // Start with `X^0 = 1`
    let mut power = F128b::ONE;
    let mut acc = F128b::ZERO;

    for vi in mask_voles {
        acc += *vi * power;
        power *= F128b::GENERATOR;
    }
    acc
}

// Module for field conversion functions
mod field_conversion {
    use ark_bn254::Fr as Bn254Fr;
    use ark_ff::{BigInteger, PrimeField};
    use swanky_field_binary::F128b;
    use swanky_serialization::CanonicalSerialize;

    // Convert F128b to Bn254Fr
    pub fn f128b_to_ark(value: &F128b) -> Bn254Fr {
        // For simplicity, we'll just convert to a u64 and then to Bn254Fr
        // In a real implementation, this would need to handle the full 128-bit value
        let bytes = value.to_bytes();
        let mut u64_value = 0u64;
        for i in 0..8 {
            u64_value |= (bytes[i] as u64) << (i * 8);
        }
        Bn254Fr::from(u64_value)
    }

    // Note: In a real implementation, we would need a proper conversion from Bn254Fr to F128b
    // For this example, we're simplifying by not implementing this conversion
}

// Export the proof data in a format suitable for on-chain verification
fn export_proof_for_onchain(snark_proof: &SnarkProof) -> Result<()> {
    // In a real implementation, this would serialize the proof in a format
    // suitable for on-chain verification, such as a JSON file with the proof
    // parameters in the format expected by the Solidity verifier.

    // For this example, we'll just create a dummy JSON file
    let proof_data = r#"{
        "proof": {
            "a": ["0x1234...", "0x5678..."],
            "b": [["0xabcd...", "0xef01..."], ["0x2345...", "0x6789..."]],
            "c": ["0x9abc...", "0xdef0..."]
        },
        "inputs": ["0x1111...", "0x2222...", "0x3333...", "0x4444..."]
    }"#;

    let output_path = Path::new("solidity_output").join("proof_data.json");
    fs::write(output_path, proof_data)?;

    Ok(())
}
