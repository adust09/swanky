use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{convert_proof, prove, setup, verify, VoleProof};
use std::{
    fs::File,
    io::{Cursor, Write},
};
use swanky_field::FiniteRing;

fn main() -> Result<()> {
    println!("Schmivitz-SNARK Basic Usage Example");
    println!("===================================");

    // Step 1: Create a simple circuit
    let circuit_bytes = "version 2.0.0;
        circuit;
        @type field 18446744073709551616;
        @begin
          $0 <- @private(0);
          $1 <- @mul(0: $0, $0);
          $2 <- @add(0: $0, $0);
        @end ";
    let circuit = Cursor::new(circuit_bytes.as_bytes());

    // Step 2: Create private input
    let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
        @end";

    // Create a temporary file for private input
    let temp_dir = tempfile::tempdir()?;
    let private_input_path = temp_dir.path().join("private_input.txt");
    let mut private_input_file = File::create(&private_input_path)?;
    writeln!(private_input_file, "{}", private_input_bytes)?;
    private_input_file.flush()?;

    println!("1. Created circuit and private input");

    // Step 3: Generate a proof using schmivitz
    let mut transcript = Transcript::new(b"schmivitz-snark example");
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
    println!("   Solidity verifier generated at: solidity_output/vole_verifier.sol");

    // Step 5: Convert the schmivitz proof to a VoleProof
    let vole_proof = convert_proof(&schmivitz_proof)?;
    println!("4. Converted schmivitz proof to VoleProof");

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

    Ok(())
}

// This is a placeholder for the actual validation_aggregate computation
// In a real implementation, this would compute the validation aggregate based on
// the schmivitz verification logic
fn compute_validation_aggregate(vole_proof: &VoleProof) -> swanky_field_binary::F128b {
    // This is just a placeholder implementation
    // The actual implementation would follow the steps in schmivitz's verify method
    swanky_field_binary::F128b::ONE
}
