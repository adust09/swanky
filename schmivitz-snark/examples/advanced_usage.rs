use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{convert_proof, prove, setup, verify, SnarkProof, VoleProof};
use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};
use swanky_field::FiniteRing;
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
    let is_valid = verify(&snark_proof, &keys)?;
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

// This is a placeholder for the actual validation_aggregate computation
// In a real implementation, this would compute the validation aggregate based on
// the schmivitz verification logic
fn compute_validation_aggregate(vole_proof: &VoleProof) -> F128b {
    // This is just a placeholder implementation
    // The actual implementation would follow the steps in schmivitz's verify method:

    // 1. Compute masked witnesses
    // let masked_witnesses = compute_masked_witnesses(vole_proof);

    // 2. Combine mask VOLEs to get validation mask
    // let validation_mask = combine(vole_proof.partial_decommitment.mask_voles());

    // 3. Run circuit traversal to get validation aggregate
    // let validation_aggregate = traverse_circuit_with_masked_witnesses(
    //     &vole_proof.witness_challenges,
    //     &vole_proof.partial_decommitment.verifier_key(),
    //     &masked_witnesses,
    // );

    // 4. Compute final validation value (aggregate + mask)
    // validation_aggregate + validation_mask

    // For now, just return a dummy value
    F128b::ONE
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
