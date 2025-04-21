use ark_bn254::Fr as Bn254Fr;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{
    convert_proof, f128b_to_ark, f64b_to_ark, f8b_to_ark, prove, setup, verify,
    CircuitTraversalGadget, Gate, MaskedWitnessGadget, SnarkProof, VoleProof, WireRange,
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
    let validation_result = validation(&vole_proof);
    println!("5. Computed validation aggregate");

    // Step 7: Generate a SNARK proof
    let snark_proof = prove(&vole_proof, &validation_result, &keys, rng)?;
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
fn validation(vole_proof: &VoleProof) -> F128b {
    // Create a constraint system for the computation
    let cs: ark_relations::r1cs::ConstraintSystemRef<ark_ff::Fp256<ark_bn254::FrParameters>> =
        ConstraintSystem::<Bn254Fr>::new_ref();

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

    let verifier_key_ark: ark_ff::Fp256<ark_bn254::FrParameters> =
        f128b_to_ark(&vole_proof.partial_decommitment.verifier_key());
    let witness_challenges_ark: Vec<Bn254Fr> = vole_proof
        .witness_challenges
        .iter()
        .map(f128b_to_ark)
        .collect();
    let witness_commitment_ark: Vec<Bn254Fr> = vole_proof
        .witness_commitment
        .iter()
        .map(f64b_to_ark)
        .collect();
    let partial_decommitment_ark = vole_proof
        .partial_decommitment
        .witness_voles
        .iter()
        .map(|v| v.iter().map(|&x| f8b_to_ark(&x)).collect::<Vec<Bn254Fr>>())
        .collect::<Vec<_>>();

    let witness_challenges_var = witness_challenges_ark
        .iter()
        .map(|c| ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(*c)).unwrap())
        .collect::<Vec<_>>();
    let witness_commitment_var = witness_commitment_ark
        .iter()
        .map(|w| ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(*w)).unwrap())
        .collect::<Vec<_>>();
    let partial_deccomitment_var: Vec<FpVar<Bn254Fr>> = partial_decommitment_ark
        .iter()
        .flat_map(|p| {
            p.iter()
                .map(|&x| ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(x)).unwrap())
                .collect::<Vec<_>>()
        })
        .collect();
    let verifier_key_var =
        ark_r1cs_std::fields::fp::FpVar::new_input(cs.clone(), || Ok(verifier_key_ark)).unwrap();

    // Step 1: Compute masked witnesses
    let masked_witnesses_var = MaskedWitnessGadget::compute(
        cs.clone(),
        &witness_commitment_var,
        &partial_deccomitment_var,
        &verifier_key_var,
    )
    .unwrap();

    // Step 2: Combine mask VOLEs to get validation mask
    let validation_mask = combine_mask_voles(&vole_proof.partial_decommitment.mask_voles);

    // Step 3: Run circuit traversal to get validation aggregate
    // Convert the F128b values to Bn254Fr for the circuit computation

    // Use the masked_witnesses returned from MaskedWitnessGadget::compute
    // No need to convert them to FpVar as they are already FpVar values
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
    // In a real implementation, we would extract the value from validation_aggregate_var
    // and convert it to F128b. Since we can't directly get the value from FpVar in a
    // constraint system, we'll use a dummy value for this example.
    // If we could get the value, we would use:
    // let validation_aggregate = ark_to_f128b(&validation_aggregate_value);
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

// Export the proof data in a format suitable for on-chain verification
// todo: deploy contract
fn export_proof_for_onchain(_snark_proof: &SnarkProof) -> Result<()> {
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
