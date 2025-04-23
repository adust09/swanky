use eyre::Result;
use merlin::Transcript;
use rand::thread_rng;
use schmivitz::{insecure::InsecureVole, Proof};
use schmivitz_snark::{convert_proof, prove, setup, verify};
use std::{
    fs::{self, File},
    io::{Cursor, Write},
    path::Path,
};
use tempfile::tempdir;

fn main() -> Result<()> {
    let circuit_bytes = "version 2.0.0;
        circuit;
        @type field 2;
        @begin
            $0 ... $1 <- @private(0);
            $2 <- @add(0: $0, $1);
        @end";
    let circuit = Cursor::new(circuit_bytes.as_bytes());

    let private_input_bytes = "version 2.0.0;
        private_input;
        @type field 2;
        @begin
            < 1 >;
            < 0 >;
        @end";

    let dir = tempdir().unwrap();
    let private_input_path = dir.path().join("private_inputs");
    let mut private_input = File::create(private_input_path.clone()).unwrap();
    writeln!(private_input, "{}", private_input_bytes).unwrap();

    let mut transcript = Transcript::new(b"schmivitz-snark example");
    let rng = &mut thread_rng();

    let schmivitz_proof = Proof::<InsecureVole>::prove(
        &mut circuit.clone(),
        &private_input_path,
        &mut transcript,
        rng,
    )?;
    let keys = setup(rng)?;

    // Ensure the solidity_output directory exists
    let solidity_dir = Path::new("solidity_output");
    if !solidity_dir.exists() {
        fs::create_dir_all(solidity_dir)?;
    }
    println!("   Solidity verifier generated at: solidity_output/vole_verifier.sol");

    let mut vole_proof = convert_proof(&schmivitz_proof)?;
    let snark_proof = prove(&mut vole_proof, &keys, rng)?;

    let is_valid = verify(&snark_proof, &keys, &vole_proof)?;
    println!(
        "Verified SNARK proof: {}",
        if is_valid { "VALID" } else { "INVALID" }
    );
    Ok(())
}
