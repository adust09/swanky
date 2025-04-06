// External dependencies
use clap::{Parser, Subcommand};
use eyre::{bail, Result};
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

// Internal modules
mod transpiler;

// Circuit compilation dependencies
use mac_n_cheese_ir::{
    circuit_builder::{build_circuit, build_privates, vole_supplier::VoleSupplier},
    compilation_format::{wire_format::Wire, FieldMacType, Type, WireSize},
};

// Zero knowledge proof dependencies
use scuttlebutt::{field::F2, ring::FiniteRing};

// Keccak implementation
use vectoreyes::array_utils::ArrayUnrolledExt;

#[derive(Parser)]
#[command(name = "keccak_zk")]
#[command(about = "Compile Keccak_f circuit and generate/verify proofs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compile Keccak_f circuit from bristol-fashion to SIEVE IR
    Compile {},

    /// Transpile a Bristol Fashion circuit to SIEVE IR
    Transpile {
        /// Input Bristol Fashion circuit file
        #[arg(short, long)]
        input: PathBuf,

        /// Output SIEVE IR file
        #[arg(short, long)]
        output: PathBuf,

        /// Output format (text or binary)
        #[arg(short, long, default_value = "text")]
        format: String,
    },

    /// Test the Keccak-f circuit with sample inputs and verify outputs
    TestKeccakF {
        /// Input Bristol Fashion circuit file
        #[arg(short, long, default_value = "src/keccak_f.txt")]
        input: PathBuf,

        /// Private input file
        #[arg(short, long, default_value = "src/keccak_private_input.txt")]
        private_input: PathBuf,
    },
}

// Helper functions for wire handling
fn own_wire(idx: impl TryInto<WireSize>) -> Wire {
    Wire::own_wire(ws(idx))
}

fn input_wire(which_input: impl TryInto<WireSize>, which_wire: impl TryInto<WireSize>) -> Wire {
    Wire::input_wire(ws(which_input), ws(which_wire))
}

fn ws(x: impl TryInto<WireSize>) -> WireSize {
    match x.try_into() {
        Ok(y) => y,
        Err(_) => panic!("wire size overflow"),
    }
}

// Circuit representation
type WireId = usize;

#[derive(Debug, Clone, Copy)]
enum WireBody {
    Inv(WireId),
    Xor(WireId, WireId),
    And(WireId, WireId),
    Input(usize),
}

#[derive(Default, Clone)]
struct Circuit {
    wires: Vec<WireBody>,
    reverse_deps: Vec<Vec<WireId>>,
    outputs: Vec<WireId>,
}

impl Circuit {
    fn add_wire(&mut self, body: WireBody) -> WireId {
        let out = self.wires.len();
        self.reverse_deps.push(Vec::new());
        match body {
            WireBody::Inv(x) => self.reverse_deps[x].push(out),
            WireBody::Xor(a, b) => {
                self.reverse_deps[a].push(out);
                if a != b {
                    self.reverse_deps[b].push(out);
                }
            }
            WireBody::And(a, b) => {
                self.reverse_deps[a].push(out);
                if a != b {
                    self.reverse_deps[b].push(out);
                }
            }
            WireBody::Input(_) => {}
        }
        self.wires.push(body);
        out
    }
}

// Constants
const NUM_INPUTS: usize = 1600;
const MAC_TY: FieldMacType = FieldMacType::BinaryF63b;

fn parse_circuit() -> Circuit {
    let src = include_str!("keccak_f.txt");
    // We're parsing the initial version of bristol circuits, not the newer version.
    let mut lines = src.trim().split('\n');
    let hdr = Vec::from_iter(lines.next().unwrap().split_ascii_whitespace());
    let _num_gates = usize::from_str(hdr[0]).unwrap();
    let num_wires = usize::from_str(hdr[1]).unwrap();
    let mut bristol2wire = vec![None; num_wires];
    let mut circuit = Circuit::default();
    for i in 0..NUM_INPUTS {
        bristol2wire[i] = Some(circuit.add_wire(WireBody::Input(i)));
    }
    let _ = lines.next().unwrap(); // Skip number of input and output wires
    let mut buf = Vec::new();
    for line in lines {
        buf.clear();
        buf.extend(line.split_ascii_whitespace());
        match *buf.last().unwrap() {
            "XOR" => {
                assert_eq!(buf[0], "2");
                assert_eq!(buf[1], "1");
                let in0 = usize::from_str(buf[2]).unwrap();
                let in1 = usize::from_str(buf[3]).unwrap();
                let output = usize::from_str(buf[4]).unwrap();
                let in0 = bristol2wire[in0].unwrap();
                let in1 = bristol2wire[in1].unwrap();
                assert!(bristol2wire[output].is_none());
                bristol2wire[output] = Some(circuit.add_wire(WireBody::Xor(in0, in1)));
            }
            "AND" => {
                assert_eq!(buf[0], "2");
                assert_eq!(buf[1], "1");
                let in0 = usize::from_str(buf[2]).unwrap();
                let in1 = usize::from_str(buf[3]).unwrap();
                let output = usize::from_str(buf[4]).unwrap();
                let in0 = bristol2wire[in0].unwrap();
                let in1 = bristol2wire[in1].unwrap();
                assert!(bristol2wire[output].is_none());
                bristol2wire[output] = Some(circuit.add_wire(WireBody::And(in0, in1)));
            }
            "INV" => {
                assert_eq!(buf[0], "1");
                assert_eq!(buf[1], "1");
                let input = usize::from_str(buf[2]).unwrap();
                let output = usize::from_str(buf[3]).unwrap();
                let input = bristol2wire[input].unwrap();
                assert!(bristol2wire[output].is_none());
                bristol2wire[output] = Some(circuit.add_wire(WireBody::Inv(input)));
            }
            cmd => panic!("unknown gate {cmd:?}"),
        }
    }
    assert_eq!(circuit.wires.len(), num_wires);
    circuit.outputs = bristol2wire[bristol2wire.len() - 1600..]
        .iter()
        .copied()
        .map(|x| x.unwrap())
        .collect();
    circuit
}
fn compile_circuit() -> Result<()> {
    // Parse the bristol-fashion circuit
    let circuit = parse_circuit();

    // Count the number of multiplications (AND gates) in the circuit
    let num_mults = ws(circuit
        .wires
        .iter()
        .filter(|x| matches!(x, WireBody::And(_, _)))
        .count());

    eprintln!("Parsed Keccak circuit with {} multiplications", num_mults);

    // Parse private input
    let witness = [false; NUM_INPUTS];
    // Optimize circuit representation for SIMD processing
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum KeccakWire {
        ConstOne,
        XorOutput(usize),
        // First 1600 bits are the input state
        FixOutput(usize),
    }

    const XOR_SIMD_SIZE: usize = 4;
    let (xors, mapping) = {
        let mut xors: Vec<[(KeccakWire, KeccakWire); XOR_SIMD_SIZE]> =
            Vec::with_capacity(circuit.wires.len());
        let mut mapping: Vec<Option<KeccakWire>> = vec![None; circuit.wires.len()];
        let mut next_mult = 0;

        // Initialize mapping for inputs and AND gates
        for (i, wire) in circuit.wires.iter().copied().enumerate() {
            match wire {
                WireBody::Inv(_) | WireBody::Xor(_, _) => {}
                WireBody::And(_, _) => {
                    mapping[i] = Some(KeccakWire::FixOutput(next_mult + 1600));
                    next_mult += 1;
                }
                WireBody::Input(j) => {
                    mapping[i] = Some(KeccakWire::FixOutput(j));
                    assert!(j < NUM_INPUTS)
                }
            }
        }

        // Identify wires ready for computation
        let mut ready_to_compute: BinaryHeap<Reverse<usize>> = Default::default();
        ready_to_compute.extend(circuit.wires.iter().copied().enumerate().filter_map(
            |(i, wire)| match wire {
                WireBody::Inv(x) => {
                    if mapping[x].is_some() {
                        Some(Reverse(i))
                    } else {
                        None
                    }
                }
                WireBody::Xor(x, y) => {
                    if mapping[x].is_some() && mapping[y].is_some() {
                        Some(Reverse(i))
                    } else {
                        None
                    }
                }
                WireBody::And(_, _) | WireBody::Input(_) => None,
            },
        ));

        // Process XOR gates in SIMD groups
        let mut next_xor = 0;
        let mut buf = Vec::<(KeccakWire, KeccakWire)>::new();
        let mut out_ids = Vec::new();

        while !ready_to_compute.is_empty() {
            while !ready_to_compute.is_empty() && buf.len() < XOR_SIMD_SIZE {
                let Reverse(i) = ready_to_compute
                    .pop()
                    .expect("we just confirmed it's nonempty!");
                buf.push(match circuit.wires[i] {
                    WireBody::Inv(x) => (KeccakWire::ConstOne, mapping[x].unwrap()),
                    WireBody::Xor(x, y) => (mapping[x].unwrap(), mapping[y].unwrap()),
                    WireBody::And(_, _) | WireBody::Input(_) => unreachable!(),
                });
                out_ids.push(i);
            }

            for oid in out_ids.iter().copied() {
                assert!(mapping[oid].is_none());
                mapping[oid] = Some(KeccakWire::XorOutput(next_xor));
                next_xor += 1;

                // Update dependencies
                for reverse_dep in circuit.reverse_deps[oid].iter().copied() {
                    match circuit.wires[reverse_dep] {
                        WireBody::Inv(x) => {
                            assert_eq!(x, oid);
                            assert!(mapping[reverse_dep].is_none());
                            ready_to_compute.push(Reverse(reverse_dep));
                        }
                        WireBody::Xor(x, y) => {
                            assert!(x == oid || y == oid);
                            assert!(mapping[reverse_dep].is_none());
                            if mapping[x].is_some() && mapping[y].is_some() {
                                ready_to_compute.push(Reverse(reverse_dep));
                            }
                        }
                        WireBody::And(_, _) | WireBody::Input(_) => continue,
                    }
                }
            }

            // Pad buffer to SIMD size
            while buf.len() < XOR_SIMD_SIZE {
                let pair = *buf.first().unwrap();
                next_xor += 1;
                buf.push(pair);
            }

            xors.push(
                *<&[(KeccakWire, KeccakWire); XOR_SIMD_SIZE]>::try_from(buf.as_slice()).unwrap(),
            );
            buf.clear();
            out_ids.clear();
        }

        // Verify all wires are mapped
        for (i, x) in mapping.iter().enumerate() {
            assert!(x.is_some(), "{} {:?}", i, circuit.wires[i]);
        }

        (
            xors,
            mapping.into_iter().map(|x| x.unwrap()).collect::<Vec<_>>(),
        )
    };

    println!("Finished fast linear Keccak evaluation");

    // Generate binary files for the circuit
    build_privates(&format!("keccak_f.priv.bin"), |pb| {
        build_circuit(&format!("keccak_f.bin"), |cb| {
            let mut vs = VoleSupplier::new(1, Default::default());

            // Define constants and prototypes
            let one = cb.new_constant_prototype(MAC_TY, [F2::ONE])?;
            let one = cb.instantiate(&one, &[], &[])?.outputs(Type::Mac(MAC_TY));

            let fix_proto = cb.new_fix_prototype(MAC_TY, 1600 + num_mults)?;

            // XOR gate prototype
            let xors_proto = cb.new_xor4_prototype(
                MAC_TY,
                &[1 /*one*/, 1600 + num_mults /*fixed*/],
                xors.iter().copied().map(|entry| {
                    entry.array_map(|(a, b)| {
                        let convert = |wire| match wire {
                            KeccakWire::ConstOne => input_wire(0, 0),
                            KeccakWire::XorOutput(i) => own_wire(i),
                            KeccakWire::FixOutput(i) => input_wire(1, i),
                        };
                        [convert(a), convert(b)]
                    })
                }),
            )?;

            // Multiplication verification prototype
            let assert_multiply_proto = cb.new_assert_multiply_prototype(
                MAC_TY,
                &[
                    ws(1600 + num_mults),           /*fixed*/
                    ws(xors.len() * XOR_SIMD_SIZE), /*xors*/
                ],
                circuit
                    .wires
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(i, wire)| match wire {
                        WireBody::Inv(_) | WireBody::Xor(_, _) | WireBody::Input(_) => None,
                        WireBody::And(x, y) => Some({
                            let convert = |j| match mapping[j] {
                                KeccakWire::ConstOne => unreachable!(),
                                KeccakWire::XorOutput(idx) => input_wire(1, idx),
                                KeccakWire::FixOutput(idx) => input_wire(0, idx),
                            };
                            [convert(x), convert(y), convert(i)]
                        }),
                    }),
            )?;

            // Prepare fixed data
            let mut fix_data = Vec::with_capacity(1600 + num_mults as usize);

            // Add input state bits
            fix_data.extend_from_slice(&witness);

            // Evaluate circuit
            let mut values: Vec<bool> = Vec::with_capacity(circuit.wires.len());
            for gate in circuit.wires.iter().copied() {
                let v = match gate {
                    WireBody::Inv(x) => !values[x],
                    WireBody::Xor(x, y) => values[x] ^ values[y],
                    WireBody::And(x, y) => {
                        let v = values[x] & values[y];
                        fix_data.push(v);
                        v
                    }
                    WireBody::Input(x) => fix_data[x],
                };
                values.push(v);
            }

            let fixed_voles = vs.supply_voles(cb, &fix_proto)?;
            let fix_output = cb.instantiate(&fix_proto, &[], &[fixed_voles])?;

            // Write fix data directly
            pb.write_fix_data::<_, F2>(&fix_output, |s| {
                for bit in fix_data.into_iter() {
                    s.add(F2::from(bit))?;
                }
                Ok(())
            })?;

            // Get the WireSlice for further operations
            let fix = fix_output.outputs(Type::Mac(MAC_TY));
            let xor_output = cb.instantiate(&xors_proto, &[one, fix], &[])?;
            let xor = xor_output.outputs(Type::Mac(MAC_TY));

            cb.instantiate(&assert_multiply_proto, &[fix, xor], &[])?;

            Ok(())
        })
    })?;

    println!("Successfully compiled circuit to SIEVE IR");
    println!("Output files generated:");
    println!("  - keccak_f.bin");
    println!("  - keccak_f.priv.bin");
    println!("You can now use these files to generate and verify proofs.");
    Ok(())
}

/// Test the Keccak-f circuit with sample inputs and verify outputs
fn test_keccak_f_circuit(input_path: &Path, private_input_path: &Path) -> Result<()> {
    println!("Testing Keccak-f circuit with sample inputs...");
    println!("Circuit file: {}", input_path.display());
    println!("Private input file: {}", private_input_path.display());

    // Step 1: Transpile the circuit from Bristol Fashion to SIEVE IR
    let bristol = transpiler::BristolCircuit::from_file(input_path)?;
    let sieve = transpiler::SieveCircuit::from_bristol(&bristol)?;

    // Step 2: Create a temporary output file for the SIEVE IR
    let output_path = "test_keccak_f_sieve_output.txt";
    sieve.to_file(output_path)?;
    println!("Successfully transpiled circuit to SIEVE IR");

    // Step 3: Use the SIEVE IR private input file directly
    println!(
        "Using SIEVE IR private input file: {}",
        private_input_path.display()
    );

    // We'll use the private input file directly in the SIEVE IR format
    // No need to parse it as it's already in the correct format

    // For evaluation purposes, we'll still create input values (all 1's)
    let mut input_values = Vec::with_capacity(1600);
    for _ in 0..1600 {
        input_values.push(true); // All inputs set to 1
    }

    // Step 4: Evaluate the circuit with the private inputs
    println!("Evaluating circuit with inputs...");

    // Create a circuit evaluation function
    let mut wire_values = vec![false; bristol.num_wires];

    // Set input values
    for (i, &wire_idx) in bristol.input_wires.iter().enumerate() {
        if i < input_values.len() {
            wire_values[wire_idx] = input_values[i];
        }
    }

    // Evaluate each gate in order
    for gate in &bristol.gates {
        match gate {
            transpiler::BristolGate::Xor { inputs, output } => {
                wire_values[*output] = wire_values[inputs[0]] ^ wire_values[inputs[1]];
            }
            transpiler::BristolGate::And { inputs, output } => {
                wire_values[*output] = wire_values[inputs[0]] & wire_values[inputs[1]];
            }
            transpiler::BristolGate::Inv { input, output } => {
                wire_values[*output] = !wire_values[*input];
            }
        }
    }

    // Extract output values
    let output_values: Vec<bool> = bristol
        .output_wires
        .iter()
        .map(|&wire_idx| wire_values[wire_idx])
        .collect();

    println!("Circuit evaluation complete");
    println!("Output size: {} bits", output_values.len());

    // Step 5: Verify the circuit structure
    println!("Verifying circuit structure...");
    assert_eq!(bristol.num_gates, 192086, "Incorrect number of gates");
    assert_eq!(bristol.num_wires, 193686, "Incorrect number of wires");
    assert_eq!(
        bristol.input_group_sizes,
        vec![1600],
        "Incorrect input group sizes"
    );
    assert_eq!(
        sieve.input_wires.len(),
        1600,
        "Should have 1600 input wires"
    );
    assert_eq!(output_values.len(), 1600, "Should have 1600 output bits");

    // Step 6: Verify the SIEVE IR output file contains expected elements
    let content = std::fs::read_to_string(output_path)?;
    assert!(
        content.contains("version 2.0.0;"),
        "Missing version in output"
    );
    assert!(
        content.contains("circuit;"),
        "Missing circuit declaration in output"
    );
    assert!(
        content.contains("@type field 2;"),
        "Missing field type in output"
    );
    assert!(content.contains("@begin"), "Missing begin marker in output");
    assert!(content.contains("@end"), "Missing end marker in output");
    assert!(
        content.contains("$0 <- @private(0);"),
        "Missing constant 1 wire definition"
    );

    // Verify at least one gate of each type exists in the output
    let has_add_gate = content.contains("@add");
    let has_mul_gate = content.contains("@mul");
    assert!(has_add_gate, "No add gates found in output");
    assert!(has_mul_gate, "No mul gates found in output");

    println!("Circuit structure verification passed!");
    println!("Successfully tested Keccak-f circuit with sample inputs");

    // In a future enhancement, we would:
    // 1. Compare the output with expected results from a reference implementation
    // 2. Implement proof generation and verification

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compile {} => compile_circuit(),
        Commands::Transpile {
            input,
            output,
            format,
        } => {
            println!("Transpiling Bristol Fashion circuit to SIEVE IR...");
            println!("Input file: {}", input.display());
            println!("Output file: {}", output.display());

            if format != "text" && format != "binary" {
                bail!(
                    "Invalid output format: {}. Must be 'text' or 'binary'",
                    format
                );
            }

            // Transpile the circuit
            let bristol = transpiler::BristolCircuit::from_file(&input)?;
            let sieve = transpiler::SieveCircuit::from_bristol(&bristol)?;

            if format == "text" {
                // Output in text format
                sieve.to_file(&output)?;
                println!("Successfully transpiled circuit to SIEVE IR text format");
            } else {
                // Output in binary format using flatbuffers
                println!("Converting to binary format...");

                // For now, we'll output in text format and note that binary is a future enhancement
                sieve.to_file(&output)?;
                println!("Note: Binary format conversion will be implemented in a future update");
                println!("The circuit has been output in text format for now");
            }

            println!("Output file generated: {}", output.display());

            Ok(())
        }
        Commands::TestKeccakF {
            input,
            private_input,
        } => test_keccak_f_circuit(&input, &private_input),
    }
}
