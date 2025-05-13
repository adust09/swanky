//! Bristol Fashion to SIEVE IR Transpiler
//!
//! This module provides functionality to convert circuit descriptions from Bristol Fashion format
//! to SIEVE IR format, enabling the use of Bristol Fashion circuits with the schmivitz
//! VOLE-in-the-head zero-knowledge proof system.

use std::collections::HashMap;
use std::fmt::{self, Display, Formatter};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::str::FromStr;

use eyre::{bail, Context, Result};

/// Represents a gate in the Bristol Fashion format
#[derive(Debug, Clone)]
pub enum BristolGate {
    /// XOR gate with two inputs and one output
    Xor { inputs: Vec<usize>, output: usize },
    /// AND gate with two inputs and one output
    And { inputs: Vec<usize>, output: usize },
    /// INV gate with one input and one output
    Inv { input: usize, output: usize },
}

/// Represents a gate in the SIEVE IR format
#[derive(Debug, Clone)]
pub enum SieveGate {
    /// Private input gate
    Private { output: usize, party: usize },
    /// Addition gate (XOR in binary field)
    Add { inputs: Vec<usize>, output: usize },
    /// Multiplication gate (AND in binary field)
    Mul { inputs: Vec<usize>, output: usize },
    /// Add Constant gate
    AddConstant {
        input: usize,
        constant: usize,
        output: usize,
    },
}

impl Display for SieveGate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SieveGate::Private { output, party } => {
                write!(f, "${} <- @private({});", output, party)
            }
            SieveGate::Add { inputs, output } => {
                write!(f, "${} <- @add(0: ", output)?;
                for (i, input) in inputs.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "${}", input)?;
                }
                write!(f, ");")
            }
            SieveGate::Mul { inputs, output } => {
                if inputs.len() != 2 {
                    return write!(f, "// ERROR: Mul gate must have exactly 2 inputs");
                }
                write!(f, "${} <- @mul(0: ${}, ${});", output, inputs[0], inputs[1])
            }
            SieveGate::AddConstant {
                input,
                constant,
                output,
            } => {
                write!(f, "${} <- @addc(0: ${}, < {} >);", output, input, constant)
            }
        }
    }
}

/// Represents a circuit in Bristol Fashion format
#[derive(Debug, Clone)]
pub struct BristolCircuit {
    /// Number of gates in the circuit
    pub num_gates: usize,
    /// Number of wires in the circuit
    pub num_wires: usize,
    /// Number of input groups
    pub num_input_groups: usize,
    /// Number of wires in each input group
    pub input_group_sizes: Vec<usize>,
    /// Number of output groups
    pub num_output_groups: usize,
    /// Number of wires in each output group
    pub output_group_sizes: Vec<usize>,
    /// Gates in the circuit
    pub gates: Vec<BristolGate>,
    /// Input wire indices
    pub input_wires: Vec<usize>,
    /// Output wire indices
    pub output_wires: Vec<usize>,
}

/// Represents a circuit in SIEVE IR format
#[derive(Debug, Clone)]
pub struct SieveCircuit {
    /// Gates in the circuit
    pub gates: Vec<SieveGate>,
    /// Input wire indices
    pub input_wires: Vec<usize>,
    /// Output wire indices
    pub output_wires: Vec<usize>,
}

impl BristolCircuit {
    /// Parse a Bristol Fashion circuit from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path).context("Failed to open Bristol Fashion circuit file")?;
        let reader = BufReader::new(file);
        Self::from_reader(reader)
    }

    /// Parse a Bristol Fashion circuit from a string
    pub fn from_str(s: &str) -> Result<Self> {
        let reader = BufReader::new(s.as_bytes());
        Self::from_reader(reader)
    }

    /// Parse a Bristol Fashion circuit from a reader
    pub fn from_reader<R: BufRead>(reader: R) -> Result<Self> {
        // Read all lines into a vector
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

        if lines.is_empty() {
            bail!("Empty circuit file");
        }

        // Parse header - first line: number of gates and number of wires
        let header_parts: Vec<&str> = lines[0].split_whitespace().collect();
        if header_parts.len() != 2 {
            bail!(
                "Invalid header format: expected 2 values, got {}",
                header_parts.len()
            );
        }

        let num_gates =
            usize::from_str(header_parts[0]).context("Failed to parse number of gates")?;
        let num_wires =
            usize::from_str(header_parts[1]).context("Failed to parse number of wires")?;

        // Parse input information - second line: number of input groups and wires per group
        if lines.len() < 2 {
            bail!("Missing input information");
        }

        let input_line_parts: Vec<&str> = lines[1].split_whitespace().collect();
        if input_line_parts.len() < 2 {
            bail!(
                "Invalid input format: expected at least 2 values, got {}",
                input_line_parts.len()
            );
        }

        let num_input_groups = usize::from_str(input_line_parts[0])
            .context("Failed to parse number of input groups")?;

        if input_line_parts.len() != num_input_groups + 1 {
            bail!(
                "Invalid input format: expected {} input group sizes, got {}",
                num_input_groups,
                input_line_parts.len() - 1
            );
        }

        let mut input_group_sizes = Vec::with_capacity(num_input_groups);
        for i in 0..num_input_groups {
            input_group_sizes.push(
                usize::from_str(input_line_parts[i + 1])
                    .context(format!("Failed to parse input group size {}", i))?,
            );
        }

        // Parse output information - third line: number of output groups and wires per group
        if lines.len() < 3 {
            bail!("Missing output information");
        }

        let output_line_parts: Vec<&str> = lines[2].split_whitespace().collect();
        if output_line_parts.len() < 2 {
            bail!(
                "Invalid output format: expected at least 2 values, got {}",
                output_line_parts.len()
            );
        }

        let num_output_groups = usize::from_str(output_line_parts[0])
            .context("Failed to parse number of output groups")?;

        if output_line_parts.len() != num_output_groups + 1 {
            bail!(
                "Invalid output format: expected {} output group sizes, got {}",
                num_output_groups,
                output_line_parts.len() - 1
            );
        }

        let mut output_group_sizes = Vec::with_capacity(num_output_groups);
        for i in 0..num_output_groups {
            output_group_sizes.push(
                usize::from_str(output_line_parts[i + 1])
                    .context(format!("Failed to parse output group size {}", i))?,
            );
        }

        // Calculate input wire indices
        let mut input_wires = Vec::new();
        let mut current_wire = 0;
        for &size in &input_group_sizes {
            for _ in 0..size {
                input_wires.push(current_wire);
                current_wire += 1;
            }
        }

        // Calculate output wire indices
        let mut output_wires = Vec::new();
        let mut total_outputs = 0;
        for &size in &output_group_sizes {
            total_outputs += size;
        }

        // In Bristol Fashion, output wires are the last wires in the circuit
        for i in 0..total_outputs {
            output_wires.push(num_wires - total_outputs + i);
        }

        // Parse gates - starting from line 4 (or after an empty line)
        let mut gate_start_index = 3;
        while gate_start_index < lines.len() && lines[gate_start_index].trim().is_empty() {
            gate_start_index += 1;
        }

        let mut gates = Vec::with_capacity(num_gates);

        // Start parsing gates from the appropriate line
        for i in gate_start_index..lines.len() {
            let line = &lines[i];
            if line.trim().is_empty() {
                continue; // Skip empty lines
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                bail!("Line {} is too short to be a gate: {}", i + 1, line);
            }

            // Parse gate according to Bristol Fashion format:
            // <num_inputs> <num_outputs> <input1> [input2] <output> <gate_type>

            // Parse number of inputs
            let num_inputs = match usize::from_str(parts[0]) {
                Ok(n) => n,
                Err(e) => bail!("Line {}: Failed to parse number of inputs: {}", i + 1, e),
            };

            // Parse number of outputs
            let num_outputs = match usize::from_str(parts[1]) {
                Ok(n) => n,
                Err(e) => bail!("Line {}: Failed to parse number of outputs: {}", i + 1, e),
            };

            // Check if we have enough parts for this gate
            let expected_parts = 3 + num_inputs + num_outputs;
            if parts.len() != expected_parts {
                bail!(
                    "Line {}: Invalid gate format: expected {} parts, got {}",
                    i + 1,
                    expected_parts,
                    parts.len()
                );
            }

            // Get gate type (last part)
            let gate_type = parts[parts.len() - 1];

            // Parse input wire indices
            let mut input_indices = Vec::with_capacity(num_inputs);
            for j in 0..num_inputs {
                match usize::from_str(parts[2 + j]) {
                    Ok(idx) => input_indices.push(idx),
                    Err(e) => bail!(
                        "Line {}: Failed to parse input wire index {}: {}",
                        i + 1,
                        j,
                        e
                    ),
                }
            }

            // Parse output wire index (only supporting single output gates for now)
            if num_outputs != 1 {
                bail!(
                    "Line {}: Only single output gates are supported, got {} outputs",
                    i + 1,
                    num_outputs
                );
            }

            let output_index = match usize::from_str(parts[2 + num_inputs]) {
                Ok(idx) => idx,
                Err(e) => bail!("Line {}: Failed to parse output wire index: {}", i + 1, e),
            };

            // Create gate based on type
            match gate_type {
                "XOR" => {
                    if num_inputs != 2 {
                        bail!(
                            "Line {}: XOR gate must have 2 inputs, got {}",
                            i + 1,
                            num_inputs
                        );
                    }
                    gates.push(BristolGate::Xor {
                        inputs: input_indices.clone(),
                        output: output_index,
                    });
                }
                "AND" => {
                    if num_inputs != 2 {
                        bail!(
                            "Line {}: AND gate must have 2 inputs, got {}",
                            i + 1,
                            num_inputs
                        );
                    }
                    gates.push(BristolGate::And {
                        inputs: input_indices.clone(),
                        output: output_index,
                    });
                }
                "INV" => {
                    if num_inputs != 1 {
                        bail!(
                            "Line {}: INV gate must have 1 input, got {}",
                            i + 1,
                            num_inputs
                        );
                    }
                    gates.push(BristolGate::Inv {
                        input: input_indices[0],
                        output: output_index,
                    });
                }
                _ => {
                    bail!("Line {}: Unsupported gate type: {}", i + 1, gate_type);
                }
            }
        }

        // Verify we parsed the expected number of gates
        if gates.len() != num_gates {
            bail!(
                "Number of gates mismatch: expected {}, got {}",
                num_gates,
                gates.len()
            );
        }

        Ok(BristolCircuit {
            num_gates,
            num_wires,
            num_input_groups,
            input_group_sizes,
            num_output_groups,
            output_group_sizes,
            gates,
            input_wires,
            output_wires,
        })
    }
}

impl SieveCircuit {
    /// Convert a Bristol Fashion circuit to SIEVE IR
    pub fn from_bristol(bristol: &BristolCircuit) -> Result<Self> {
        // Create a new SIEVE IR circuit
        let mut sieve_gates = Vec::new();

        // Create private inputs for all Bristol inputs
        let mut input_wires = Vec::new();
        let mut current_wire = 0;
        for _ in &bristol.input_wires {
            input_wires.push(current_wire);
            sieve_gates.push(SieveGate::Private {
                output: current_wire,
                party: 0,
            });
            current_wire += 1;
        }

        // Create a mapping from Bristol wire indices to SIEVE IR wire indices
        let mut wire_map = HashMap::new();

        // Map input wires
        for (i, &input_wire) in bristol.input_wires.iter().enumerate() {
            wire_map.insert(input_wire, input_wires[i]);
        }

        let mut next_wire_id = current_wire;

        // Map all gate output wires to new unique IDs
        for gate in &bristol.gates {
            match gate {
                BristolGate::Xor { output, .. }
                | BristolGate::And { output, .. }
                | BristolGate::Inv { output, .. } => {
                    // Check if this output wire ID is already mapped (e.g., it's an input wire)
                    if !wire_map.contains_key(output) {
                        wire_map.insert(*output, next_wire_id);
                        next_wire_id += 1;
                    }
                }
            }
        }

        // Second pass: create gates with proper wire mappings
        for gate in &bristol.gates {
            match gate {
                BristolGate::Xor { inputs, output } => {
                    // Map inputs to SIEVE IR wire indices
                    let sieve_inputs = inputs
                        .iter()
                        .map(|&input| *wire_map.get(&input).expect("Wire ID should be mapped"))
                        .collect();

                    // Get the mapped output wire ID
                    let sieve_output = *wire_map
                        .get(output)
                        .expect("Output wire ID should be mapped");

                    // Create an add gate
                    sieve_gates.push(SieveGate::Add {
                        inputs: sieve_inputs,
                        output: sieve_output,
                    });
                }
                BristolGate::And { inputs, output } => {
                    // Map inputs to SIEVE IR wire indices
                    let sieve_inputs = inputs
                        .iter()
                        .map(|&input| *wire_map.get(&input).expect("Wire ID should be mapped"))
                        .collect();

                    // Get the mapped output wire ID
                    let sieve_output = *wire_map
                        .get(output)
                        .expect("Output wire ID should be mapped");

                    // Create a mul gate
                    sieve_gates.push(SieveGate::Mul {
                        inputs: sieve_inputs,
                        output: sieve_output,
                    });
                }
                BristolGate::Inv { input, output } => {
                    // Map input to SIEVE IR wire index
                    let sieve_input = *wire_map.get(input).expect("Wire ID should be mapped");

                    // Get the mapped output wire ID
                    let sieve_output = *wire_map
                        .get(output)
                        .expect("Output wire ID should be mapped");

                    // Create an addc gate with constant 1
                    sieve_gates.push(SieveGate::AddConstant {
                        input: sieve_input,
                        constant: 1,
                        output: sieve_output,
                    });
                }
            }
        }

        // Map output wires
        let output_wires = bristol
            .output_wires
            .iter()
            .map(|&output_wire| {
                *wire_map
                    .get(&output_wire)
                    .expect("Output wire ID should be mapped")
            })
            .collect();

        Ok(SieveCircuit {
            gates: sieve_gates,
            input_wires,
            output_wires,
        })
    }

    /// Generate SIEVE IR text representation
    pub fn to_string(&self) -> String {
        let mut result = String::new();

        // Add header
        result.push_str("version 2.0.0;\n");
        result.push_str("circuit;\n");
        result.push_str("@type field 2;\n");
        result.push_str("@begin\n");

        // Add gates
        for gate in &self.gates {
            result.push_str(&format!("  {}\n", gate));
        }

        // Add footer
        result.push_str("@end\n");

        result
    }

    /// Write SIEVE IR to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut file = File::create(path).context("Failed to create SIEVE IR output file")?;
        file.write_all(self.to_string().as_bytes())
            .context("Failed to write SIEVE IR to file")?;
        Ok(())
    }
}

/// Transpile a Bristol Fashion circuit to SIEVE IR
pub fn transpile<P: AsRef<Path>, Q: AsRef<Path>>(input_path: P, output_path: Q) -> Result<()> {
    // Parse Bristol Fashion circuit
    let bristol = BristolCircuit::from_file(input_path)?;

    // Convert to SIEVE IR
    let sieve = SieveCircuit::from_bristol(&bristol)?;

    // Write SIEVE IR to file
    sieve.to_file(output_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_to_add_conversion() {
        let bristol_str = r#"1 5
2 1 1
1 1
2 1 0 1 4 XOR"#;
        let bristol = BristolCircuit::from_str(bristol_str).unwrap();

        let sieve = SieveCircuit::from_bristol(&bristol).unwrap();

        // Verify the XOR gate was converted to an Add gate
        let mut found_add_gate = false;
        for gate in &sieve.gates {
            if let SieveGate::Add { inputs, output } = gate {
                if *output == 2 && inputs.contains(&0) && inputs.contains(&1) {
                    found_add_gate = true;
                    break;
                }
            }
        }

        assert!(
            found_add_gate,
            "XOR gate was not properly converted to Add gate"
        );

        // Verify the SIEVE IR text representation contains the Add gate
        let sieve_text = sieve.to_string();
        println!("{:?}", sieve_text);
        assert!(
            sieve_text.contains("$2 <- @add(0: $0, $1);"),
            "SIEVE IR text does not contain the expected Add gate"
        );
    }

    #[test]
    fn test_and_to_mul_conversion() {
        let bristol_str = r#"1 5
2 1 1
1 1
2 1 0 1 4 AND"#;

        let bristol = BristolCircuit::from_str(bristol_str).unwrap();

        let sieve = SieveCircuit::from_bristol(&bristol).unwrap();

        // Verify the AND gate was converted to a Mul gate
        let mut found_mul_gate = false;
        for gate in &sieve.gates {
            if let SieveGate::Mul { inputs, output } = gate {
                if *output == 2 && inputs.contains(&0) && inputs.contains(&1) {
                    found_mul_gate = true;
                    break;
                }
            }
        }

        assert!(
            found_mul_gate,
            "AND gate was not properly converted to Mul gate"
        );

        // Verify the SIEVE IR text representation contains the Mul gate
        let sieve_text = sieve.to_string();
        assert!(
            sieve_text.contains("$2 <- @mul(0: $0, $1);"),
            "SIEVE IR text does not contain the expected Mul gate"
        );
    }

    #[test]
    fn test_inv_to_addc_conversion() {
        let bristol_str = r#"1 4
1 1
1 1
1 1 0 3 INV"#;

        let bristol = BristolCircuit::from_str(bristol_str).unwrap();

        let sieve = SieveCircuit::from_bristol(&bristol).unwrap();
        let sieve_text = sieve.to_string();

        // Verify the INV gate was converted to an AddConstant gate with constant 1
        let mut found_inv_conversion = false;
        for gate in &sieve.gates {
            if let SieveGate::AddConstant {
                input,
                constant,
                output,
            } = gate
            {
                if *output == 1 && *input == 0 && *constant == 1 {
                    found_inv_conversion = true;
                    break;
                }
            }
        }

        assert!(
            found_inv_conversion,
            "INV gate was not properly converted to AddConstant gate with constant 1"
        );

        // Verify the SIEVE IR text representation contains the AddConstant gate for INV
        assert!(
            sieve_text.contains("$1 <- @addc(0: $0, < 1 >);"),
            "SIEVE IR text does not contain the expected AddConstant gate for INV conversion"
        );
    }

    #[test]
    fn test_parse_simple_circuit() {
        let bristol_str = r#"3 7
2 1 1
1 1
2 1 0 1 4 XOR
2 1 0 1 5 AND
1 1 1 6 INV"#;

        let circuit = BristolCircuit::from_str(bristol_str).unwrap();

        assert_eq!(circuit.num_gates, 3);
        assert_eq!(circuit.num_wires, 7);
        assert_eq!(circuit.num_input_groups, 2);
        assert_eq!(circuit.input_group_sizes, vec![1, 1]);
        assert_eq!(circuit.num_output_groups, 1);
        assert_eq!(circuit.output_group_sizes, vec![1]);
        assert_eq!(circuit.input_wires, vec![0, 1]);
        assert_eq!(circuit.output_wires, vec![6]);
        assert_eq!(circuit.gates.len(), 3);
    }

    #[test]
    fn test_convert_to_sieve() {
        let bristol_str = r#"3 7
2 1 1
1 1
2 1 0 1 4 XOR
2 1 0 1 5 AND
1 1 1 6 INV"#;

        let bristol = BristolCircuit::from_str(bristol_str).unwrap();
        let sieve = SieveCircuit::from_bristol(&bristol).unwrap();

        assert_eq!(sieve.input_wires, vec![0, 1]);
        assert_eq!(sieve.output_wires, vec![4]);

        // Check the SIEVE IR text representation
        let sieve_text = sieve.to_string();
        assert!(sieve_text.contains("version 2.0.0;"));
        assert!(sieve_text.contains("@type field 2;"));
        assert!(sieve_text.contains("$0 <- @private(0);"));
        assert!(sieve_text.contains("$1 <- @private(0);"));
        assert!(sieve_text.contains("$2 <- @add(0: $0, $1);"));
        assert!(sieve_text.contains("$3 <- @mul(0: $0, $1);"));
        assert!(sieve_text.contains("$4 <- @addc(0: $1, < 1 >);"));
    }

    #[test]
    fn test_write_to_file() {
        let bristol_str = r#"3 7
2 1 1
1 1
2 1 0 1 4 XOR
2 1 0 1 5 AND
1 1 1 6 INV"#;

        let bristol = BristolCircuit::from_str(bristol_str).unwrap();

        let sieve = SieveCircuit::from_bristol(&bristol).unwrap();

        let output_path = "output/test_sieve.txt";
        sieve.to_file(output_path).unwrap();
        assert!(std::path::Path::new(output_path).exists());

        let content = std::fs::read_to_string(output_path).unwrap();
        assert!(content.contains("version 2.0.0;"));
        assert!(content.contains("circuit;"));
        assert!(content.contains("@type field 2;"));
        assert!(content.contains("@begin"));
        assert!(content.contains("$0 <- @private(0);"));
        assert!(content.contains("$1 <- @private(0);"));
        assert!(content.contains("$2 <- @add(0: $0, $1);"));
        assert!(content.contains("$3 <- @mul(0: $0, $1);"));
        assert!(content.contains("$4 <- @addc(0: $1, < 1 >);"));
        assert!(content.contains("@end"));

        std::fs::remove_file(output_path).unwrap();
    }

    #[test]
    fn test_transpile_function() {
        let bristol_str = r#"3 7
2 1 1
1 1
2 1 0 1 4 XOR
2 1 0 1 5 AND
1 1 1 6 INV"#;

        let temp_dir = tempfile::tempdir().unwrap();
        let input_path = temp_dir.path().join("test_bristol_input.txt");
        let output_path = temp_dir.path().join("test_sieve_output.txt");
        std::fs::write(&input_path, bristol_str).unwrap();

        transpile(&input_path, &output_path).unwrap();
        assert!(std::path::Path::new(&output_path).exists());

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("version 2.0.0;"));
        assert!(content.contains("circuit;"));
        assert!(content.contains("@type field 2;"));
        assert!(content.contains("@begin"));
        assert!(content.contains("$0 <- @private(0);"));
        assert!(content.contains("$1 <- @private(0);"));
        assert!(content.contains("$2 <- @add(0: $0, $1);"));
        assert!(content.contains("$3 <- @mul(0: $0, $1);"));
        assert!(content.contains("$4 <- @addc(0: $1, < 1 >);"));
        assert!(content.contains("@end"));

        std::fs::remove_file(input_path).unwrap();
        std::fs::remove_file(output_path).unwrap();
    }

    #[test]
    fn test_with_keccak_f_circuit() {
        let input_path = "../bristol-fashion/circuits/Keccak_f.txt";
        let output_path = "output/test_keccak_f_sieve.txt";
        let bristol =
            BristolCircuit::from_file(input_path).expect("Failed to parse Keccak_f circuit");

        assert_eq!(bristol.num_gates, 192086, "Incorrect number of gates");
        assert_eq!(bristol.num_wires, 193686, "Incorrect number of wires");
        assert_eq!(
            bristol.input_group_sizes,
            vec![1600],
            "Incorrect input group sizes"
        );

        let sieve = SieveCircuit::from_bristol(&bristol).expect("Failed to convert to SIEVE IR");
        assert_eq!(
            sieve.input_wires.len(),
            1600,
            "Should have 1600 input wires"
        );

        sieve
            .to_file(output_path)
            .expect("Failed to write SIEVE IR to file");
        assert!(
            std::path::Path::new(output_path).exists(),
            "Output file was not created"
        );

        let content = std::fs::read_to_string(output_path).expect("Failed to read output file");
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

        // Verify the constant 1 wire is defined
        assert!(
            content.contains("$0 <- @private(0);"),
            "Missing constant 1 wire definition"
        );

        // Verify at least one gate of each type exists in the output
        let has_add_gate = content.contains("@add");
        let has_mul_gate = content.contains("@mul");

        assert!(has_add_gate, "No add gates found in output");
        assert!(has_mul_gate, "No mul gates found in output");

        std::fs::remove_file(output_path).expect("Failed to remove test output file");

        println!("Successfully tested transpiler with Keccak_f circuit");
    }
}
