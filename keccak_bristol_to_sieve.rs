use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// Bristol Fashion gate types
enum BristolGate {
    XOR { a: u64, b: u64, out: u64 },
    AND { a: u64, b: u64, out: u64 },
    INV { a: u64, out: u64 },
    EQ { lit: bool, out: u64 },
    EQW { a: u64, out: u64 },
}

// Function to parse Bristol Fashion circuit
fn parse_bristol_circuit(
    path: &Path,
) -> Result<(Vec<u64>, Vec<u64>, Vec<BristolGate>), Box<dyn Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    // Parse header
    let header = lines.next().ok_or("Empty file")??;
    let parts: Vec<&str> = header.split_whitespace().collect();
    let ngates: u64 = parts[0].parse()?;
    let nwires: u64 = parts[1].parse()?;

    // Parse input sizes
    let input_line = lines.next().ok_or("Missing input line")??;
    let parts: Vec<&str> = input_line.split_whitespace().collect();
    let ninputs: u64 = parts[0].parse()?;
    let mut input_sizes = Vec::new();
    for i in 0..ninputs as usize {
        input_sizes.push(parts[i + 1].parse()?);
    }

    // Parse output sizes
    let output_line = lines.next().ok_or("Missing output line")??;
    let parts: Vec<&str> = output_line.split_whitespace().collect();
    let noutputs: u64 = parts[0].parse()?;
    let mut output_sizes = Vec::new();
    for i in 0..noutputs as usize {
        output_sizes.push(parts[i + 1].parse()?);
    }

    // Skip empty line
    lines.next();

    // Parse gates
    let mut gates = Vec::new();
    for _ in 0..ngates {
        let line = lines.next().ok_or("Not enough gates")??;
        let parts: Vec<&str> = line.split_whitespace().collect();
        let gate_type = parts.last().ok_or("Invalid gate format")?;

        match *gate_type {
            "XOR" => {
                let in_arity: u64 = parts[0].parse()?;
                let out_arity: u64 = parts[1].parse()?;
                if in_arity != 2 || out_arity != 1 {
                    return Err("Invalid XOR gate format".into());
                }
                let a: u64 = parts[2].parse()?;
                let b: u64 = parts[3].parse()?;
                let out: u64 = parts[4].parse()?;
                gates.push(BristolGate::XOR { a, b, out });
            }
            "AND" => {
                let in_arity: u64 = parts[0].parse()?;
                let out_arity: u64 = parts[1].parse()?;
                if in_arity != 2 || out_arity != 1 {
                    return Err("Invalid AND gate format".into());
                }
                let a: u64 = parts[2].parse()?;
                let b: u64 = parts[3].parse()?;
                let out: u64 = parts[4].parse()?;
                gates.push(BristolGate::AND { a, b, out });
            }
            "INV" => {
                let in_arity: u64 = parts[0].parse()?;
                let out_arity: u64 = parts[1].parse()?;
                if in_arity != 1 || out_arity != 1 {
                    return Err("Invalid INV gate format".into());
                }
                let a: u64 = parts[2].parse()?;
                let out: u64 = parts[3].parse()?;
                gates.push(BristolGate::INV { a, out });
            }
            "EQ" => {
                let in_arity: u64 = parts[0].parse()?;
                let out_arity: u64 = parts[1].parse()?;
                if in_arity != 1 || out_arity != 1 {
                    return Err("Invalid EQ gate format".into());
                }
                let lit: bool = parts[2].parse::<u8>()? == 1;
                let out: u64 = parts[3].parse()?;
                gates.push(BristolGate::EQ { lit, out });
            }
            "EQW" => {
                let in_arity: u64 = parts[0].parse()?;
                let out_arity: u64 = parts[1].parse()?;
                if in_arity != 1 || out_arity != 1 {
                    return Err("Invalid EQW gate format".into());
                }
                let a: u64 = parts[2].parse()?;
                let out: u64 = parts[3].parse()?;
                gates.push(BristolGate::EQW { a, out });
            }
            _ => return Err(format!("Unknown gate type: {}", gate_type).into()),
        }
    }

    Ok((input_sizes, output_sizes, gates))
}

// Function to convert Bristol Fashion circuit to SIEVE IR
fn convert_to_sieve_ir(
    input_sizes: &[u64],
    output_sizes: &[u64],
    gates: &[BristolGate],
    output_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut output = File::create(output_path)?;

    // Write SIEVE IR header
    writeln!(output, "version 2.0.0;")?;
    writeln!(output, "circuit;")?;

    // Define field type (F2 for binary circuits)
    writeln!(output, "@type field 2;")?;

    // Begin circuit definition
    writeln!(output, "@begin")?;

    // Define main function
    let total_input_size: u64 = input_sizes.iter().sum();
    let total_output_size: u64 = output_sizes.iter().sum();

    writeln!(
        output,
        "    @function(keccak_f, @out: 0:{}, @in: 0:{})",
        total_output_size, total_input_size
    )?;

    // Allocate wires
    let max_wire = gates.iter().fold(0, |max, gate| match gate {
        BristolGate::XOR { a, b, out } => *out.max(a).max(b),
        BristolGate::AND { a, b, out } => *out.max(a).max(b),
        BristolGate::INV { a, out } => *out.max(a),
        BristolGate::EQ { out, .. } => *out,
        BristolGate::EQW { a, out } => *out.max(a),
    });

    // Map input wires
    let mut input_map = Vec::new();
    let mut current_wire = 0;
    for &size in input_sizes {
        for i in 0..size {
            input_map.push(current_wire + i);
        }
        current_wire += size;
    }

    // Map output wires
    let mut output_map = Vec::new();
    let mut current_wire = 0;
    for &size in output_sizes {
        for i in 0..size {
            output_map.push(current_wire + i);
        }
        current_wire += size;
    }

    // Convert gates to SIEVE IR
    for gate in gates {
        match gate {
            BristolGate::XOR { a, b, out } => {
                // XOR in F2 is equivalent to addition
                writeln!(output, "        ${} <- @add(${},${}); // XOR", out, a, b)?;
            }
            BristolGate::AND { a, b, out } => {
                // AND in F2 is equivalent to multiplication
                writeln!(output, "        ${} <- @mul(${},${}); // AND", out, a, b)?;
            }
            BristolGate::INV { a, out } => {
                // INV in F2 is equivalent to adding 1
                writeln!(output, "        ${} <- @addc(${},$<1>); // INV", out, a)?;
            }
            BristolGate::EQ { lit, out } => {
                // EQ sets a constant value
                let value = if *lit { 1 } else { 0 };
                writeln!(
                    output,
                    "        ${} <- 0:<{}>; // Constant {}",
                    out, value, value
                )?;
            }
            BristolGate::EQW { a, out } => {
                // EQW copies a wire
                writeln!(output, "        ${} <- ${}; // Copy", out, a)?;
            }
        }
    }

    // Map outputs
    for (i, &out_wire) in output_map.iter().enumerate() {
        writeln!(output, "        ${} <- ${};", i, out_wire)?;
    }

    // End function and circuit
    writeln!(output, "    @end")?;
    writeln!(output, "@end")?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // Path to Bristol Fashion circuit
    let bristol_path = Path::new("bristol-fashion/circuits/Keccak_f.txt");

    // Path for output SIEVE IR circuit
    let sieve_path = Path::new("keccak_f.sieve");

    // Parse Bristol Fashion circuit
    let (input_sizes, output_sizes, gates) = parse_bristol_circuit(bristol_path)?;

    // Convert to SIEVE IR
    convert_to_sieve_ir(&input_sizes, &output_sizes, &gates, sieve_path)?;

    println!(
        "Conversion complete. SIEVE IR circuit written to {}",
        sieve_path.display()
    );

    Ok(())
}
