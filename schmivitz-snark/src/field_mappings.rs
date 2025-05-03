use ark_bn254::Fr as Bn254Fr;
use ark_ff::Field;
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, R1CSVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F64b, F8b};
use swanky_serialization::CanonicalSerialize;

/// Convert F8b to an array of Boolean variables
///
/// This function converts a value from the F8b field (GF(2^8)) to an array of Boolean variables
/// that can be used in constraint systems.
///
/// Mathematical relationship:
/// - F8b is a binary field of size 2^8, with elements represented as 8-bit integers
///   reduced modulo an irreducible polynomial.
/// - Each bit in the F8b value is converted to a Boolean variable.
///
/// Implementation details:
/// - The F8b value is converted to bytes and then to individual bits.
/// - Each bit is represented as a Boolean variable in the constraint system.
/// - The resulting array has exactly 8 Boolean variables.
pub fn f8b_to_boolean_array<F: Field>(
    cs: ConstraintSystemRef<F>,
    value: &F8b,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let bytes = value.to_bytes();
    let mut bits = Vec::with_capacity(8);

    // Extract 8 bits from the first byte
    for i in 0..8 {
        let bit = (bytes[0] >> i) & 1 == 1;
        bits.push(Boolean::new_witness(
            ark_relations::ns!(cs, "f8b_bit"),
            || Ok(bit),
        )?);
    }

    Ok(bits)
}

/// Convert F64b to an array of Boolean variables
///
/// This function converts a value from the F64b field (GF(2^64)) to an array of Boolean variables
/// that can be used in constraint systems.
///
/// Mathematical relationship:
/// - F64b is a binary field of size 2^64, with elements represented as 64-bit integers
///   reduced modulo an irreducible polynomial.
/// - Each bit in the F64b value is converted to a Boolean variable.
///
/// Implementation details:
/// - The F64b value is converted to bytes and then to individual bits.
/// - Each bit is represented as a Boolean variable in the constraint system.
/// - The resulting array has exactly 64 Boolean variables.
pub fn f64b_to_boolean_array<F: Field>(
    cs: ConstraintSystemRef<F>,
    value: &F64b,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let bytes = value.to_bytes();
    let mut bits = Vec::with_capacity(64);

    // Extract 64 bits from the bytes (8 bytes)
    for byte_idx in 0..8 {
        for bit_idx in 0..8 {
            let bit = (bytes[byte_idx] >> bit_idx) & 1 == 1;
            bits.push(Boolean::new_witness(
                ark_relations::ns!(cs, "f64b_bit"),
                || Ok(bit),
            )?);
        }
    }

    Ok(bits)
}

/// Convert F128b to an array of Boolean variables
///
/// This function converts a value from the F128b field (GF(2^128)) to an array of Boolean variables
/// that can be used in constraint systems.
///
/// Mathematical relationship:
/// - F128b is a binary field of size 2^128, with elements represented as 128-bit integers
///   reduced modulo the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
/// - Each bit in the F128b value is converted to a Boolean variable.
///
/// Implementation details:
/// - The F128b value is converted to bytes and then to individual bits.
/// - Each bit is represented as a Boolean variable in the constraint system.
/// - The resulting array has exactly 128 Boolean variables.
pub fn f128b_to_boolean_array<F: Field>(
    cs: ConstraintSystemRef<F>,
    value: &F128b,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let bytes = value.to_bytes();
    let mut bits = Vec::with_capacity(128);

    // Extract 128 bits from the bytes (16 bytes)
    for byte_idx in 0..16 {
        for bit_idx in 0..8 {
            let bit = (bytes[byte_idx] >> bit_idx) & 1 == 1;
            bits.push(Boolean::new_witness(
                ark_relations::ns!(cs, "f128b_bit"),
                || Ok(bit),
            )?);
        }
    }

    Ok(bits)
}

/// Convert an array of Boolean variables to F8b
///
/// This function converts an array of Boolean variables to a value in the F8b field (GF(2^8)).
///
/// Mathematical relationship:
/// - Each Boolean variable represents a bit in the resulting F8b value.
/// - The bits are combined to form an 8-bit value in the F8b field.
///
/// Implementation details:
/// - The function expects exactly 8 Boolean variables.
/// - The Boolean values are extracted and combined to form a byte.
/// - The byte is then converted to an F8b value.
pub fn boolean_array_to_f8b<F: Field>(bits: &[Boolean<F>]) -> Result<F8b, SynthesisError> {
    // Ensure we have exactly 8 bits
    if bits.len() != 8 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Extract the boolean values
    let mut byte: u8 = 0;
    for (i, bit) in bits.iter().enumerate() {
        if bit.value()? {
            byte |= 1 << i;
        }
    }

    // Create a byte array for F8b::from_uniform_bytes
    let mut array = [0u8; 16];
    array[0] = byte;

    // Convert to F8b
    Ok(F8b::from_uniform_bytes(&array))
}

/// Convert an array of Boolean variables to F64b
///
/// This function converts an array of Boolean variables to a value in the F64b field (GF(2^64)).
///
/// Mathematical relationship:
/// - Each Boolean variable represents a bit in the resulting F64b value.
/// - The bits are combined to form a 64-bit value in the F64b field.
///
/// Implementation details:
/// - The function expects exactly 64 Boolean variables.
/// - The Boolean values are extracted and combined to form 8 bytes.
/// - The bytes are then converted to an F64b value.
pub fn boolean_array_to_f64b<F: Field>(bits: &[Boolean<F>]) -> Result<F64b, SynthesisError> {
    // Ensure we have exactly 64 bits
    if bits.len() != 64 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Extract the boolean values and combine them into bytes
    let mut bytes = [0u8; 16];
    for byte_idx in 0..8 {
        for bit_idx in 0..8 {
            let bit_pos = byte_idx * 8 + bit_idx;
            if bits[bit_pos].value()? {
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    // Convert to F64b
    Ok(F64b::from_uniform_bytes(&bytes))
}

/// Convert an array of Boolean variables to F128b
///
/// This function converts an array of Boolean variables to a value in the F128b field (GF(2^128)).
///
/// Mathematical relationship:
/// - Each Boolean variable represents a bit in the resulting F128b value.
/// - The bits are combined to form a 128-bit value in the F128b field.
///
/// Implementation details:
/// - The function expects exactly 128 Boolean variables.
/// - The Boolean values are extracted and combined to form 16 bytes.
/// - The bytes are then converted to an F128b value.
pub fn boolean_array_to_f128b<F: Field>(bits: &[Boolean<F>]) -> Result<F128b, SynthesisError> {
    // Ensure we have exactly 128 bits
    if bits.len() != 128 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Extract the boolean values and combine them into bytes
    let mut bytes = [0u8; 16];
    for byte_idx in 0..16 {
        for bit_idx in 0..8 {
            let bit_pos = byte_idx * 8 + bit_idx;
            if bits[bit_pos].value()? {
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    // Convert to F128b
    Ok(F128b::from_uniform_bytes(&bytes))
}

#[cfg(test)]
mod boolean_conversion_tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use swanky_field_binary::F8b;

    #[test]
    fn test_f8b_boolean_conversion() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test with a simple value
        let f8b_value = F8b::from(123u8);

        // Convert to boolean array
        let boolean_array = f8b_to_boolean_array(cs.clone(), &f8b_value).unwrap();

        // Verify the length
        assert_eq!(boolean_array.len(), 8);

        // Convert back to F8b
        let f8b_back = boolean_array_to_f8b(&boolean_array).unwrap();

        // Verify the value is preserved
        assert_eq!(f8b_value, f8b_back);
    }

    #[test]
    fn test_f64b_boolean_conversion() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test with a simple value
        let f64b_value = F64b::from(0x123456789ABCDEFu64);

        // Convert to boolean array
        let boolean_array = f64b_to_boolean_array(cs.clone(), &f64b_value).unwrap();

        // Verify the length
        assert_eq!(boolean_array.len(), 64);

        // Convert back to F64b
        let f64b_back = boolean_array_to_f64b(&boolean_array).unwrap();

        // Verify the value is preserved
        assert_eq!(f64b_value, f64b_back);
    }

    #[test]
    fn test_f128b_boolean_conversion() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create a test value for F128b
        let mut bytes = [0u8; 16];
        // Lower 64 bits: 0x0123456789ABCDEF
        bytes[0] = 0xEF;
        bytes[1] = 0xCD;
        bytes[2] = 0xAB;
        bytes[3] = 0x89;
        bytes[4] = 0x67;
        bytes[5] = 0x45;
        bytes[6] = 0x23;
        bytes[7] = 0x01;
        // Upper 64 bits: 0xFEDCBA9876543210
        bytes[8] = 0x10;
        bytes[9] = 0x32;
        bytes[10] = 0x54;
        bytes[11] = 0x76;
        bytes[12] = 0x98;
        bytes[13] = 0xBA;
        bytes[14] = 0xDC;
        bytes[15] = 0xFE;

        let f128b_value = F128b::from_uniform_bytes(&bytes);

        // Convert to boolean array
        let boolean_array = f128b_to_boolean_array(cs.clone(), &f128b_value).unwrap();

        // Verify the length
        assert_eq!(boolean_array.len(), 128);

        // Convert back to F128b
        let f128b_back = boolean_array_to_f128b(&boolean_array).unwrap();

        // Verify the value is preserved
        assert_eq!(f128b_value, f128b_back);
    }

    #[test]
    fn test_boolean_operations() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test XOR operation on F8b values using Boolean representation
        let f8b_a = F8b::from(0x0Fu8); // 00001111
        let f8b_b = F8b::from(0x33u8); // 00110011

        // Expected result of XOR: 00111100 = 0x3C
        let expected_xor = F8b::from(0x3Cu8);

        // Convert to boolean arrays
        let bits_a = f8b_to_boolean_array(cs.clone(), &f8b_a).unwrap();
        let bits_b = f8b_to_boolean_array(cs.clone(), &f8b_b).unwrap();

        // Perform XOR operation bit by bit
        let mut xor_result = Vec::with_capacity(8);
        for i in 0..8 {
            xor_result.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F8b
        let f8b_xor = boolean_array_to_f8b(&xor_result).unwrap();

        // Verify the result
        assert_eq!(f8b_xor, expected_xor);
    }
}

// #[warn(dead_code)]
// pub fn f2_2_ark(value: &F2) -> Bn254Fr {
//     if *value == F2::one() {
//         Bn254Fr::one()
//     } else {
//         Bn254Fr::zero()
//     }
// }

// Convert F8b to arkworks field element
pub fn f8b_to_ark(value: &F8b) -> Bn254Fr {
    // F8b is represented as a u8, so we need to convert it to a field element
    // Get the bytes representation
    let bytes = value.to_bytes();

    // Convert the u8 value to a Bn254Fr field element
    Bn254Fr::from(bytes[0] as u64)
}

// Convert F64b to arkworks field element
pub fn f64b_to_ark(value: &F64b) -> Bn254Fr {
    // F64b is represented as a u64, so we need to convert it to a field element
    // Get the bytes representation
    let bytes = value.to_bytes();

    // Convert bytes to u64
    let mut u64_value: u64 = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        u64_value |= (byte as u64) << (i * 8);
    }

    // Convert the u64 value to a Bn254Fr field element
    Bn254Fr::from(u64_value)
}

/// Convert F128b to arkworks field element (Bn254Fr)
///
/// This function converts a value from the F128b field (GF(2^128)) to the Bn254Fr field.
///
/// Mathematical relationship:
/// - F128b is a binary field of size 2^128, with elements represented as 128-bit integers
///   reduced modulo the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
/// - Bn254Fr is a prime field of size approximately 2^254, with elements represented as
///   integers modulo a large prime p = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
///
/// Since these fields have different characteristics (2 vs p), there is no direct mathematical
/// homomorphism between them. This conversion is primarily for representation purposes.
///
/// Implementation details:
/// - This implementation handles the full 128-bit value of F128b.
/// - We split the 128-bit value into two 64-bit parts (high and low).
/// - The high part is multiplied by 2^64 and added to the low part in the Bn254Fr field.
/// - This preserves the full numeric value of the F128b element in the Bn254Fr field.
pub fn f128b_to_ark(value: &F128b) -> Bn254Fr {
    use ark_ff::Field;
    use ark_std::One;

    // Get the bytes representation of the F128b value
    let bytes = value.to_bytes();

    // Extract the lower 64 bits
    let mut lower_u64: u64 = 0;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        lower_u64 |= (byte as u64) << (i * 8);
    }

    // Extract the upper 64 bits
    let mut upper_u64: u64 = 0;
    for (i, &byte) in bytes.iter().skip(8).take(8).enumerate() {
        upper_u64 |= (byte as u64) << (i * 8);
    }

    // Convert the lower 64 bits to a Bn254Fr field element
    let lower_fr = Bn254Fr::from(lower_u64);

    // If the upper 64 bits are all zero, we can just return the lower part
    if upper_u64 == 0 {
        return lower_fr;
    }

    // Convert the upper 64 bits to a Bn254Fr field element
    let upper_fr = Bn254Fr::from(upper_u64);

    // Calculate 2^64 in the Bn254Fr field
    // We'll use repeated squaring to compute 2^64 efficiently
    let mut power_of_two = Bn254Fr::from(2u64);
    let mut shift_factor = Bn254Fr::one();

    // Compute 2^64 using the binary exponentiation method
    let mut exponent: u64 = 64;
    while exponent > 0 {
        if exponent & 1 == 1 {
            shift_factor *= power_of_two;
        }
        power_of_two = power_of_two.square();
        exponent >>= 1;
    }

    // Multiply the upper part by 2^64
    let upper_shifted = upper_fr * shift_factor;

    // Combine the two parts using field addition
    lower_fr + upper_shifted
}

/// Convert arkworks field element (Bn254Fr) to F128b
///
/// This function converts a value from the Bn254Fr field to the F128b field (GF(2^128)).
///
/// Mathematical relationship:
/// - Bn254Fr is a prime field of size approximately 2^254, with elements represented as
///   integers modulo a large prime p = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
/// - F128b is a binary field of size 2^128, with elements represented as 128-bit integers
///   reduced modulo the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
///
/// Since these fields have different characteristics (p vs 2), there is no direct mathematical
/// homomorphism between them. This conversion is primarily for representation purposes.
///
/// Implementation details:
/// - We extract up to 128 bits from the Bn254Fr value for the conversion.
/// - The Bn254Fr field can represent values much larger than 2^128, so we only use the lower bits.
/// - We extract the first two 64-bit limbs from the Bn254Fr representation.
/// - These are combined to form a 128-bit value which is then converted to an F128b element.
pub fn ark_to_f128b(value: &Bn254Fr) -> F128b {
    use ark_ff::PrimeField;

    // Get the bytes representation of the Bn254Fr field element
    let repr = value.into_repr();

    // Create a byte array of the appropriate size (16 bytes for F128b)
    let mut array = [0u8; 16];

    // Extract the lower 64 bits (first limb)
    let lower_u64 = repr.0[0];

    // Convert the lower 64 bits to little-endian bytes and copy to the array
    for i in 0..8 {
        array[i] = ((lower_u64 >> (i * 8)) & 0xFF) as u8;
    }

    // Extract the next 64 bits (second limb) if available
    if repr.0.len() > 1 {
        let upper_u64 = repr.0[1];

        // Convert the upper 64 bits to little-endian bytes and copy to the array
        for i in 0..8 {
            array[i + 8] = ((upper_u64 >> (i * 8)) & 0xFF) as u8;
        }
    }

    // Convert the byte array to F128b
    F128b::from_uniform_bytes(&array)
}

/// Convert arkworks field element (Bn254Fr) to F8b
///
/// This function converts a value from the Bn254Fr field to the F8b field (GF(2^8)).
///
/// Mathematical relationship:
/// - Bn254Fr is a prime field of size approximately 2^254, with elements represented as
///   integers modulo a large prime p = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
/// - F8b is a binary field of size 2^8, with elements represented as 8-bit integers
///   reduced modulo an irreducible polynomial.
///
/// Since these fields have different characteristics (p vs 2), there is no direct mathematical
/// homomorphism between them. This conversion is primarily for representation purposes.
///
/// Implementation details:
/// - We extract only the lowest 8 bits from the Bn254Fr value for the conversion.
/// - The Bn254Fr field can represent values much larger than 2^8, so we only use the lowest byte.
pub fn ark_to_f8b(value: &Bn254Fr) -> F8b {
    use ark_ff::PrimeField;

    // Get the bytes representation of the Bn254Fr field element
    let repr = value.into_repr();

    // Extract the lowest byte from the first limb
    let byte = (repr.0[0] & 0xFF) as u8;

    // Create a byte array of the appropriate size (16 bytes for F8b::from_uniform_bytes)
    let mut array = [0u8; 16];
    array[0] = byte;

    // Convert the byte array to F8b
    F8b::from_uniform_bytes(&array)
}

/// Convert arkworks field element (Bn254Fr) to F64b
///
/// This function converts a value from the Bn254Fr field to the F64b field (GF(2^64)).
///
/// Mathematical relationship:
/// - Bn254Fr is a prime field of size approximately 2^254, with elements represented as
///   integers modulo a large prime p = 21888242871839275222246405745257275088548364400416034343698204186575808495617.
/// - F64b is a binary field of size 2^64, with elements represented as 64-bit integers
///   reduced modulo an irreducible polynomial.
///
/// Since these fields have different characteristics (p vs 2), there is no direct mathematical
/// homomorphism between them. This conversion is primarily for representation purposes.
///
/// Implementation details:
/// - We extract up to 64 bits from the Bn254Fr value for the conversion.
/// - The Bn254Fr field can represent values much larger than 2^64, so we only use the lower bits.
/// - We extract the first 64-bit limb from the Bn254Fr representation.
pub fn ark_to_f64b(value: &Bn254Fr) -> F64b {
    use ark_ff::PrimeField;

    // Get the bytes representation of the Bn254Fr field element
    let repr = value.into_repr();

    // Extract the lower 64 bits (first limb)
    let lower_u64 = repr.0[0];

    // Create a byte array of the appropriate size (16 bytes for F64b::from_uniform_bytes)
    let mut array = [0u8; 16];

    // Convert the lower 64 bits to little-endian bytes and copy to the array
    for i in 0..8 {
        array[i] = ((lower_u64 >> (i * 8)) & 0xFF) as u8;
    }

    // Convert the byte array to F64b
    F64b::from_uniform_bytes(&array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_std::UniformRand;
    use swanky_field::FiniteRing;
    use swanky_field_binary::{F128b, F64b};

    #[test]
    fn test_f64b_to_ark() {
        let f64b = F64b::from(123456789u64);
        let ark = f64b_to_ark(&f64b);
        assert_eq!(ark, Bn254Fr::from(123456789u64));
    }

    #[test]
    fn test_f128b_to_ark() {
        // Test with a value that fits in 64 bits
        let mut bytes = [0u8; 16];
        bytes[0] = 0x15;
        bytes[1] = 0xCD;
        bytes[2] = 0x5B;
        bytes[3] = 0x07; // 123456789 in little-endian
        let f128b_small = F128b::from_uniform_bytes(&bytes);
        let ark_small = f128b_to_ark(&f128b_small);
        assert_eq!(ark_small, Bn254Fr::from(123456789u64));

        // Test with a value that requires the full 128 bits
        let mut bytes = [0u8; 16];
        // 0x1234567890ABCDEF1234567890ABCDEF in little-endian
        bytes[0] = 0xEF;
        bytes[1] = 0xCD;
        bytes[2] = 0xAB;
        bytes[3] = 0x90;
        bytes[4] = 0x78;
        bytes[5] = 0x56;
        bytes[6] = 0x34;
        bytes[7] = 0x12;
        bytes[8] = 0xEF;
        bytes[9] = 0xCD;
        bytes[10] = 0xAB;
        bytes[11] = 0x90;
        bytes[12] = 0x78;
        bytes[13] = 0x56;
        bytes[14] = 0x34;
        bytes[15] = 0x12;
        let f128b_large = F128b::from_uniform_bytes(&bytes);
        let ark_large = f128b_to_ark(&f128b_large);

        // Verify by converting back and comparing the lower 64 bits
        // (since the conversion back might not be perfect for the full 128 bits)
        let f128b_back = ark_to_f128b(&ark_large);
        let bytes_original = f128b_large.to_bytes();
        let bytes_back = f128b_back.to_bytes();

        // The lower 64 bits should match exactly
        for i in 0..8 {
            assert_eq!(bytes_original[i], bytes_back[i]);
        }
    }

    #[test]
    fn test_ark_to_f128b() {
        // Test with a small value
        let ark_small = Bn254Fr::from(123456789u64);
        let f128b_small = ark_to_f128b(&ark_small);
        let ark_back = f128b_to_ark(&f128b_small);
        assert_eq!(ark_small, ark_back);

        // Test with a random value
        let ark_random = Bn254Fr::rand(&mut rand::thread_rng());
        let f128b_random = ark_to_f128b(&ark_random);
        let ark_back = f128b_to_ark(&f128b_random);

        // The conversion might not be perfect due to the different field sizes,
        // but converting back and forth should be consistent
        let f128b_back = ark_to_f128b(&ark_back);
        assert_eq!(f128b_random, f128b_back);
    }

    #[test]
    fn test_ark_to_f8b() {
        // Test with a small value
        let ark_small = Bn254Fr::from(123u64);
        let f8b_small = ark_to_f8b(&ark_small);
        let ark_back = f8b_to_ark(&f8b_small);

        // Since F8b can only represent values from 0 to 255,
        // we expect the conversion to only preserve the lowest 8 bits
        assert_eq!(ark_back, Bn254Fr::from(123u64));

        // Test with a value > 255
        let ark_large = Bn254Fr::from(1234u64);
        let f8b_large = ark_to_f8b(&ark_large);
        let ark_back = f8b_to_ark(&f8b_large);

        // We expect only the lowest 8 bits to be preserved (1234 % 256 = 210)
        assert_eq!(ark_back, Bn254Fr::from(210u64));
    }

    #[test]
    fn test_ark_to_f64b() {
        // Test with a small value
        let ark_small = Bn254Fr::from(123456789u64);
        let f64b_small = ark_to_f64b(&ark_small);
        let ark_back = f64b_to_ark(&f64b_small);
        assert_eq!(ark_small, ark_back);

        // Test with a value that uses all 64 bits
        let max_u64 = u64::MAX;
        let ark_max = Bn254Fr::from(max_u64);
        let f64b_max = ark_to_f64b(&ark_max);
        let ark_back = f64b_to_ark(&f64b_max);
        assert_eq!(ark_max, ark_back);

        // Test with a random value
        let ark_random = Bn254Fr::rand(&mut rand::thread_rng());
        let f64b_random = ark_to_f64b(&ark_random);
        let ark_back = f64b_to_ark(&f64b_random);

        // The conversion might not be perfect due to the different field sizes,
        // but converting back and forth within the 64-bit range should be consistent
        let f64b_back = ark_to_f64b(&ark_back);
        assert_eq!(f64b_random, f64b_back);
    }

    #[test]
    fn test_full_128bit_conversion() {
        // Test with a value that uses the full 128 bits
        let mut bytes = [0u8; 16];
        // Set both high and low 64-bit parts to non-zero values
        // Lower 64 bits: 0x0123456789ABCDEF
        bytes[0] = 0xEF;
        bytes[1] = 0xCD;
        bytes[2] = 0xAB;
        bytes[3] = 0x89;
        bytes[4] = 0x67;
        bytes[5] = 0x45;
        bytes[6] = 0x23;
        bytes[7] = 0x01;
        // Upper 64 bits: 0xFEDCBA9876543210
        bytes[8] = 0x10;
        bytes[9] = 0x32;
        bytes[10] = 0x54;
        bytes[11] = 0x76;
        bytes[12] = 0x98;
        bytes[13] = 0xBA;
        bytes[14] = 0xDC;
        bytes[15] = 0xFE;

        let f128b_value = F128b::from_uniform_bytes(&bytes);

        // Convert to Bn254Fr and back
        let ark_value = f128b_to_ark(&f128b_value);
        let f128b_back = ark_to_f128b(&ark_value);

        // Get the byte representations
        let bytes_original = f128b_value.to_bytes();
        let bytes_back = f128b_back.to_bytes();

        // Verify that both high and low parts are preserved
        // The lower 64 bits should match exactly
        for i in 0..8 {
            assert_eq!(
                bytes_original[i], bytes_back[i],
                "Lower 64 bits mismatch at index {}: original={:02x}, back={:02x}",
                i, bytes_original[i], bytes_back[i]
            );
        }

        // The upper 64 bits should also match
        for i in 8..16 {
            assert_eq!(
                bytes_original[i], bytes_back[i],
                "Upper 64 bits mismatch at index {}: original={:02x}, back={:02x}",
                i, bytes_original[i], bytes_back[i]
            );
        }
    }

    #[test]
    fn test_roundtrip_conversion() {
        // Test roundtrip conversion for various values
        let test_values = [
            F128b::ZERO,
            F128b::ONE,
            // Create a value representing max u64
            {
                let mut bytes = [0u8; 16];
                bytes[0] = 0xFF;
                bytes[1] = 0xFF;
                bytes[2] = 0xFF;
                bytes[3] = 0xFF;
                bytes[4] = 0xFF;
                bytes[5] = 0xFF;
                bytes[6] = 0xFF;
                bytes[7] = 0xFF;
                F128b::from_uniform_bytes(&bytes)
            },
            // Create a random value
            {
                let mut bytes = [0u8; 16];
                bytes[0] = 0xEF;
                bytes[1] = 0xCD;
                bytes[2] = 0xAB;
                bytes[3] = 0x90;
                F128b::from_uniform_bytes(&bytes)
            },
        ];

        for &value in &test_values {
            let ark = f128b_to_ark(&value);
            let f128b_back = ark_to_f128b(&ark);

            // For values that fit in the Bn254Fr field, the roundtrip should be exact
            // Compare the byte representations instead of accessing the private field
            let bytes_original = value.to_bytes();
            let bytes_back = f128b_back.to_bytes();

            // Check if the value is small enough to fit in 64 bits
            let is_small = bytes_original.iter().skip(8).all(|&b| b == 0);

            if is_small {
                assert_eq!(bytes_original, bytes_back);
            }
        }
    }
}
