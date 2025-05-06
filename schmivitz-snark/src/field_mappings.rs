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
    // Get the bytes representation, handling potential missing assignments
    let bytes = value.to_bytes();
    let mut bits = Vec::with_capacity(8);

    // Extract 8 bits from the first byte
    for i in 0..8 {
        let bit = (bytes[0] >> i) & 1 == 1;

        // Create a witness variable with proper error handling for missing assignments
        bits.push(Boolean::new_witness(
            ark_relations::ns!(cs, "f8b_bit"),
            || {
                // Check if the value is valid, otherwise return AssignmentMissing
                if bytes.is_empty() {
                    Err(SynthesisError::AssignmentMissing)
                } else {
                    Ok(bit)
                }
            },
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
    // Get the bytes representation, handling potential missing assignments
    let bytes = value.to_bytes();
    let mut bits = Vec::with_capacity(64);

    // Extract 64 bits from the bytes (8 bytes)
    for byte_idx in 0..8 {
        for bit_idx in 0..8 {
            // Check if the byte index is valid
            let bit = if byte_idx < bytes.len() {
                (bytes[byte_idx] >> bit_idx) & 1 == 1
            } else {
                false
            };

            // Create a witness variable with proper error handling for missing assignments
            bits.push(Boolean::new_witness(
                ark_relations::ns!(cs, "f64b_bit"),
                || {
                    // Check if the value is valid, otherwise return AssignmentMissing
                    if byte_idx >= bytes.len() {
                        Err(SynthesisError::AssignmentMissing)
                    } else {
                        Ok(bit)
                    }
                },
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
    // Get the bytes representation, handling potential missing assignments
    let bytes = value.to_bytes();
    let mut bits = Vec::with_capacity(128);

    // Extract 128 bits from the bytes (16 bytes)
    for byte_idx in 0..16 {
        for bit_idx in 0..8 {
            // Check if the byte index is valid
            let bit = if byte_idx < bytes.len() {
                (bytes[byte_idx] >> bit_idx) & 1 == 1
            } else {
                false
            };

            // Create a witness variable with proper error handling for missing assignments
            bits.push(Boolean::new_witness(
                ark_relations::ns!(cs, "f128b_bit"),
                || {
                    // Check if the value is valid, otherwise return AssignmentMissing
                    if byte_idx >= bytes.len() {
                        Err(SynthesisError::AssignmentMissing)
                    } else {
                        Ok(bit)
                    }
                },
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
    use ark_bn254::Fr as Bn254Fr;
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
    #[test]
    fn test_f8b_addition() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test values
        let f8b_a = F8b::from(0x0Fu8); // 00001111
        let f8b_b = F8b::from(0x33u8); // 00110011

        // Expected result of addition in GF(2^8): 00111100 = 0x3C
        // In binary fields, addition is XOR
        let expected_sum = F8b::from(0x3Cu8);

        // Direct field addition
        let direct_sum = f8b_a + f8b_b;
        assert_eq!(direct_sum, expected_sum);

        // Addition through boolean arrays
        let bits_a = f8b_to_boolean_array(cs.clone(), &f8b_a).unwrap();
        let bits_b = f8b_to_boolean_array(cs.clone(), &f8b_b).unwrap();

        // Perform addition (XOR) operation bit by bit
        let mut sum_bits = Vec::with_capacity(8);
        for i in 0..8 {
            sum_bits.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F8b
        let boolean_sum = boolean_array_to_f8b(&sum_bits).unwrap();

        // Verify both methods give the same result
        assert_eq!(boolean_sum, expected_sum);
        assert_eq!(boolean_sum, direct_sum);
    }

    #[test]
    fn test_f8b_subtraction() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test values
        let f8b_a = F8b::from(0x0Fu8); // 00001111
        let f8b_b = F8b::from(0x33u8); // 00110011

        // In binary fields, subtraction is the same as addition (XOR)
        // Expected result: 00111100 = 0x3C
        let expected_diff = F8b::from(0x3Cu8);

        // Direct field subtraction
        let direct_diff = f8b_a - f8b_b;
        assert_eq!(direct_diff, expected_diff);

        // Subtraction through boolean arrays (same as addition/XOR in binary fields)
        let bits_a = f8b_to_boolean_array(cs.clone(), &f8b_a).unwrap();
        let bits_b = f8b_to_boolean_array(cs.clone(), &f8b_b).unwrap();

        // Perform subtraction (XOR) operation bit by bit
        let mut diff_bits = Vec::with_capacity(8);
        for i in 0..8 {
            diff_bits.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F8b
        let boolean_diff = boolean_array_to_f8b(&diff_bits).unwrap();

        // Verify both methods give the same result
        assert_eq!(boolean_diff, expected_diff);
        assert_eq!(boolean_diff, direct_diff);

        // Verify that addition and subtraction are the same in binary fields
        assert_eq!(direct_diff, f8b_a + f8b_b);
    }

    #[test]
    fn test_f64b_addition() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test values
        let f64b_a = F64b::from(0x0F0F0F0F0F0F0F0Fu64);
        let f64b_b = F64b::from(0x3333333333333333u64);

        // Expected result of addition in GF(2^64)
        // In binary fields, addition is XOR
        let expected_sum = F64b::from(0x3C3C3C3C3C3C3C3Cu64);

        // Direct field addition
        let direct_sum = f64b_a + f64b_b;
        assert_eq!(direct_sum, expected_sum);

        // Addition through boolean arrays
        let bits_a = f64b_to_boolean_array(cs.clone(), &f64b_a).unwrap();
        let bits_b = f64b_to_boolean_array(cs.clone(), &f64b_b).unwrap();

        // Perform addition (XOR) operation bit by bit
        let mut sum_bits = Vec::with_capacity(64);
        for i in 0..64 {
            sum_bits.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F64b
        let boolean_sum = boolean_array_to_f64b(&sum_bits).unwrap();

        // Verify both methods give the same result
        assert_eq!(boolean_sum, expected_sum);
        assert_eq!(boolean_sum, direct_sum);
    }

    #[test]
    fn test_f64b_subtraction() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Test values
        let f64b_a = F64b::from(0x0F0F0F0F0F0F0F0Fu64);
        let f64b_b = F64b::from(0x3333333333333333u64);

        // In binary fields, subtraction is the same as addition (XOR)
        let expected_diff = F64b::from(0x3C3C3C3C3C3C3C3Cu64);

        // Direct field subtraction
        let direct_diff = f64b_a - f64b_b;
        assert_eq!(direct_diff, expected_diff);

        // Subtraction through boolean arrays (same as addition/XOR in binary fields)
        let bits_a = f64b_to_boolean_array(cs.clone(), &f64b_a).unwrap();
        let bits_b = f64b_to_boolean_array(cs.clone(), &f64b_b).unwrap();

        // Perform subtraction (XOR) operation bit by bit
        let mut diff_bits = Vec::with_capacity(64);
        for i in 0..64 {
            diff_bits.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F64b
        let boolean_diff = boolean_array_to_f64b(&diff_bits).unwrap();

        // Verify both methods give the same result
        assert_eq!(boolean_diff, expected_diff);
        assert_eq!(boolean_diff, direct_diff);

        // Verify that addition and subtraction are the same in binary fields
        assert_eq!(direct_diff, f64b_a + f64b_b);
    }

    #[test]
    fn test_f128b_addition() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create test values for F128b
        let mut bytes_a = [0u8; 16];
        bytes_a[0] = 0x0F; // Lower bits pattern: 0x0F0F0F0F0F0F0F0F
        bytes_a[1] = 0x0F;
        bytes_a[2] = 0x0F;
        bytes_a[3] = 0x0F;
        bytes_a[4] = 0x0F;
        bytes_a[5] = 0x0F;
        bytes_a[6] = 0x0F;
        bytes_a[7] = 0x0F;
        bytes_a[8] = 0x0F; // Upper bits pattern: 0x0F0F0F0F0F0F0F0F
        bytes_a[9] = 0x0F;
        bytes_a[10] = 0x0F;
        bytes_a[11] = 0x0F;
        bytes_a[12] = 0x0F;
        bytes_a[13] = 0x0F;
        bytes_a[14] = 0x0F;
        bytes_a[15] = 0x0F;

        let mut bytes_b = [0u8; 16];
        bytes_b[0] = 0x33; // Lower bits pattern: 0x3333333333333333
        bytes_b[1] = 0x33;
        bytes_b[2] = 0x33;
        bytes_b[3] = 0x33;
        bytes_b[4] = 0x33;
        bytes_b[5] = 0x33;
        bytes_b[6] = 0x33;
        bytes_b[7] = 0x33;
        bytes_b[8] = 0x33; // Upper bits pattern: 0x3333333333333333
        bytes_b[9] = 0x33;
        bytes_b[10] = 0x33;
        bytes_b[11] = 0x33;
        bytes_b[12] = 0x33;
        bytes_b[13] = 0x33;
        bytes_b[14] = 0x33;
        bytes_b[15] = 0x33;

        let mut expected_bytes = [0u8; 16];
        expected_bytes[0] = 0x3C; // Expected pattern: 0x3C3C3C3C3C3C3C3C
        expected_bytes[1] = 0x3C;
        expected_bytes[2] = 0x3C;
        expected_bytes[3] = 0x3C;
        expected_bytes[4] = 0x3C;
        expected_bytes[5] = 0x3C;
        expected_bytes[6] = 0x3C;
        expected_bytes[7] = 0x3C;
        expected_bytes[8] = 0x3C; // Expected pattern: 0x3C3C3C3C3C3C3C3C
        expected_bytes[9] = 0x3C;
        expected_bytes[10] = 0x3C;
        expected_bytes[11] = 0x3C;
        expected_bytes[12] = 0x3C;
        expected_bytes[13] = 0x3C;
        expected_bytes[14] = 0x3C;
        expected_bytes[15] = 0x3C;

        let f128b_a = F128b::from_uniform_bytes(&bytes_a);
        let f128b_b = F128b::from_uniform_bytes(&bytes_b);
        let expected_sum = F128b::from_uniform_bytes(&expected_bytes);

        // Direct field addition
        let direct_sum = f128b_a + f128b_b;
        assert_eq!(direct_sum, expected_sum);

        // Addition through boolean arrays
        let bits_a = f128b_to_boolean_array(cs.clone(), &f128b_a).unwrap();
        let bits_b = f128b_to_boolean_array(cs.clone(), &f128b_b).unwrap();

        // Perform addition (XOR) operation bit by bit
        let mut sum_bits = Vec::with_capacity(128);
        for i in 0..128 {
            sum_bits.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F128b
        let boolean_sum = boolean_array_to_f128b(&sum_bits).unwrap();

        // Verify both methods give the same result
        assert_eq!(boolean_sum, expected_sum);
        assert_eq!(boolean_sum, direct_sum);
    }

    #[test]
    fn test_f128b_subtraction() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create test values for F128b (same as in addition test)
        let mut bytes_a = [0u8; 16];
        bytes_a[0] = 0x0F; // Lower bits pattern: 0x0F0F0F0F0F0F0F0F
        bytes_a[1] = 0x0F;
        bytes_a[2] = 0x0F;
        bytes_a[3] = 0x0F;
        bytes_a[4] = 0x0F;
        bytes_a[5] = 0x0F;
        bytes_a[6] = 0x0F;
        bytes_a[7] = 0x0F;
        bytes_a[8] = 0x0F; // Upper bits pattern: 0x0F0F0F0F0F0F0F0F
        bytes_a[9] = 0x0F;
        bytes_a[10] = 0x0F;
        bytes_a[11] = 0x0F;
        bytes_a[12] = 0x0F;
        bytes_a[13] = 0x0F;
        bytes_a[14] = 0x0F;
        bytes_a[15] = 0x0F;

        let mut bytes_b = [0u8; 16];
        bytes_b[0] = 0x33; // Lower bits pattern: 0x3333333333333333
        bytes_b[1] = 0x33;
        bytes_b[2] = 0x33;
        bytes_b[3] = 0x33;
        bytes_b[4] = 0x33;
        bytes_b[5] = 0x33;
        bytes_b[6] = 0x33;
        bytes_b[7] = 0x33;
        bytes_b[8] = 0x33; // Upper bits pattern: 0x3333333333333333
        bytes_b[9] = 0x33;
        bytes_b[10] = 0x33;
        bytes_b[11] = 0x33;
        bytes_b[12] = 0x33;
        bytes_b[13] = 0x33;
        bytes_b[14] = 0x33;
        bytes_b[15] = 0x33;

        let mut expected_bytes = [0u8; 16];
        expected_bytes[0] = 0x3C; // Expected pattern: 0x3C3C3C3C3C3C3C3C
        expected_bytes[1] = 0x3C;
        expected_bytes[2] = 0x3C;
        expected_bytes[3] = 0x3C;
        expected_bytes[4] = 0x3C;
        expected_bytes[5] = 0x3C;
        expected_bytes[6] = 0x3C;
        expected_bytes[7] = 0x3C;
        expected_bytes[8] = 0x3C; // Expected pattern: 0x3C3C3C3C3C3C3C3C
        expected_bytes[9] = 0x3C;
        expected_bytes[10] = 0x3C;
        expected_bytes[11] = 0x3C;
        expected_bytes[12] = 0x3C;
        expected_bytes[13] = 0x3C;
        expected_bytes[14] = 0x3C;
        expected_bytes[15] = 0x3C;

        let f128b_a = F128b::from_uniform_bytes(&bytes_a);
        let f128b_b = F128b::from_uniform_bytes(&bytes_b);
        let expected_diff = F128b::from_uniform_bytes(&expected_bytes);

        // Direct field subtraction
        let direct_diff = f128b_a - f128b_b;
        assert_eq!(direct_diff, expected_diff);

        // Subtraction through boolean arrays
        let bits_a = f128b_to_boolean_array(cs.clone(), &f128b_a).unwrap();
        let bits_b = f128b_to_boolean_array(cs.clone(), &f128b_b).unwrap();

        // Perform subtraction (XOR) operation bit by bit
        let mut diff_bits = Vec::with_capacity(128);
        for i in 0..128 {
            diff_bits.push(bits_a[i].xor(&bits_b[i]).unwrap());
        }

        // Convert back to F128b
        let boolean_diff = boolean_array_to_f128b(&diff_bits).unwrap();

        // Verify both methods give the same result
        assert_eq!(boolean_diff, expected_diff);
        assert_eq!(boolean_diff, direct_diff);

        // Verify that addition and subtraction are the same in binary fields
        assert_eq!(direct_diff, f128b_a + f128b_b);
    }
}
