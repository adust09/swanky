use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::{fp::FpVar, FieldVar},
    R1CSVar, ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use core::marker::PhantomData;
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F64b, F8b};
use swanky_serialization::CanonicalSerialize;

/// An optimized representation of binary field elements in the constraint system.
///
/// This struct provides a more efficient representation of binary field elements
/// (F8b, F64b, F128b) by using FpVar instead of bit-by-bit Boolean variables.
/// This significantly reduces the number of constraints needed to represent and
/// operate on binary field elements.
#[derive(Clone, Debug)]
pub struct BinaryFieldVar<F: PrimeField, T> {
    /// The field variable representing the binary field element
    pub value: FpVar<F>,
    /// Phantom data to track the original binary field type
    pub _phantom: PhantomData<T>,
}

// Implementation for F8b
impl<F: PrimeField> BinaryFieldVar<F, F8b> {
    /// Creates a new BinaryFieldVar from an F8b value
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        value: impl FnOnce() -> Result<F8b, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let f8b_value = value()?;
        let bytes = f8b_value.to_bytes();

        // Convert the bytes to a field element
        let field_value = F::from_le_bytes_mod_order(&bytes);

        // Create a new witness variable
        let var = FpVar::new_witness(cs, || Ok(field_value))?;

        Ok(Self {
            value: var,
            _phantom: PhantomData,
        })
    }

    /// Creates a new constant BinaryFieldVar from an F8b value
    pub fn constant(value: F8b) -> Self {
        let bytes = value.to_bytes();
        let field_value = F::from_le_bytes_mod_order(&bytes);

        Self {
            value: FpVar::constant(field_value),
            _phantom: PhantomData,
        }
    }

    /// Converts this BinaryFieldVar to a boolean array representation
    pub fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        // Get the bits from the FpVar, but only take the first 8 bits
        let bits = self.value.to_bits_le()?;
        Ok(bits.into_iter().take(8).collect())
    }

    /// Performs XOR operation (addition in binary fields)
    pub fn xor(&self, other: &Self) -> Result<Self, SynthesisError> {
        // In binary fields, addition is XOR
        // We need to implement this at the bit level since FpVar addition is not XOR
        let self_bits = self.to_bits_le()?;
        let other_bits = other.to_bits_le()?;

        let mut result_bits = Vec::with_capacity(8);
        for i in 0..8 {
            result_bits.push(self_bits[i].xor(&other_bits[i])?);
        }

        // Convert back to FpVar
        let mut result_bytes = [0u8; 32]; // Enough space for F::from_le_bytes_mod_order
        for (i, bit) in result_bits.iter().enumerate().take(8) {
            if bit.value()? {
                result_bytes[i / 8] |= 1 << (i % 8);
            }
        }

        let result_value = F::from_le_bytes_mod_order(&result_bytes);

        Ok(Self {
            value: FpVar::new_witness(self.value.cs(), || Ok(result_value))?,
            _phantom: PhantomData,
        })
    }
}

// Implementation for F64b
impl<F: PrimeField> BinaryFieldVar<F, F64b> {
    /// Creates a new BinaryFieldVar from an F64b value
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        value: impl FnOnce() -> Result<F64b, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let f64b_value = value()?;
        let bytes = f64b_value.to_bytes();

        // Convert the bytes to a field element
        let field_value = F::from_le_bytes_mod_order(&bytes);

        // Create a new witness variable
        let var = FpVar::new_witness(cs, || Ok(field_value))?;

        Ok(Self {
            value: var,
            _phantom: PhantomData,
        })
    }

    /// Creates a new constant BinaryFieldVar from an F64b value
    pub fn constant(value: F64b) -> Self {
        let bytes = value.to_bytes();
        let field_value = F::from_le_bytes_mod_order(&bytes);

        Self {
            value: FpVar::constant(field_value),
            _phantom: PhantomData,
        }
    }

    /// Converts this BinaryFieldVar to a boolean array representation
    pub fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        // Get the bits from the FpVar, but only take the first 64 bits
        let bits = self.value.to_bits_le()?;
        Ok(bits.into_iter().take(64).collect())
    }

    /// Performs XOR operation (addition in binary fields)
    pub fn xor(&self, other: &Self) -> Result<Self, SynthesisError> {
        // In binary fields, addition is XOR
        // We need to implement this at the bit level since FpVar addition is not XOR
        let self_bits = self.to_bits_le()?;
        let other_bits = other.to_bits_le()?;

        let mut result_bits = Vec::with_capacity(64);
        for i in 0..64 {
            result_bits.push(self_bits[i].xor(&other_bits[i])?);
        }

        // Convert back to FpVar
        let mut result_bytes = [0u8; 32]; // Enough space for F::from_le_bytes_mod_order
        for (i, bit) in result_bits.iter().enumerate().take(64) {
            if bit.value()? {
                result_bytes[i / 8] |= 1 << (i % 8);
            }
        }

        let result_value = F::from_le_bytes_mod_order(&result_bytes);

        Ok(Self {
            value: FpVar::new_witness(self.value.cs(), || Ok(result_value))?,
            _phantom: PhantomData,
        })
    }
}

// Implementation for F128b
impl<F: PrimeField> BinaryFieldVar<F, F128b> {
    /// Creates a new BinaryFieldVar from an F128b value
    pub fn new_witness(
        cs: ConstraintSystemRef<F>,
        value: impl FnOnce() -> Result<F128b, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let f128b_value = value()?;
        let bytes = f128b_value.to_bytes();

        // Convert the bytes to a field element
        let field_value = F::from_le_bytes_mod_order(&bytes);

        // Create a new witness variable
        let var = FpVar::new_witness(cs, || Ok(field_value))?;

        Ok(Self {
            value: var,
            _phantom: PhantomData,
        })
    }

    pub fn new_input(
        cs: ConstraintSystemRef<F>,
        value: impl FnOnce() -> Result<F128b, SynthesisError>,
    ) -> Result<Self, SynthesisError> {
        let f128b_value = value()?;
        let bytes = f128b_value.to_bytes();

        // Convert the bytes to a field element
        let field_value = F::from_le_bytes_mod_order(&bytes);

        // Create a new witness variable
        let var = FpVar::new_input(cs, || Ok(field_value))?;

        Ok(Self {
            value: var,
            _phantom: PhantomData,
        })
    }

    /// Creates a new constant BinaryFieldVar from an F128b value
    pub fn constant(value: F128b) -> Self {
        let bytes = value.to_bytes();
        let field_value = F::from_le_bytes_mod_order(&bytes);

        Self {
            value: FpVar::constant(field_value),
            _phantom: PhantomData,
        }
    }

    /// Converts this BinaryFieldVar to a boolean array representation
    pub fn to_bits_le(&self) -> Result<Vec<Boolean<F>>, SynthesisError> {
        // Get the bits from the FpVar, but only take the first 128 bits
        let bits = self.value.to_bits_le()?;
        Ok(bits.into_iter().take(128).collect())
    }

    /// Performs XOR operation (addition in binary fields)
    pub fn xor(&self, other: &Self) -> Result<Self, SynthesisError> {
        // In binary fields, addition is XOR
        // We need to implement this at the bit level since FpVar addition is not XOR
        let self_bits = self.to_bits_le()?;
        let other_bits = other.to_bits_le()?;

        let mut result_bits = Vec::with_capacity(128);
        for i in 0..128 {
            result_bits.push(self_bits[i].xor(&other_bits[i])?);
        }

        // Convert back to FpVar
        let mut result_bytes = [0u8; 32]; // Enough space for F::from_le_bytes_mod_order
        for (i, bit) in result_bits.iter().enumerate().take(128) {
            if bit.value()? {
                result_bytes[i / 8] |= 1 << (i % 8);
            }
        }

        let result_value = F::from_le_bytes_mod_order(&result_bytes);

        Ok(Self {
            value: FpVar::new_witness(self.value.cs(), || Ok(result_value))?,
            _phantom: PhantomData,
        })
    }

    /// Converts from a boolean array to BinaryFieldVar
    pub fn from_bits_le(bits: &[Boolean<F>]) -> Result<Self, SynthesisError> {
        if bits.len() != 128 {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Convert the boolean array to bytes
        let mut bytes = [0u8; 32]; // Enough space for F::from_le_bytes_mod_order
        for (i, bit) in bits.iter().enumerate() {
            if bit.value()? {
                bytes[i / 8] |= 1 << (i % 8);
            }
        }

        let field_value = F::from_le_bytes_mod_order(&bytes);

        // Get the constraint system from the first bit
        let cs = bits[0].cs();

        Ok(Self {
            value: FpVar::new_witness(cs, || Ok(field_value))?,
            _phantom: PhantomData,
        })
    }
}

/// Convert F8b to an optimized BinaryFieldVar
///
/// This function converts a value from the F8b field (GF(2^8)) to a BinaryFieldVar
/// that can be used in constraint systems more efficiently than bit-by-bit representation.
///
/// Mathematical relationship:
/// - F8b is a binary field of size 2^8, with elements represented as 8-bit integers
///   reduced modulo an irreducible polynomial.
///
/// Implementation details:
/// - The F8b value is converted to bytes and then to a field element in the constraint system.
/// - This representation is much more efficient than using 8 separate Boolean variables.
pub fn f8b_to_field_var<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: &F8b,
) -> Result<BinaryFieldVar<F, F8b>, SynthesisError> {
    BinaryFieldVar::<F, F8b>::new_witness(cs, || Ok(*value))
}

/// Convert F64b to an optimized BinaryFieldVar
///
/// This function converts a value from the F64b field (GF(2^64)) to a BinaryFieldVar
/// that can be used in constraint systems more efficiently than bit-by-bit representation.
///
/// Mathematical relationship:
/// - F64b is a binary field of size 2^64, with elements represented as 64-bit integers
///   reduced modulo an irreducible polynomial.
///
/// Implementation details:
/// - The F64b value is converted to bytes and then to a field element in the constraint system.
/// - This representation is much more efficient than using 64 separate Boolean variables.
pub fn f64b_to_field_var<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: &F64b,
) -> Result<BinaryFieldVar<F, F64b>, SynthesisError> {
    BinaryFieldVar::<F, F64b>::new_witness(cs, || Ok(*value))
}

/// Convert F128b to an optimized BinaryFieldVar
///
/// This function converts a value from the F128b field (GF(2^128)) to a BinaryFieldVar
/// that can be used in constraint systems more efficiently than bit-by-bit representation.
///
/// Mathematical relationship:
/// - F128b is a binary field of size 2^128, with elements represented as 128-bit integers
///   reduced modulo the irreducible polynomial x^128 + x^7 + x^2 + x + 1.
///
/// Implementation details:
/// - The F128b value is converted to bytes and then to a field element in the constraint system.
/// - This representation is much more efficient than using 128 separate Boolean variables.
pub fn f128b_to_field_var<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: &F128b,
) -> Result<BinaryFieldVar<F, F128b>, SynthesisError> {
    BinaryFieldVar::<F, F128b>::new_witness(cs, || Ok(*value))
}

pub fn f128b_to_field_input_var<F: PrimeField>(
    cs: ConstraintSystemRef<F>,
    value: &F128b,
) -> Result<BinaryFieldVar<F, F128b>, SynthesisError> {
    BinaryFieldVar::<F, F128b>::new_input(cs, || Ok(*value))
}

/// Convert a BinaryFieldVar back to F8b
///
/// This function converts a BinaryFieldVar back to an F8b value.
pub fn field_var_to_f8b<F: PrimeField>(
    var: &BinaryFieldVar<F, F8b>,
) -> Result<F8b, SynthesisError> {
    // Get the bits from the FpVar
    let bits = var.to_bits_le()?;

    // Convert the bits to bytes
    let mut bytes = [0u8; 16];
    for bit_idx in 0..8 {
        if bit_idx < bits.len() && bits[bit_idx].value()? {
            bytes[0] |= 1 << bit_idx;
        }
    }

    // Convert to F8b
    Ok(F8b::from_uniform_bytes(&bytes))
}

/// Convert a BinaryFieldVar back to F64b
///
/// This function converts a BinaryFieldVar back to an F64b value.
pub fn field_var_to_f64b<F: PrimeField>(
    var: &BinaryFieldVar<F, F64b>,
) -> Result<F64b, SynthesisError> {
    // Get the bits from the FpVar
    let bits = var.to_bits_le()?;

    // Convert the bits to bytes
    let mut bytes = [0u8; 16];
    for byte_idx in 0..8 {
        for bit_idx in 0..8 {
            let bit_pos = byte_idx * 8 + bit_idx;
            if bit_pos < bits.len() && bits[bit_pos].value()? {
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    // Convert to F64b
    Ok(F64b::from_uniform_bytes(&bytes))
}

/// Convert a BinaryFieldVar back to F128b
///
/// This function converts a BinaryFieldVar back to an F128b value.
pub fn field_var_to_f128b<F: PrimeField>(
    var: &BinaryFieldVar<F, F128b>,
) -> Result<F128b, SynthesisError> {
    // Get the bits from the FpVar
    let bits = var.to_bits_le()?;

    // Convert the bits to bytes
    let mut bytes = [0u8; 16];
    for byte_idx in 0..16 {
        for bit_idx in 0..8 {
            let bit_pos = byte_idx * 8 + bit_idx;
            if bit_pos < bits.len() && bits[bit_pos].value()? {
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
    }

    // Convert to F128b
    Ok(F128b::from_uniform_bytes(&bytes))
}

// /// Safe version of from_bits_le for F8b that works with the constraint system
// pub fn from_bits_le_safe_f8b<F: PrimeField>(
//     bits: &[Boolean<F>],
// ) -> Result<BinaryFieldVar<F, F8b>, SynthesisError> {
//     if bits.len() < 8 {
//         return Err(SynthesisError::Unsatisfiable);
//     }

//     // Take only the first 8 bits
//     let bits = &bits[0..8];

//     // Get the constraint system from the first bit
//     let cs = R1CSVar::cs(&bits[0]);

//     // Create a new witness variable
//     let value = FpVar::new_witness(cs.clone(), || {
//         let mut val = F::zero();
//         let mut coeff = F::one();

//         for bit in bits.iter() {
//             if bit.value()? {
//                 val += coeff;
//             }
//             coeff = coeff + coeff;
//         }

//         Ok(val)
//     })?;

//     Ok(BinaryFieldVar {
//         value,
//         _phantom: PhantomData,
//     })
// }

// /// Safe version of from_bits_le for F64b that works with the constraint system
// pub fn from_bits_le_safe_f64b<F: PrimeField>(
//     bits: &[Boolean<F>],
// ) -> Result<BinaryFieldVar<F, F64b>, SynthesisError> {
//     if bits.len() < 64 {
//         return Err(SynthesisError::Unsatisfiable);
//     }

//     // Take only the first 64 bits
//     let bits = &bits[0..64];

//     // Get the constraint system from the first bit
//     let cs = R1CSVar::cs(&bits[0]);

//     // Create a new witness variable
//     let value = FpVar::new_witness(cs.clone(), || {
//         let mut val = F::zero();
//         let mut coeff = F::one();

//         for bit in bits.iter() {
//             if bit.value()? {
//                 val += coeff;
//             }
//             coeff = coeff + coeff;
//         }

//         Ok(val)
//     })?;

//     Ok(BinaryFieldVar {
//         value,
//         _phantom: PhantomData,
//     })
// }

// /// Safe version of from_bits_le for F128b that works with the constraint system
// pub fn from_bits_le_safe_f128b<F: PrimeField>(
//     bits: &[Boolean<F>],
// ) -> Result<BinaryFieldVar<F, F128b>, SynthesisError> {
//     if bits.len() != 128 {
//         return Err(SynthesisError::Unsatisfiable);
//     }

//     // Get the constraint system from the first bit
//     let cs = R1CSVar::cs(&bits[0]);

//     // Create a new witness variable
//     let value = FpVar::new_witness(cs.clone(), || {
//         let mut val = F::zero();
//         let mut coeff = F::one();

//         for bit in bits.iter() {
//             if bit.value()? {
//                 val += coeff;
//             }
//             coeff = coeff + coeff;
//         }

//         Ok(val)
//     })?;

//     Ok(BinaryFieldVar {
//         value,
//         _phantom: PhantomData,
//     })
// }

// /// Safe version of XOR operation for F8b that works with the constraint system
// pub fn xor_safe_f8b<F: PrimeField>(
//     a: &BinaryFieldVar<F, F8b>,
//     b: &BinaryFieldVar<F, F8b>,
// ) -> Result<BinaryFieldVar<F, F8b>, SynthesisError> {
//     // In binary fields, addition is XOR
//     // We need to implement this at the bit level since FpVar addition is not XOR
//     let a_bits = a.to_bits_le()?;
//     let b_bits = b.to_bits_le()?;

//     let mut result_bits = Vec::with_capacity(8);
//     for i in 0..8 {
//         result_bits.push(a_bits[i].xor(&b_bits[i])?);
//     }

//     // Convert back to BinaryFieldVar using from_bits_le_safe
//     from_bits_le_safe_f8b(&result_bits)
// }

// /// Safe version of XOR operation for F64b that works with the constraint system
// pub fn xor_safe_f64b<F: PrimeField>(
//     a: &BinaryFieldVar<F, F64b>,
//     b: &BinaryFieldVar<F, F64b>,
// ) -> Result<BinaryFieldVar<F, F64b>, SynthesisError> {
//     // In binary fields, addition is XOR
//     // We need to implement this at the bit level since FpVar addition is not XOR
//     let a_bits = a.to_bits_le()?;
//     let b_bits = b.to_bits_le()?;

//     let mut result_bits = Vec::with_capacity(64);
//     for i in 0..64 {
//         result_bits.push(a_bits[i].xor(&b_bits[i])?);
//     }

//     // Convert back to BinaryFieldVar using from_bits_le_safe
//     from_bits_le_safe_f64b(&result_bits)
// }

// /// Safe version of XOR operation for F128b that works with the constraint system
// pub fn xor_safe_f128b<F: PrimeField>(
//     a: &BinaryFieldVar<F, F128b>,
//     b: &BinaryFieldVar<F, F128b>,
// ) -> Result<BinaryFieldVar<F, F128b>, SynthesisError> {
//     // In binary fields, addition is XOR
//     // We need to implement this at the bit level since FpVar addition is not XOR
//     let a_bits = a.to_bits_le()?;
//     let b_bits = b.to_bits_le()?;

//     let mut result_bits = Vec::with_capacity(128);
//     for i in 0..128 {
//         result_bits.push(a_bits[i].xor(&b_bits[i])?);
//     }

//     // Convert back to BinaryFieldVar using from_bits_le_safe
//     from_bits_le_safe_f128b(&result_bits)
// }

/// Safe version of from_bits_le for F8b that works with the constraint system
pub fn from_bits_le_safe_f8b<F: PrimeField>(
    bits: &[Boolean<F>],
) -> Result<BinaryFieldVar<F, F8b>, SynthesisError> {
    if bits.len() < 8 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Take only the first 8 bits
    let bits = &bits[0..8];

    // Get the constraint system from the first bit
    let cs = R1CSVar::cs(&bits[0]);

    // Create a new witness variable
    let value = FpVar::new_witness(cs.clone(), || {
        let mut val = F::zero();
        let mut coeff = F::one();

        for bit in bits.iter() {
            if bit.value()? {
                val += coeff;
            }
            coeff = coeff + coeff;
        }

        Ok(val)
    })?;

    Ok(BinaryFieldVar {
        value,
        _phantom: PhantomData,
    })
}

/// Safe version of from_bits_le for F64b that works with the constraint system
pub fn from_bits_le_safe_f64b<F: PrimeField>(
    bits: &[Boolean<F>],
) -> Result<BinaryFieldVar<F, F64b>, SynthesisError> {
    if bits.len() < 64 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Take only the first 64 bits
    let bits = &bits[0..64];

    // Get the constraint system from the first bit
    let cs = R1CSVar::cs(&bits[0]);

    // Create a new witness variable
    let value = FpVar::new_witness(cs.clone(), || {
        let mut val = F::zero();
        let mut coeff = F::one();

        for bit in bits.iter() {
            if bit.value()? {
                val += coeff;
            }
            coeff = coeff + coeff;
        }

        Ok(val)
    })?;

    Ok(BinaryFieldVar {
        value,
        _phantom: PhantomData,
    })
}

/// Safe version of from_bits_le for F128b that works with the constraint system
pub fn from_bits_le_safe_f128b<F: PrimeField>(
    bits: &[Boolean<F>],
) -> Result<BinaryFieldVar<F, F128b>, SynthesisError> {
    if bits.len() != 128 {
        return Err(SynthesisError::Unsatisfiable);
    }

    // Get the constraint system from the first bit
    let cs = R1CSVar::cs(&bits[0]);

    // Create a new witness variable
    let value = FpVar::new_witness(cs.clone(), || {
        let mut val = F::zero();
        let mut coeff = F::one();

        for bit in bits.iter() {
            if bit.value()? {
                val += coeff;
            }
            coeff = coeff + coeff;
        }

        Ok(val)
    })?;

    Ok(BinaryFieldVar {
        value,
        _phantom: PhantomData,
    })
}

/// Safe version of XOR operation for F8b that works with the constraint system
pub fn xor_safe_f8b<F: PrimeField>(
    a: &BinaryFieldVar<F, F8b>,
    b: &BinaryFieldVar<F, F8b>,
) -> Result<BinaryFieldVar<F, F8b>, SynthesisError> {
    // In binary fields, addition is XOR
    // We need to implement this at the bit level since FpVar addition is not XOR
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut result_bits = Vec::with_capacity(8);
    for i in 0..8 {
        result_bits.push(a_bits[i].xor(&b_bits[i])?);
    }

    // Convert back to BinaryFieldVar using from_bits_le_safe
    from_bits_le_safe_f8b(&result_bits)
}

/// Safe version of XOR operation for F64b that works with the constraint system
pub fn xor_safe_f64b<F: PrimeField>(
    a: &BinaryFieldVar<F, F64b>,
    b: &BinaryFieldVar<F, F64b>,
) -> Result<BinaryFieldVar<F, F64b>, SynthesisError> {
    // In binary fields, addition is XOR
    // We need to implement this at the bit level since FpVar addition is not XOR
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut result_bits = Vec::with_capacity(64);
    for i in 0..64 {
        result_bits.push(a_bits[i].xor(&b_bits[i])?);
    }

    // Convert back to BinaryFieldVar using from_bits_le_safe
    from_bits_le_safe_f64b(&result_bits)
}

/// Safe version of XOR operation for F128b that works with the constraint system
pub fn xor_safe_f128b<F: PrimeField>(
    a: &BinaryFieldVar<F, F128b>,
    b: &BinaryFieldVar<F, F128b>,
) -> Result<BinaryFieldVar<F, F128b>, SynthesisError> {
    // In binary fields, addition is XOR
    // We need to implement this at the bit level since FpVar addition is not XOR
    let a_bits = a.to_bits_le()?;
    let b_bits = b.to_bits_le()?;

    let mut result_bits = Vec::with_capacity(128);
    for i in 0..128 {
        result_bits.push(a_bits[i].xor(&b_bits[i])?);
    }

    // Convert back to BinaryFieldVar using from_bits_le_safe
    from_bits_le_safe_f128b(&result_bits)
}

pub fn f128b_to_boolean_array_public<F: Field>(
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
            bits.push(Boolean::new_input(
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

#[cfg(test)]
mod boolean_conversion_tests {

    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_f128b_xor() {
        // Create a constraint system
        let cs = ConstraintSystem::<Bn254Fr>::new_ref();

        // Create test values
        let f128b_a = F128b::from_uniform_bytes(&[
            0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F,
        ]);

        let f128b_b = F128b::from_uniform_bytes(&[
            0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
            0x33, 0x33,
        ]);

        // Expected result of XOR
        let expected_xor = f128b_a + f128b_b; // In binary fields, addition is XOR

        // Convert to optimized field vars
        let field_var_a = f128b_to_field_var(cs.clone(), &f128b_a).unwrap();
        let field_var_b = f128b_to_field_var(cs.clone(), &f128b_b).unwrap();

        // Perform XOR operation
        let field_var_xor = field_var_a.xor(&field_var_b).unwrap();

        // Convert back to F128b
        let f128b_xor = field_var_to_f128b(&field_var_xor).unwrap();

        // Verify the result
        assert_eq!(f128b_xor, expected_xor);
    }
}
