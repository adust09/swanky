use ark_bn254::Fr as Bn254Fr;
use swanky_field_binary::{F128b, F64b, F8b};
use swanky_serialization::CanonicalSerialize;

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

// Convert F128b to arkworks field element
pub fn f128b_to_ark(value: &F128b) -> Bn254Fr {
    // F128b is represented as a u128, so we need to convert it to a field element
    // Get the bytes representation
    let bytes = value.to_bytes();

    // Since Bn254Fr can only represent values up to the prime field size,
    // we'll use the lower 64 bits of the F128b value to avoid overflow
    let mut u64_value: u64 = 0;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        u64_value |= (byte as u64) << (i * 8);
    }

    // Convert the u64 value to a Bn254Fr field element
    Bn254Fr::from(u64_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as Bn254Fr;
    use swanky_field_binary::F64b;

    #[test]
    fn test_f64b_to_ark() {
        let f64b = F64b::from(123456789u64);
        let ark = f64b_to_ark(&f64b);
        assert_eq!(ark, Bn254Fr::from(123456789u64));
    }
}
