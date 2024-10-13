use alloc::vec::Vec;

/// Performs XOR operation on a Vec<u8> using a given key (u8).
pub fn xor_bytes(data: Vec<u8>, key: u8) -> Vec<u8> {
    data.into_iter().map(|byte| byte ^ key).collect()
}
