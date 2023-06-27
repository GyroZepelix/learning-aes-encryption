use aes::{
    cipher::{
        generic_array::GenericArray, typenum::UInt, typenum::UTerm, typenum::B0, typenum::B1,
        BlockDecrypt, BlockEncrypt,
    },
    Aes128,
};
use anyhow::{bail, Ok, Result};

type Block128 = GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>>;

pub fn string_to_blocks(slice: &str) -> Vec<Block128> {
    slice
        .as_bytes()
        .chunks(16)
        .map(bytes_to_block)
        .collect::<Vec<Block128>>()
}

pub fn encrypt_blocks(cipher: &Aes128, blocks: &mut Vec<Block128>) {
    blocks
        .iter_mut()
        .for_each(|block: &mut Block128| (cipher.encrypt_block(block)));
}

pub fn decrypt_blocks(cipher: &Aes128, blocks: &mut Vec<Block128>) {
    blocks
        .iter_mut()
        .for_each(|block: &mut Block128| (cipher.decrypt_block(block)));
}

pub fn hex_to_block(hex_slice: &str) -> Result<Block128> {
    if hex_slice.len() != 32 {
        bail!("hex slice not 32 characters long: {}", hex_slice);
    }
    let decoded_hex = hex::decode(hex_slice)?;
    Ok(bytes_to_block(&decoded_hex))
}

pub fn print_blocks_to_hex(blocks: &Vec<Block128>) {
    blocks.iter().for_each(|block| print!("{:x}", block));
    println!();
}

fn bytes_to_block(bytes: &[u8]) -> Block128 {
    let mut block = [0u8; 16];
    let len = bytes.len().min(16);
    block[..len].copy_from_slice(&bytes[..len]);
    GenericArray::from(block)
}
