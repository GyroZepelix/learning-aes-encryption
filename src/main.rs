use aes::cipher::{generic_array::GenericArray, KeyInit};
use aes::{Aes128, Block};
use anyhow::Result;
use namecrypt::{decrypt_blocks, encrypt_blocks, print_blocks_to_hex, string_to_blocks};
use std::io;
fn main() -> Result<()> {
    let key = GenericArray::from([10u8; 16]);
    println!("{:?}", key);

    let mut input = String::new();

    io::stdin().read_line(&mut input)?;

    let mut blocks: Vec<Block> = string_to_blocks(&input.trim());

    let cipher = Aes128::new(&key);

    print_blocks_to_hex(&blocks);
    println!("{}\n", String::from_utf8(blocks.concat())?);
    encrypt_blocks(&cipher, &mut blocks);
    print_blocks_to_hex(&blocks);
    println!(
        "{}\n",
        String::from_utf8(blocks.concat()).unwrap_or("Cannot convert to String".to_owned())
    );
    decrypt_blocks(&cipher, &mut blocks);
    print_blocks_to_hex(&blocks);
    println!("{}\n", String::from_utf8(blocks.concat())?);

    Ok(())
}
