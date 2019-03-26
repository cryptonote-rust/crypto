use cryptonight::hash;
use cryptonight::aes;
use cryptonight::aes::{AESSupport};
use cryptonight::byte_string;

use std::convert::{TryFrom, TryInto};

const CHACHA_KEY_SIZE:usize =  32;
const CHACHA_IV_SIZE:usize = 8;


pub struct ChachaKey {
  data: [u8; CHACHA_KEY_SIZE],
}

pub struct ChachaIV {
    data: [u8; CHACHA_IV_SIZE],
}

pub fn generate(password: String) -> ChachaKey {
  let aes = aes::new(AESSupport::HW);
    let input = byte_string::string_to_u8_array(&password);
    let cn_hash = hash::hash_alloc_scratchpad(&input, &aes, hash::HashVersion::Version6);
    println!("{}", cn_hash);
    let (data, _) = cn_hash.as_bytes().split_at(CHACHA_KEY_SIZE);
    assert!(data.len() == CHACHA_KEY_SIZE);
    let data: [u8; CHACHA_KEY_SIZE] = data.try_into().unwrap();
    ChachaKey{
      data
    }
}

#[cfg(test)]
mod tests {
  use super::*;
  
  #[test]
    fn show_generate() {
      let key = generate(String::from(""));
      assert!(key.data == [101, 98, 49, 52, 101, 56, 97, 56, 51, 51, 102, 97, 99, 54, 102, 101, 57, 97, 52, 51, 98, 53, 55, 98, 51, 51, 54, 55, 56, 57, 99, 52]
);
      println!("{:?}", key.data);
    }

}