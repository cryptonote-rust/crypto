use cryptonight::hash;
use cryptonight::aes;
use cryptonight::aes::{AESSupport};
use std::convert::{TryInto};

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
  let input = password.as_bytes();
  let cn_hash = hash::hash_alloc_scratchpad(&input[0..], &aes, hash::HashVersion::Version6);
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
  fn should_generate() {
    let key = generate(String::from(""));
    assert!(key.data == [101, 98, 49, 52, 101, 56, 97, 56, 51, 51, 102, 97, 99, 54, 102, 101, 57, 97, 52, 51, 98, 53, 55, 98, 51, 51, 54, 55, 56, 57, 99, 52]);
    let key1 = generate(String::from("This is a test"));
    assert!(key1.data == [97, 48, 56, 52, 102, 48, 49, 100, 49, 52, 51, 55, 97, 48, 57, 99, 54, 57, 56, 53, 52, 48, 49, 98, 54, 48, 100, 52, 51, 53, 53, 52]);
  }
}
