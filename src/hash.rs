use std::fmt;

use sha3::{Digest, Keccak256Full};
use std::convert::{TryInto};
use cryptonight::aes::{AESSupport};
use cryptonight::hash;
use cryptonight::aes;

#[derive(PartialEq, Debug, Clone)]
pub struct Hash256 {
data: [u8; 32]
}

#[derive(PartialEq, Debug, Clone)]
pub struct Hash8 {
data: [u8; 8]
}

impl Hash256 {
  pub fn null_hash() -> Hash256 {
    Hash256 {
data: [0;32]
    }
  }
  pub fn from(str: &str) -> Result<Hash256, hex::FromHexError> {
    if str.len() != 64 {
      // TODO
      return Err(hex::FromHexError::OddLength);
    }
    let data = hex::decode(str)?;
    let mut hash = Hash256::null_hash();
    hash.data = array_ref!(data, 0, 32).clone();
    Ok(hash)
  }
  pub fn data(&self) -> &[u8] {
    &self.data
  }
  pub fn copy_from_slice(&mut self, data: &[u8]) {
    self.data.copy_from_slice(data);
  }
}

impl Hash8 {
  pub fn null_hash() -> Hash8 {
    Hash8 {
data: [0; 8]
    }
  }
  pub fn from(str: &str) -> Result<Hash8, hex::FromHexError> {
    if str.len() != 16 {
      return Err(hex::FromHexError::OddLength);
    }
    let data = hex::decode(str)?;
    let mut hash = Hash8::null_hash();
    hash.data = array_ref!(data, 0, 8).clone();
    Ok(hash)
  }
  pub fn data(&self) -> &[u8] {
    &self.data
  }
  pub fn copy_from_slice(&mut self, data: &[u8]) {
    self.data.copy_from_slice(data);
  }
}

macro_rules! impl_Display {
  (for $($t:ty),+) => {
    $(impl fmt::Display for $t {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "<{}>", hex::encode(self.data))
        }
        })*
  }
}

impl_Display!(for Hash256, Hash8);

pub fn cn_fast_hash(data: &[u8]) -> Hash256 {
  let mut hash = Hash256::null_hash();
  hash.data.copy_from_slice(&Keccak256Full::digest(data)[..32]);
  hash
}

pub fn cn_slow_hash(data: &[u8], version: hash::HashVersion) -> Hash256 {
  let aes = aes::new(AESSupport::HW);
  let cn_hash = hash::hash_alloc_scratchpad(&data[0..], &aes, version);
  let (data, _) = cn_hash.as_bytes().split_at(32);
  assert!(data.len() == 32);
  let data: [u8; 32] = data.try_into().unwrap();
  let mut hash = Hash256::null_hash();
  hash.data.copy_from_slice(&data[0..]);
  hash
}

#[cfg(test)]
mod tests {
  use super::*;
  use cryptonight::byte_string;

#[test]
  fn null_hash() {
    let hash = Hash256::null_hash();
    assert_eq!(hash.data, [0; 32]);

    let hash = Hash8::null_hash();
    assert_eq!(hash.data, [0; 8]);
  }

#[test]
  fn decodes_correctly() {
    let data: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    let hash = Hash256::from("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20").unwrap();
    assert_eq!(hash.data, data);

    let data: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let hash = Hash8::from("0102030405060708").unwrap();
    assert_eq!(hash.data, data);
  }

#[test]
  fn errors_on_invalid_input() {
    assert!(Hash256::from("01").is_err());
    assert!(Hash8::from("01111111111111111111111111111111111111").is_err());
  }

#[test] 
  fn should_test_fast_hash() {
    let a = b"hello world!";
    let hash = cn_fast_hash(&a[0..]);
    assert!(hash.data == [87, 202, 161, 118, 175, 26, 192, 67, 60, 93, 243, 14, 141, 171, 205, 46, 193, 175, 30, 146, 162, 110, 206, 213, 247, 25, 184, 132, 88, 119, 124, 214]);
  }

#[test] 
  fn should_test_slow_hash() {
    let a = b"hello world!";
    let hash = cn_slow_hash(&a[0..], hash::HashVersion::Version6);
    assert!(hash.data == [53, 102, 50, 56, 56, 50, 56, 48, 55, 51, 101, 57, 54, 52, 100, 48, 101, 48, 51, 53, 49, 100, 57, 50, 98, 57, 56, 52, 99, 52, 97, 51]);
    let a = b"";
    let hash = cn_slow_hash(&a[0..], hash::HashVersion::Version6);
    assert!(hash.data == [101, 98, 49, 52, 101, 56, 97, 56, 51, 51, 102, 97, 99, 54, 102, 101, 57, 97, 52, 51, 98, 53, 55, 98, 51, 51, 54, 55, 56, 57, 99, 52]);

    let a = byte_string::string_to_u8_array("0707cff699d605f7eb4dbdcad3a38b462b52e9b8ecdf06fb4c95bc5b058a177f84d327f27db739430000000363862429fb90c0fc35fcb9f760c484c8532ee5f2a7cbea4e769d44cd12a7f201");
    let hash = cn_slow_hash(&a[0..], hash::HashVersion::Version7);
    assert!(hash.data == [
        0x61,
        0x30,
        0x31,
        0x65,
        0x33,
        0x36,
        0x39,
        0x39,
        0x32,
        0x37,
        0x62,
        0x39,
        0x30,
        0x65,
        0x31,
        0x31,
        0x64,
        0x32,
        0x31,
        0x35,
        0x39,
        0x61,
        0x38,
        0x35,
        0x63,
        0x65,
        0x64,
        0x63,
        0x30,
        0x66,
        0x65,
        0x64
    ]
);
  }
}
