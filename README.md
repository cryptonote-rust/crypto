# Cryptography Primitives For CryptoNote Based Crypto Currencies


[![](https://travis-ci.com/cryptonote-rust/crypto.svg?branch=master)](https://travis-ci.com/cryptonote-rust/crypto)
[![](https://img.shields.io/crates/v/cryptonote-crypto.svg)](https://crates.io/crates/cryptonote-crypto)
[![codecov](https://codecov.io/gh/cryptonote-rust/crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptonote-rust/crypto)

# Usage

1. Generate chacha key.

```

use cryptonote_crypto::chacha;

let password = "your password";

let key = chacha::generate(passowrd);
```

2. Slow Hash

```

use cryptonote_crypto::hash;
// Version 6
let a = b"hello world!";
let hash = hash::cn_slow_hash(&a[0..], hash::HashVersion::Version6);

// Version 7
// a must be a byte_string with more than 64 bytes long
let a = byte_string::string_to_u8_array("0707cff699d605f7eb4dbdcad3a38b462b52e9b8ecdf06fb4c95bc5b058a177f84d327f27db739430000000363862429fb90c0fc35fcb9f760c484c8532ee5f2a7cbea4e769d44cd12a7f201");
let hash = hash::cn_slow_hash(&a[0..], hash::HashVersion::Version7);
```

3. Fast Hash

```
use cryptonote_crypto::hash;
let a = b"hello world!";
let hash = hash::cn_fast_hash(&a[0..]);
```


