# How to apply in your own code

First include the relevant dependencies:

```rust
use crate::regex::ciphertext::{gen_keys, encrypt_str};
use crate::regex::engine::has_match;
```

Then, generate a private and public key pair:

```rust
let (client_key, server_key) = gen_keys();
```

Encrypt the content, this generates a `StringCiphertext` from a `&str`. The
content can only contain ascii characters, if there are any non-ascii symbols
present `encrypt_str` below will throw an error:

```rust
let ct_content = encrypt_str(&client_key, 'some body of text')?;
```

Apply your regex pattern to the generated ciphertext content:

```rust
let ct_res = has_match(&server_key, &ct_content, '/^ab|cd$/')?;
```

The result (`ct_res` here) is an encrypted ciphertext and must therefore first
be decrypted with the client key:

```rust
let res = client_key.decrypt(&ct_res);
```
once decrypted (`res` here), it will be either `0` for no match or `1` for a
match.
