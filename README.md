# A homomorphic regex engine

This is a regex engine for determining whether a regex pattern matches on
_encrypted_ content. The content is never decrypted, the engine builds on
[https://github.com/zama-ai/tfhe-rs](tfhe-rs) to apply fully homomorphic
encryption circuits. This enables to never have to decrypt the content, instead
producing results in the same encrypted space (ie whoever has the private key
with which the content was encrypted can decrypt the regex result).

The result is either an encrypted 0 (no match), or an encrypted 1 (somewhere in
the content the pattern matched).

## How to use this

The binary produced here serves as a basic demo. Simply call it with first
argument the content string and second argument the pattern string. For
example, `cargo run -- 'this is the content' '/^pattern$/'`; though it's
advicable to first compile an executable with `cargo install --path .` as the
key generation and homomorphic operations seem to experience a heavy
performance penalty when running with `cargo run`.

On execution it first creates a private and public key pair. It then encrypts
the content with the private key, and applies the regex pattern onto the
encrypted content string. Finally, it decrypts the resulting encrypted result
using the private key and prints it to the console (0 for false, 1 for true).

To get some more information on what exactly it is doing, set the `RUST_LOG`
environment variable to `debug` or to `trace`, ie: `RUST_LOG=debug cargo run --
'text' '/^text$/'`.

## Supported regex constructs

Here's a list to give some ideas of what's supported:
- Contains matching: `/abc/` only matches with strings containing abc (e.g., abc, 123abc, abc123, 123abc456)
- Start matching: `/^abc/` only matches strings starting with abc (e.g., abc, abc123)
- End matching: `/abc$/` only matches strings ending with abc (e.g., abc, 123abc)
- Exact matching: `/^abc$/` only matches the string abc
- Case-insensitive matching: `/^abc$/i` only matches with abc, Abc, aBc, abC, ABc, aBC, AbC, ABC
- Optional matching: `/^ab?c$/` only matches with abc, ac
- Zero or more matching: `/^ab*c$/` only matches with ac, abc, abbc, abbbc and so on
- One or more matching: /^ab+c$/ only matches with abc, abbc, abbbc and so on
- Numbered matching: 
  * `/^ab{2}c$/` only matches with abbc
  * `/^ab{3,}c$/` only matches with abbbc, abbbbc, abbbbbc and so on
  * `/^ab{2,4}c$/` only matches with abbc, abbbc, abbbbc
- Alternative matching: `/^ab|cd$/` only matches with ab and cd
- Any character matching: `/^.$/` only matches with a, b, A, B, ? and so on
- Character range matching: 
  * `/^[abc]$/` only matches with a, b and c
  * `/^[a-d]$/` only matches with a, b, c and d
- Character range not matching: 
  * `/^[^abc]$/` only doesn't match with a, b and c
  * `/^[^a-d]$/` only doesn't match with a, b, c and d
- Escaping special characters: 
  * `/^\.$/` only matches with .
  * `/^\*$/` only matches with *
  * Same for all special characters used above (e.g., [, ], $ and so on)
- and any combination of the features above

## Internals

Internally the regex engine works on a vector of encrypted content characters
(ie each content's character is encrypted individually). As a consequence this
does mean that at least some information about the content is leaked to the
party that is applying the regex pattern: the length of the content. Though
this could probably be mitigated at cost of a significant performance penalty
by introducing some sort of padding character (fake character that does not 
break pattern matches).

It parses the pattern, then generates lazily (in the sense of not yet executing
any homomorphic operations) the list of potential homomorphic circuits that
must each be ran exhaustively. The list is lazily generated, so as to automatically
exclude any pattern that is provably going to result in a false result. For
example, consider an application of `/^a+b$/` on content `acb`, then any
pattern that doesn't start from the first content character and any pattern
that does not end at the final content character can immediately be discarded.
In this example it'd mean that we would only end up executing the homomorphic
circuit generated to test for `aab`. Finally, each executed variant is then
joined together with homomorphic `bitor` operations to reach a single result.

Each homomorphic operation is expensive, and so to limit any double work there
is a cache maintained. For example, `/^a?ab/` will generate multiple circuit
variants where `a` is homomorphically compared to a same content's character.
The cache prevents any such recomputations from being actually recomputed; we
already know the answer.
