# BIP-39 word lists

Copied offline from the installed `@scure/bip39` 2.0.1 package. Its upstream MIT
license is preserved in `LICENSE`. The upstream list source is
[bitcoin/bips, bip-0039](https://github.com/bitcoin/bips/tree/master/bip-0039).
No package code or dependency is used at runtime.

`manifest.json` records source files and SHA-256 digests. Each UTF-8 file has
2,048 unique NFKD words in upstream order, one word per line with a final LF.
The BIP-39 English list digest is
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`.

Aumlok samples seven independent words from these lists. It does not create a
BIP-39 mnemonic or checksum, and it keeps the existing Aumlok scrypt derivation.
