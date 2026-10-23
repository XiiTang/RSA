# Boundless patches

The `boundless` branch carries these patches on upstream v0.10.0-rc.18
(`e31a0209de98cce82de44a5efc241912eb38f6ea`). Boundless performs every RSA
private-key operation in aws-lc; through russh and ssh-key this crate only
parses, encodes and validates keys and performs public-key operations.

| Patch | Why | Regression |
| --- | --- | --- |
| Refuse every private-key operation | None of this crate's private-key operations is constant-time (the Marvin attack, RUSTSEC-2023-0071, no fixed release). Every one of them — `RsaPrivateKey::sign`, `sign_with_rng`, `decrypt`, `decrypt_blinded`, the PKCS#1 v1.5 and PSS signing keys, the PKCS#1 v1.5 and OAEP decrypting keys and `hazmat` — runs through `algorithms::rsa::rsa_decrypt`, which now returns `Error::PrivateKeyOperationRefused`; the blinding and exponentiation it used are removed. A dependent that reaches one, however it is called, fails instead of leaking timing. Upstream tests and README examples that sign or decrypt are ignored or `no_run` with the reason | `tests/refused.rs` (`every_private_key_operation_is_refused`) reaches each entry point and checks parsing, validation and public-key operations still work; the remaining upstream suite, Wycheproof verification included, passes |

```sh
git submodule update --init --depth 1
cargo test --all-features
```

Boundless consumes a full commit SHA through `[patch.crates-io]`; run these and
the Boundless SSH and RSA regressions before moving the pin. To move to a newer
upstream release, replace `rsa_decrypt`'s body again, drop what only it used,
and ignore the upstream tests that sign or decrypt.

## Fixed constant-time utilities (#312)

Update the lockfile's ctutils 0.4.2 to 0.4.4, the smallest patched release
for RUSTSEC-2026-0385 (mask generation and u128 comparisons). The private-key
operation refusal and public-key API are unchanged. Regression coverage:
`cargo test --all-features --locked`, including `tests/refused.rs`, plus
Boundless's SSH and RSA tests in its complete library suite.
