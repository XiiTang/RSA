//! This fork refuses every private-key operation (RUSTSEC-2023-0071): each
//! entry point a dependent can reach fails, while keys still parse and
//! public-key operations still work.
#![cfg(feature = "encoding")]

use pkcs8::DecodePrivateKey;
use rsa::{
    hazmat, oaep, pkcs1v15, pss,
    signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier},
    traits::{Decryptor, RandomizedDecryptor, RandomizedEncryptor},
    BoxedUint, Error, Oaep, Pkcs1v15Encrypt, Pkcs1v15Sign, Pss, RsaPrivateKey, RsaPublicKey,
};
use sha2::{Digest, Sha256};

fn key() -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(include_str!("examples/pkcs8/rsa2048-priv.pem")).unwrap()
}

fn refused<T: core::fmt::Debug>(result: Result<T, Error>) {
    assert_eq!(result.unwrap_err(), Error::PrivateKeyOperationRefused);
}

fn refused_signature<T: core::fmt::Debug>(result: Result<T, rsa::signature::Error>) {
    let error = result.unwrap_err();
    let source = std::error::Error::source(&error).expect("the rsa error");
    assert_eq!(
        source.downcast_ref::<Error>(),
        Some(&Error::PrivateKeyOperationRefused)
    );
}

#[test]
fn every_private_key_operation_is_refused() {
    let key = key();
    key.validate().unwrap();
    let public = RsaPublicKey::from(&key);
    let digest = Sha256::digest(b"message");
    let mut rng = rand::rng();

    refused(key.sign(Pkcs1v15Sign::new::<Sha256>(), &digest));
    refused(key.sign_with_rng(&mut rng, Pkcs1v15Sign::new::<Sha256>(), &digest));
    refused(key.sign_with_rng(&mut rng, Pss::<Sha256>::new(), &digest));
    refused(key.sign_with_rng(&mut rng, Pss::<Sha256>::new_blinded(), &digest));

    let encrypted = public
        .encrypt(&mut rng, Pkcs1v15Encrypt, b"secret")
        .unwrap();
    refused(key.decrypt(Pkcs1v15Encrypt, &encrypted));
    refused(key.decrypt_blinded(&mut rng, Pkcs1v15Encrypt, &encrypted));
    let encrypted = public
        .encrypt(&mut rng, Oaep::<Sha256>::new(), b"secret")
        .unwrap();
    refused(key.decrypt(Oaep::<Sha256>::new(), &encrypted));

    refused_signature(pkcs1v15::SigningKey::<Sha256>::new(key.clone()).try_sign(b"message"));
    refused_signature(
        pkcs1v15::SigningKey::<Sha256>::new(key.clone()).try_sign_with_rng(&mut rng, b"message"),
    );
    refused_signature(
        pss::SigningKey::<Sha256>::new(key.clone()).try_sign_with_rng(&mut rng, b"m"),
    );
    refused_signature(
        pss::BlindedSigningKey::<Sha256>::new(key.clone()).try_sign_with_rng(&mut rng, b"m"),
    );

    refused(pkcs1v15::DecryptingKey::new(key.clone()).decrypt(&encrypted));
    refused(oaep::DecryptingKey::<Sha256>::new(key.clone()).decrypt(&encrypted));
    refused(oaep::DecryptingKey::<Sha256>::new(key.clone()).decrypt_with_rng(&mut rng, &encrypted));

    let c = BoxedUint::from_be_slice(&encrypted, 2048).unwrap();
    refused(hazmat::rsa_decrypt(
        None::<&mut rand::rngs::ChaCha8Rng>,
        &key,
        &c,
    ));
    refused(hazmat::rsa_decrypt_and_check(&key, Some(&mut rng), &c));

    // Public-key operations are untouched: a signature made elsewhere verifies.
    let encryptor = oaep::EncryptingKey::<Sha256>::new(public.clone());
    encryptor.encrypt_with_rng(&mut rng, b"secret").unwrap();
    let verifying = pkcs1v15::VerifyingKey::<Sha256>::new(public);
    let forged = pkcs1v15::Signature::try_from(vec![1u8; 256].as_slice()).unwrap();
    assert!(verifying.verify(b"message", &forged).is_err());
    assert_eq!(forged.to_vec().len(), 256);
}
