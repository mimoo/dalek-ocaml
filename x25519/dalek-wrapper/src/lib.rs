use rand::prelude::*;
use std::convert::TryInto as _;
use x25519_dalek as x25519;

// [u8; 32] type (necessary for ocaml)

#[derive(ocaml::IntoValue, ocaml::FromValue)]
pub struct Array32Bytes(Vec<u8>);

// private key stuff

#[derive(Clone)]
pub struct PrivateKey(x25519::StaticSecret);

unsafe impl<'a> ocaml::FromValue<'a> for PrivateKey {
    fn from_value(value: ocaml::Value) -> Self {
        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
        x.as_ref().clone()
    }
}

impl PrivateKey {
    unsafe extern "C" fn finalize(v: ocaml::Raw) {
        let ptr = v.as_pointer::<PrivateKey>();
        ptr.drop_in_place()
    }
}

ocaml::custom!(PrivateKey {
    finalize: PrivateKey::finalize,
});

#[ocaml::func]
pub fn new() -> PrivateKey {
    let mut rng = thread_rng();
    let private_key = x25519::StaticSecret::new(&mut rng);
    PrivateKey(private_key)
}

#[ocaml::func]
pub fn diffie_hellman(private_key: PrivateKey, public_key: PublicKey) -> Array32Bytes {
    let shared_secret = private_key.0.diffie_hellman(&public_key.0);
    Array32Bytes(shared_secret.to_bytes().into())
}

#[ocaml::func]
pub fn to_public_key(private_key: PrivateKey) -> PublicKey {
    let public_key = x25519::PublicKey::from(&private_key.0);
    PublicKey(public_key)
}

#[ocaml::func]
pub fn private_to_bytes(private_key: PrivateKey) -> Array32Bytes {
    Array32Bytes(private_key.0.to_bytes().into())
}

#[ocaml::func]
pub fn private_from_bytes(bytes: Array32Bytes) -> PrivateKey {
    let private_bytes: [u8; 32] = bytes
        .0
        .try_into()
        .expect("private key was not a 32-byte array");
    PrivateKey(x25519::StaticSecret::from(private_bytes))
}

// public key stuff

#[derive(Clone)]
pub struct PublicKey(x25519::PublicKey);

unsafe impl<'a> ocaml::FromValue<'a> for PublicKey {
    fn from_value(value: ocaml::Value) -> Self {
        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
        x.as_ref().clone()
    }
}

impl PublicKey {
    unsafe extern "C" fn finalize(v: ocaml::Raw) {
        let ptr = v.as_pointer::<PublicKey>();
        ptr.drop_in_place()
    }
}

ocaml::custom!(PublicKey {
    finalize: PublicKey::finalize,
});

#[ocaml::func]
pub fn public_to_bytes(public_key: PublicKey) -> Array32Bytes {
    Array32Bytes(public_key.0.to_bytes().into())
}

#[ocaml::func]
pub fn public_from_bytes(bytes: Array32Bytes) -> PublicKey {
    let public_bytes: [u8; 32] = bytes
        .0
        .try_into()
        .expect("public key was not a 32-byte array");
    PublicKey(x25519::PublicKey::from(public_bytes))
}
