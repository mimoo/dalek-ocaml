use rand::prelude::*;
use x25519_dalek as x25519;

// create an ocaml type?

#[derive(Clone)]
pub struct PrivateKey(x25519::StaticSecret);

unsafe impl<'a> ocaml::FromValue<'a> for PrivateKey {
    fn from_value(value: ocaml::Value) -> Self {
        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
        x.as_ref().clone()
    }
}

#[derive(Clone)]
pub struct PublicKey(x25519::PublicKey);

unsafe impl<'a> ocaml::FromValue<'a> for PublicKey {
    fn from_value(value: ocaml::Value) -> Self {
        let x: ocaml::Pointer<Self> = ocaml::FromValue::from_value(value);
        x.as_ref().clone()
    }
}

extern "C" fn mytype_finalizer(_: ocaml::Raw) {
    println!("This runs when the value gets garbage collected");
}

ocaml::custom!(PrivateKey {
    finalize: mytype_finalizer,
});
ocaml::custom!(PublicKey {
    finalize: mytype_finalizer,
});

#[ocaml::func]
pub fn new() -> PrivateKey {
    let mut rng = thread_rng();
    let private_key = x25519::StaticSecret::new(&mut rng);
    PrivateKey(private_key)
}

#[derive(ocaml::IntoValue, ocaml::FromValue)]
pub struct SharedSecret(Vec<u8>);

#[ocaml::func]
pub fn diffie_hellman(private_key: PrivateKey, public_key: PublicKey) -> SharedSecret {
    let shared_secret = private_key.0.diffie_hellman(&public_key.0);
    SharedSecret(shared_secret.to_bytes().into())
}

#[ocaml::func]
pub fn to_public_key(private_key: PrivateKey) -> PublicKey {
    let public_key = x25519::PublicKey::from(&private_key.0);
    PublicKey(public_key)
}

//pub fn private_to_bytes(private_key: PrivateKey) ->
