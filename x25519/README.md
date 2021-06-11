# X25519

Usage:

```ocaml
(* to generate a private key *)
let priv = PrivateKey.generate () in
(* to serialization a private key *)
let priv_bytes = PrivateKey.to_bytes priv in
(* to deserialize a private key *)
let priv = PrivateKey.of_bytes priv_bytes in
(* to get a public key *)
let pub = PrivateKey.(generate () |> to_public_key) in
(* to get a shared secret from a diffie-hellman key exchange *)
let shared_secret = PrivateKey.diffie_hellman priv pub in
(* the shared secret is an array of 32 chars *)
shared_secret.inner
```
