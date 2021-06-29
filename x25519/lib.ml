open Core_kernel

type array32bytes = { inner : char array } [@@boxed]

module PublicKey = struct
  type t

  external to_bytes : t -> array32bytes = "public_to_bytes"

  external of_bytes : array32bytes -> t option = "public_from_bytes"
end

module PrivateKey = struct
  type t

  external generate : unit -> t = "new"

  external to_public_key : t -> PublicKey.t = "to_public_key"

  external to_bytes : t -> array32bytes = "private_to_bytes"

  external of_bytes : array32bytes -> t = "private_from_bytes"

  external diffie_hellman : t -> PublicKey.t -> array32bytes = "diffie_hellman"
end

let%test_unit "two diffie-hellman, same result" =
  let priv = PrivateKey.generate () in
  let pub = PrivateKey.(generate () |> to_public_key) in
  let shared_secret = PrivateKey.diffie_hellman priv pub in
  let shared_secret2 = PrivateKey.diffie_hellman priv pub in
  [%test_eq: char array] shared_secret.inner shared_secret2.inner

let%test_unit "serialization of private key" =
  let priv = PrivateKey.generate () in
  let priv_bytes = PrivateKey.to_bytes priv in
  let priv2 = PrivateKey.of_bytes priv_bytes in
  let pub = PrivateKey.(generate () |> to_public_key) in
  let shared_secret = PrivateKey.diffie_hellman priv pub in
  let shared_secret2 = PrivateKey.diffie_hellman priv2 pub in
  [%test_eq: char array] shared_secret.inner shared_secret2.inner

let%test_unit "serialization of public key" =
  let priv = PrivateKey.generate () in
  let pub = PrivateKey.(generate () |> to_public_key) in
  let pub_bytes = PublicKey.to_bytes pub in
  let pub2 =
    match PublicKey.of_bytes pub_bytes with
    | None -> failwith "error"
    | Some x -> x
  in
  let shared_secret = PrivateKey.diffie_hellman priv pub in
  let shared_secret2 = PrivateKey.diffie_hellman priv pub2 in
  [%test_eq: char array] shared_secret.inner shared_secret2.inner
