open Core_kernel

type shared_secret = { inner : char array }

module PublicKey = struct
  type t
end

module PrivateKey = struct
  type t

  external generate : unit -> t = "new"

  external to_public_key : t -> PublicKey.t = "to_public_key"

  (*  external to_bytes : t -> bytes = "to_bytes" *)

  external diffie_hellman : t -> PublicKey.t -> shared_secret = "diffie_hellman"
end

let%test_unit "two diffie-hellman, same result" =
  let priv = PrivateKey.generate () in
  let pub = PrivateKey.(generate () |> to_public_key) in
  let shared_secret = PrivateKey.diffie_hellman priv pub in
  let shared_secret2 = PrivateKey.diffie_hellman priv pub in
  [%test_eq: char array] shared_secret.inner shared_secret2.inner
