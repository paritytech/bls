# bls [![Crates.io](https://img.shields.io/crates/v/w3f-bls.svg)](https://crates.io/crates/w3f-bls) #

Boneh-Lynn-Shacham (BLS) signatures have slow signing, very slow verification, require pairing-friendly curves with a lower security margin at comparable sizes, and tend towards dangerous malleability.  Yet, BLS permits a diverse array of signature aggregation options far beyond any other known signature scheme, which makes BLS a preferred scheme for voting in consensus algorithms and for threshold signatures.

In this crate, we take a largely unified approach to aggregation techniques and verifier optimisations for BLS signature:  We support the [BLS12-381](https://z.cash/blog/new-snark-curve.html) and [BLS12-377](https://eprint.iacr.org/2018/962.pdf) (Barreto-Lynn-Scott) curves via Arkworks traits, but abstract the pairing so that developers can choose their preferred orientation for BLS signatures. 

The main maintained aggregation path provided by the library is based on proofs-of-possession; experimental implementations of aggregation based on the distinct-message and delinearized strategies are provided for research and comparison purposes only and are niether audited nor currently maintained.

We only provide proof-of-possession for NuggetBLS scheme in `NuggetBLSPoP`. This a Schnorr-style DLEQ check fused into a pairing verification that binds the Nugget double public key's two representations (G1 and G2) to a single secret and hence force a PoP verification.  An experimental standalone Schnorr-signature PoP (`experimental::schnorr_pop::SchnorrPoP`) is also provided for research and comparison purposes; it has not been audited.


## ⚠ Proof-of-Possession is a caller-side precondition

The abstractions provided are not misuse-resistant. In particular, the crate's verification and aggregation primitives — including `verify_*`, `SignatureAggregatorAssumingPoP`, and the Chaum-Pedersen verifiers — **do not themselves validate that a public key has an accompanying proof-of-possession**. The onus is on the caller to establish PoP either by explicitly verifying the PoP proof (using the `ProofOfPossession` API) or by consulting a trusted upstream source (e.g. an on-chain registry) before invoking these APIs.

**Using the aggregation and verification primitives on public keys that have not been PoP-verified by the surrounding system exposes the user to various types of attacks, including classical rogue-key, infinity-point, and low-order-subgroup attacks.**

## Documentation

You first bring the `bls` crate into your project just as you normally would.

```rust
use w3f_bls::{Keypair,ZBLS,Message,Signed};

let mut keypair = Keypair::<ZBLS>::generate(::rand::thread_rng());
let message = Message::new(b"Some context",b"Some message");
let sig = keypair.sign(&message);
assert!( sig.verify(&message,&keypair.public) );
```

In this example, `sig` is a `Signature<ZBLS>` which only contains the signature.  One can use `Keypair::signed_message`, which returns a `SignedMessage` struct containing the message hash, the signer's public key, and the signature, though one should usually detach these constituents for wire formats.

### Aggregation with proof-of-possession

Aggregation is the main reason to use BLS, so we focus on the PoP-based aggregation path here.  The following example demonstrates generating and verifying proofs-of-possession and then using `SignatureAggregatorAssumingPoP` to batch and verify multiple BLS signatures.  As a rule, aggregation over distinct messages still requires one Miller-loop step per message, so these aggregate signatures have slow verification times but small signature sizes.

> **Note:** for brevity, the example below uses the experimental standalone `SchnorrPoP` constructor.

```rust
use w3f_bls::{Keypair,PublicKey,ZBLS,Message,Signed, ProofOfPossessionGenerator, ProofOfPossession, experimental::schnorr_pop::{SchnorrPoP}, pop_aggregator::SignatureAggregatorAssumingPoP};
use sha2::Sha256;

let mut keypairs = [Keypair::<ZBLS>::generate(::rand::thread_rng()), Keypair::<ZBLS>::generate(::rand::thread_rng())];
let msgs = ["The ships", "hung in the sky", "in much the same way", "that bricks don’t."].iter().map(|m| Message::new(b"Some context", m.as_bytes())).collect::<Vec<_>>();
let sigs = msgs.iter().zip(keypairs.iter_mut()).map(|(m,k)| k.sign(m)).collect::<Vec<_>>();

let publickeys = keypairs.iter().map(|k|k.public.clone()).collect::<Vec<_>>();
let pops = keypairs.iter_mut().map(|k|(ProofOfPossessionGenerator::<ZBLS, Sha256, PublicKey<ZBLS>, SchnorrPoP<ZBLS>>::generate_pok(k))).collect::<Vec<_>>();

//first make sure public keys have valid pop
let publickeys = publickeys.iter().zip(pops.iter()).map(|(publickey, pop) | {assert!(ProofOfPossession::<ZBLS, Sha256, PublicKey<ZBLS>>::verify(pop,publickey)); publickey}).collect::<Vec<_>>();

let batch_poped = msgs.iter().zip(publickeys).zip(sigs).fold(
    SignatureAggregatorAssumingPoP::<ZBLS>::new(),
    |mut bpop,((message, publickey),sig)| { bpop.add_message_n_publickey(message, &publickey); bpop.add_signature(&sig); bpop }
);
assert!(batch_poped.verify())
```

### Efficient Aggregatable BLS Signatures with Chaum-Pedersen Proofs

The scheme introduced in [`our recent paper`](https://eprint.iacr.org/2022/1611) is implemented across [`chaum_pedersen_signature.rs`](src/chaum_pedersen_signature.rs) (via the `ChaumPedersenSigner` and `ChaumPedersenVerifier` traits) and [`nugget.rs`](src/nugget.rs), with aggregation in [`pop_aggregator.rs`](src/pop_aggregator.rs) via the `add_message_n_publickey` and `verify_using_aggregated_auxiliary_public_keys` methods, as demonstrated in the following example:
```rust
use sha2::Sha256;
use ark_bls12_377::Bls12_377;
use rand::thread_rng;

use w3f_bls::{
    pop_aggregator::SignatureAggregatorAssumingPoP, DoubleNuggetBLS, EngineBLS, Keypair,
    Message, NuggetPublicKey, PublicKeyInSignatureGroup, TinyBLS, TinyBLS377,
};


let message = Message::new(b"ctx", b"I'd far rather be happy than right any day.");
let mut keypairs: Vec<_> = (0..3)
    .into_iter()
    .map(|_| Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(thread_rng()))
    .collect();
let pub_keys_in_sig_grp: Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs
    .iter()
    .map(|k| DoubleNuggetBLS::<TinyBLS377>::to_nugget_double_public_key(k).to_public_key_in_signature_group())
    .collect();

let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();

//sign, aggregate, and add (publickey, aux) pairs
for (k, aux) in keypairs.iter_mut().zip(pub_keys_in_sig_grp.iter()) {
    verifier_aggregator.add_signature(&k.sign(&message));
    verifier_aggregator.add_message_n_publickey(&message, &(k.public, *aux));
}

assert!(
    verifier_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
    "verifying with honest auxilary public key should pass"
);
```

### Hash to Curve

In order to sign a message, the library needs to hash the message as a point on the signature curve.  While the `BLSEngine` trait is agnostic about the `MapToSignatureCurve` method, our implementations of BLS12-381 (`ZBLS`) and BLS12-377 (`BLS377`) specifically use the Wahby and Boneh hash-to-curve method described in Section 6.6.3 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/.

## Experimental code

Multiple flavors of BLS signature batching — bit-field, delinearized batching, and batching only for distinct messages (`experimental::distinct` and `delinear`) — as well as Schnorr Proof of Possession and Triple Nugget BLS with various sister curves, have been implemented purely for comparison and research purposes.  This code resides in [`src/experimental`](src/experimental) and [`experimental_curves`](experimental_curves) behind the `--experimental` feature flag.  **It has not been audited and is not intended to be used in production**; new integrations should use the PoP-based aggregation shown above.

## Security Warnings

This library does not make any guarantees about constant-time operations, memory access patterns, or resistance to side-channel attacks.

See also the Proof-of-Possession precondition noted near the top of this README: callers are responsible for ensuring every public key passed to a verification or aggregation primitive has had its PoP verified upstream.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.