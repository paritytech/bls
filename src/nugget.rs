//! ## BLS key pair with public key in both G1 and G2 and on a third curve of
//! ## group the same prime order
//! ## This implement Unaggreagated BLS signature along side with their DLEQ proof
//!
//! Implements schemes suggested in
//! [paper](https://eprint.iacr.org/2022/1611)
//! with a chaum-pedersen signature on a third curve
//!
//! The scheme is the same as the one implemented in `double.rs`
//! with the exception that the signature is on the third curve.
//!

use alloc::vec::Vec;
use core::{iter::once, marker::PhantomData};

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::broken_derives;
use crate::chaum_pedersen_signature::{ChaumPedersenSigner, ChaumPedersenVerifier};
use crate::schnorr_pop::SchnorrProof;
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, KeypairVT, PublicKey, SecretKeyVT, Signature};
use crate::{EngineBLS, Message, Signed};

/// Wrapper for a point in the signature group which is supposed to
/// have the same logarithm as the public key in the public key group
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKeyInSignatureGroup<E: EngineBLS>(pub E::SignatureGroup);
broken_derives!(PublicKeyInSignatureGroup); // Actually the derive works for this one, not sure why.

//TODO: Make a type for a sister group. This makes sense because SisterGroup it doesn't mean on itself
// SisterGroup<E: EngineBLS> = CurveGroup + PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes
/// Wrapper for a point in the third curve sister group which is supposed to
/// have the same logarithm as the public key in the public key group
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalDeserialize)]
pub struct PublicKeyInSisterGroup<S: CurveGroup>(pub S);

pub trait NuggetPublicKey<
    E: EngineBLS,
    S: CurveGroup + PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
>
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;

    fn into_bls_public_key(&self) -> PublicKey<E>;

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S>;

    fn sister_gen_plus_public_key(&self) -> S;

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool;
}

pub trait NuggetBLS<E: EngineBLS, S: CurveGroup>
where
    S: PrimeGroup<ScalarField = E::Scalar>,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S>;

    /// Return a triple public object containing public keys both in G1 and G2 and S
    fn sign(&mut self, message: &Message) -> NuggetSignature<E>;
}

impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for SecretKeyVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup(
            <E::SignatureGroup as CurveGroup>::Affine::generator().into_group() * self.0,
        )
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        PublicKeyInSisterGroup(S::Affine::generator().into_group() * self.0)
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        ChaumPedersenSigner::<E, S, Sha256>::generate_cp_signature(self, &message)
    }
}

impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for KeypairVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.secret)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        self.secret.into_public_key_in_sister_group()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetBLS::<E, S>::sign(&mut self.secret, message)
    }
}

impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for Keypair<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.into_vartime())
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        self.into_vartime().into_public_key_in_sister_group()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetBLS::<E, S>::sign(&mut self.into_vartime(), message)
    }
}

/// Detached BLS Signature containing DLEQ
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct NuggetSignature<E: EngineBLS>(pub E::SignatureGroup, pub SchnorrProof<E>);

impl<E: EngineBLS> NuggetSignature<E> {
    //const DESCRIPTION : &'static str = "A BLS signature";

    /// Verify a single BLS signature using DLEQ proof
    pub fn verify<
        S: CurveGroup,
        H: FixedOutputReset + Default + Clone,
        P: ChaumPedersenVerifier<E, S, H>,
    >(
        &self,
        message: &Message,
        publickey: &P,
    ) -> bool
    where
        S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    {
        publickey.verify_cp_signature(message, self)
    }
}

/// Message with attached BLS signature
///
///
#[derive(Debug, Clone)]
pub struct NuggetSignedMessage<E: EngineBLS, S: CurveGroup, P: NuggetPublicKey<E, S>>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    P: Sized,
{
    pub message: Message,
    pub publickey: P,
    pub signature: NuggetSignature<E>,
    pub _phantom: PhantomData<S>,
}

impl<E: EngineBLS, S: CurveGroup, P: NuggetPublicKey<E, S>> NuggetSignedMessage<E, S, P>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    P: Sized,
{
    pub fn new(message: Message, publickey: P, signature: NuggetSignature<E>) -> Self {
        NuggetSignedMessage {
            message,
            publickey,
            signature,
            _phantom: PhantomData,
        }
    }
}

impl<E: EngineBLS, S: CurveGroup, P: NuggetPublicKey<E, S>> PartialEq<Self>
    for NuggetSignedMessage<E, S, P>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn eq(&self, other: &Self) -> bool {
        self.message.eq(&other.message)
            && self
                .publickey
                .into_bls_public_key()
                .eq(&other.publickey.into_bls_public_key())
            && self
                .publickey
                .into_public_key_in_signature_group()
                .eq(&other.publickey.into_public_key_in_signature_group())
            && self
                .publickey
                .into_public_key_in_sister_group()
                .eq(&other.publickey.into_public_key_in_sister_group())
            && self.signature.0.eq(&other.signature.0)
    }
}

impl<'a, E: EngineBLS, S: CurveGroup, P: ChaumPedersenVerifier<E, S, Sha256>> Signed
    for &'a NuggetSignedMessage<E, S, P>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    type E = E;

    type M = Message;
    type PKG = PublicKey<E>;

    type PKnM = ::core::iter::Once<(Message, PublicKey<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        once((self.message.clone(), self.publickey.into_bls_public_key())) // TODO:  Avoid clone
    }

    fn signature(&self) -> Signature<E> {
        Signature(self.signature.0)
    }

    fn verify(self) -> bool {
        //we chaum pederesen verification which is faster
        ChaumPedersenVerifier::<E, S, Sha256>::verify_cp_signature(
            &self.publickey,
            &self.message,
            &self.signature,
        )
    }
}

/// Serialization for NuggetSignature
impl<E: EngineBLS> SerializableToBytes for NuggetSignature<E> {
    const SERIALIZED_BYTES_SIZE: usize = E::SIGNATURE_SERIALIZED_SIZE + 2 * E::SECRET_KEY_SIZE;
}

#[cfg(all(test, feature = "std"))]
mod tests {
    // //use rand::thread_rng;

    // use super::*;

    // use ark_bls12_377::Bls12_377;
    // use ark_bls12_381::Bls12_381;
    // use ark_ec::bls12::Bls12Config;
    // use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
    // use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    // use ark_ec::pairing::Pairing as PairingEngine;

    // use crate::{EngineBLS, Message, TinyBLS};

    // fn nugget_public_key_serialization_test<
    //     EB: EngineBLS<Engine = E>,
    //     S: CurveGroup + PrimeGroup<ScalarField = EB::Scalar> + SerializableToBytes,
    //     E: PairingEngine,
    //     P: Bls12Config,
    //     PUB: NuggetPublicKey<EB, S> + SerializableToBytes,
    // >(
    //     x: NuggetSignedMessage<EB, S, PUB>,
    // ) -> NuggetSignedMessage<EB, S, PUB>
    // where
    //     <P as Bls12Config>::G2Config: WBConfig,
    //     WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
    //     EB::SignatureGroup: SerializableToBytes,
    // {
    //     let NuggetSignedMessage {
    //         message,
    //         publickey,
    //         signature,
    //         _phantom,
    //     } = x;

    //     let publickey = PUB::from_bytes(&publickey.to_bytes()).unwrap();
    //     let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

    //     NuggetSignedMessage {
    //         message,
    //         publickey,
    //         signature,
    //         _phantom: PhantomData,
    //     }
    // }

    // // fn test_single_bls_message_double_signature_scheme<
    // //     EB: EngineBLS<Engine = E>,
    // //     E: PairingEngine,
    // //     P: Bls12Config,
    // // >()
    // // where
    // //     <P as Bls12Config>::G2Config: WBConfig,
    // //     WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
    // // {
    // //     let good = Message::new(b"ctx", b"test message");

    // //     let mut keypair = Keypair::<EB>::generate(thread_rng());
    // //     let public_key = NuggetBLS::into_double_public_key(&mut keypair);
    // //     let good_sig = NuggetBLS::sign(&mut keypair, &good);

    // //     assert!(
    // //         public_key.verify(&good, &good_sig),
    // //         "Verification of a valid signature failed!"
    // //     );

    // //     let bad = Message::new(b"ctx", b"wrong message");
    // //     let bad_sig = NuggetBLS::sign(&mut keypair, &bad);

    // //     assert!(bad_sig.verify(
    // //         &bad,
    // //         &NuggetBLS::into_double_public_key(&keypair)
    // //     ));

    // //     assert!(good != bad, "good == bad");
    // //     assert!(good_sig.0 != bad_sig.0, "good sig == bad sig");

    // //     assert!(
    // //         !bad_sig.verify(
    // //             &good,
    // //             &NuggetBLS::into_double_public_key(&keypair)
    // //         ),
    // //         "Verification of a signature on a different message passed!"
    // //     );
    // //     assert!(
    // //         !good_sig.verify(
    // //             &bad,
    // //             &NuggetBLS::into_double_public_key(&keypair)
    // //         ),
    // //         "Verification of a signature on a different message passed!"
    // //     );
    // // }

    // // #[test]
    // // fn test_double_public_key_double_signature_serialization_for_bls12_377() {
    // //     let mut keypair =
    // //         Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(thread_rng());
    // //     let message = Message::new(b"ctx", b"test message");
    // //     let good_sig0 = NuggetBLS::sign(&mut keypair, &message);

    // //     let signed_message = NuggetSignedMessage {
    // //         message: message,
    // //         publickey: NuggetPublicKey(
    // //             keypair.into_public_key_in_signature_group().0,
    // //             keypair.public.0,
    // //         ),
    // //         signature: good_sig0,
    // //     };

    // //     assert!(
    // //         signed_message.verify(),
    // //         "valid double signed message should verify"
    // //     );

    // //     let deserialized_signed_message = double_public_serialization_test::<
    // //         TinyBLS<Bls12_377, ark_bls12_377::Config>,
    // //         Bls12_377,
    // //         ark_bls12_377::Config,
    // //     >(signed_message);

    // //     assert!(
    // //         deserialized_signed_message.verify(),
    // //         "deserialized valid double signed message should verify"
    // //     );
    // // }

    // // #[test]
    // // fn test_double_public_key_double_signature_serialization_for_bls12_381() {
    // //     let mut keypair =
    // //         Keypair::<TinyBLS<Bls12_381, ark_bls12_381::Config>>::generate(thread_rng());
    // //     let message = Message::new(b"ctx", b"test message");
    // //     let good_sig0 = NuggetBLS::sign(&mut keypair, &message);

    // //     let signed_message = NuggetSignedMessage {
    // //         message: message,
    // //         publickey: NuggetPublicKey(
    // //             keypair.into_public_key_in_signature_group().0,
    // //             keypair.public.0,
    // //         ),
    // //         signature: good_sig0,
    // //     };

    // //     assert!(
    // //         signed_message.verify(),
    // //         "valid double signed message should verify"
    // //     );

    // //     let deserialized_signed_message = double_public_serialization_test::<
    // //         TinyBLS<Bls12_381, ark_bls12_381::Config>,
    // //         Bls12_381,
    // //         ark_bls12_381::Config,
    // //     >(signed_message);

    // //     assert!(
    // //         deserialized_signed_message.verify(),
    // //         "deserialized valid double signed message should verify"
    // //     );
    // // }

    // // #[test]
    // // fn test_single_bls_message_double_signature_scheme_for_bls12_377() {
    // //     test_single_bls_message_double_signature_scheme::<
    // //         TinyBLS<Bls12_377, ark_bls12_377::Config>,
    // //         Bls12_377,
    // //         ark_bls12_377::Config,
    // //     >();
    // // }

    // // #[test]
    // // fn test_single_bls_message_double_signature_scheme_for_bls12_381() {
    // //     test_single_bls_message_double_signature_scheme::<
    // //         TinyBLS<Bls12_381, ark_bls12_381::Config>,
    // //         Bls12_381,
    // //         ark_bls12_381::Config,
    // //     >();
    // // }
}
