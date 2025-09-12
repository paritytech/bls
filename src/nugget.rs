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
use core::iter::once;

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

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

/// Wrapper for a point in the third curve sister group which is supposed to
/// have the same logarithm as the public key in the public key group
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalDeserialize)]
pub struct PublicKeyInSisterGroup<S: CurveGroup>(pub S);

/// BLS Public Key with sub keys in both G1 and G2 and on a third curve with same prime order group
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct NuggetPublicKey<E: EngineBLS, S: CurveGroup>(
    pub E::SignatureGroup,
    pub E::PublicKeyGroup,
    pub S,
)
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes;

impl<E: EngineBLS, S: CurveGroup> NuggetPublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    pub fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool {
        signature.verify(message, self)
    }
}

pub trait NuggetPublicKeyScheme<E: EngineBLS, S: CurveGroup>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S>;

    /// Return a triple public object containing public keys both in G1 and G2 and S
    fn into_nugget_public_key(&self) -> NuggetPublicKey<E, S>;
    fn sign(&mut self, message: &Message) -> NuggetSignature<E>;
}

impl<E: EngineBLS, S: CurveGroup> NuggetPublicKeyScheme<E, S> for SecretKeyVT<E>
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

    fn into_nugget_public_key(&self) -> NuggetPublicKey<E, S> {
        NuggetPublicKey(
            NuggetPublicKeyScheme::<E, S>::into_public_key_in_signature_group(self).0,
            self.into_public().0,
            self.into_public_key_in_sister_group().0,
        )
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        let chaum_pedersen_signature =
            ChaumPedersenSigner::<E, S, Sha256>::generate_cp_signature(self, &message);
        NuggetSignature(chaum_pedersen_signature.0 .0, chaum_pedersen_signature.1)
    }
}

/// Serialization for NuggetPublickey
/// Serialize size depends on the size of the public key of the thrid curve
/// so S, the sister curve  need to implement SerializableToBytes
impl<E: EngineBLS, S: CurveGroup> SerializableToBytes for NuggetPublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar>,
    S: SerializableToBytes,
{
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE + S::SERIALIZED_BYTES_SIZE;
}

impl<E: EngineBLS, S: CurveGroup> NuggetPublicKeyScheme<E, S> for KeypairVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetPublicKeyScheme::<E, S>::into_public_key_in_signature_group(&self.secret)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        self.secret.into_public_key_in_sister_group()
    }

    fn into_nugget_public_key(&self) -> NuggetPublicKey<E, S> {
        self.secret.into_nugget_public_key()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetPublicKeyScheme::<E, S>::sign(&mut self.secret, message)
    }
}

impl<E: EngineBLS, S: CurveGroup> NuggetPublicKeyScheme<E, S> for Keypair<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetPublicKeyScheme::<E, S>::into_public_key_in_signature_group(&self.into_vartime())
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        self.into_vartime().into_public_key_in_sister_group()
    }

    fn into_nugget_public_key(&self) -> NuggetPublicKey<E, S> {
        self.into_vartime().into_nugget_public_key()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetPublicKeyScheme::<E, S>::sign(&mut self.into_vartime(), message)
    }
}

/// Detached BLS Signature containing DLEQ
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct NuggetSignature<E: EngineBLS>(pub E::SignatureGroup, SchnorrProof<E>);

impl<E: EngineBLS> NuggetSignature<E> {
    //const DESCRIPTION : &'static str = "A BLS signature";

    /// Verify a single BLS signature using DLEQ proof
    pub fn verify<S: CurveGroup>(
        &self,
        message: &Message,
        publickey: &NuggetPublicKey<E, S>,
    ) -> bool
    where
        S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    {
        <NuggetPublicKey<E, S> as ChaumPedersenVerifier<E, S, Sha256>>::verify_cp_signature(
            &publickey,
            &message,
            (Signature(self.0), self.1),
        )
    }
}

/// Message with attached BLS signature
///
///
#[derive(Debug, Clone)]
pub struct NuggetSignedMessage<E: EngineBLS, S: CurveGroup>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    pub message: Message,
    pub publickey: NuggetPublicKey<E, S>,
    pub signature: NuggetSignature<E>,
}

impl<E: EngineBLS, S: CurveGroup> PartialEq<Self> for NuggetSignedMessage<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn eq(&self, other: &Self) -> bool {
        self.message.eq(&other.message)
            && self.publickey.0.eq(&other.publickey.0)
            && self.publickey.1.eq(&other.publickey.1)
            && self.signature.0.eq(&other.signature.0)
    }
}

impl<'a, E: EngineBLS, S: CurveGroup> Signed for &'a NuggetSignedMessage<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    type E = E;

    type M = Message;
    type PKG = PublicKey<E>;

    type PKnM = ::core::iter::Once<(Message, PublicKey<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        once((self.message.clone(), PublicKey(self.publickey.1))) // TODO:  Avoid clone
    }

    fn signature(&self) -> Signature<E> {
        Signature(self.signature.0)
    }

    fn verify(self) -> bool {
        //we chaum pederesen verification which is faster
        ChaumPedersenVerifier::<E, S, Sha256>::verify_cp_signature(
            &self.publickey,
            &self.message,
            (Signature(self.signature.0), self.signature.1),
        )
    }
}

/// Serialization for NuggetSignature
impl<E: EngineBLS> SerializableToBytes for NuggetSignature<E> {
    const SERIALIZED_BYTES_SIZE: usize = E::SIGNATURE_SERIALIZED_SIZE + 2 * E::SECRET_KEY_SIZE;
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand::thread_rng;

    use super::*;

    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12Config;
    use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ec::pairing::Pairing as PairingEngine;

    use crate::{EngineBLS, Message, TinyBLS};

    fn double_public_serialization_test<
        EB: EngineBLS<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >(
        x: NuggetSignedMessage<EB>,
    ) -> NuggetSignedMessage<EB>
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
    {
        let NuggetSignedMessage {
            message,
            publickey,
            signature,
        } = x;

        let publickey = NuggetPublicKey::<EB>::from_bytes(&publickey.to_bytes()).unwrap();
        let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

        NuggetSignedMessage {
            message,
            publickey,
            signature,
        }
    }

    fn test_single_bls_message_double_signature_scheme<
        EB: EngineBLS<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >()
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
    {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let public_key = NuggetPublicKeyScheme::into_double_public_key(&mut keypair);
        let good_sig = NuggetPublicKeyScheme::sign(&mut keypair, &good);

        assert!(
            public_key.verify(&good, &good_sig),
            "Verification of a valid signature failed!"
        );

        let bad = Message::new(b"ctx", b"wrong message");
        let bad_sig = NuggetPublicKeyScheme::sign(&mut keypair, &bad);

        assert!(bad_sig.verify(
            &bad,
            &NuggetPublicKeyScheme::into_double_public_key(&keypair)
        ));

        assert!(good != bad, "good == bad");
        assert!(good_sig.0 != bad_sig.0, "good sig == bad sig");

        assert!(
            !bad_sig.verify(
                &good,
                &NuggetPublicKeyScheme::into_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            !good_sig.verify(
                &bad,
                &NuggetPublicKeyScheme::into_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
    }

    #[test]
    fn test_double_public_key_double_signature_serialization_for_bls12_377() {
        let mut keypair =
            Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = NuggetPublicKeyScheme::sign(&mut keypair, &message);

        let signed_message = NuggetSignedMessage {
            message: message,
            publickey: NuggetPublicKey(
                keypair.into_public_key_in_signature_group().0,
                keypair.public.0,
            ),
            signature: good_sig0,
        };

        assert!(
            signed_message.verify(),
            "valid double signed message should verify"
        );

        let deserialized_signed_message = double_public_serialization_test::<
            TinyBLS<Bls12_377, ark_bls12_377::Config>,
            Bls12_377,
            ark_bls12_377::Config,
        >(signed_message);

        assert!(
            deserialized_signed_message.verify(),
            "deserialized valid double signed message should verify"
        );
    }

    #[test]
    fn test_double_public_key_double_signature_serialization_for_bls12_381() {
        let mut keypair =
            Keypair::<TinyBLS<Bls12_381, ark_bls12_381::Config>>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = NuggetPublicKeyScheme::sign(&mut keypair, &message);

        let signed_message = NuggetSignedMessage {
            message: message,
            publickey: NuggetPublicKey(
                keypair.into_public_key_in_signature_group().0,
                keypair.public.0,
            ),
            signature: good_sig0,
        };

        assert!(
            signed_message.verify(),
            "valid double signed message should verify"
        );

        let deserialized_signed_message = double_public_serialization_test::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            Bls12_381,
            ark_bls12_381::Config,
        >(signed_message);

        assert!(
            deserialized_signed_message.verify(),
            "deserialized valid double signed message should verify"
        );
    }

    #[test]
    fn test_single_bls_message_double_signature_scheme_for_bls12_377() {
        test_single_bls_message_double_signature_scheme::<
            TinyBLS<Bls12_377, ark_bls12_377::Config>,
            Bls12_377,
            ark_bls12_377::Config,
        >();
    }

    #[test]
    fn test_single_bls_message_double_signature_scheme_for_bls12_381() {
        test_single_bls_message_double_signature_scheme::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            Bls12_381,
            ark_bls12_381::Config,
        >();
    }
}
