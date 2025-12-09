//! ## BLS key pair with public key in both G1 and G2
//! ## Unaggreagated BLS signature along side with their DLEQ proof
//!
//!
//! Implements schemes suggested the
//! [paper](https://eprint.iacr.org/2022/1611)
//! This is a specialized case of nugget where the sister group is G1.
//!
//! The scheme proposes for the public key be represented by doube points,
//! both in G1 and G2 and aggregate keys in G1.
//!
//! It also proposes that each individual BLS signature accompany a DLEQ proof
//! for faster verification

use alloc::vec::Vec;
use core::iter::once;

use ark_ec::{AffineRepr, CurveGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use sha2::Sha256;

use crate::chaum_pedersen_signature::{ChaumPedersenSigner, ChaumPedersenVerifier};
use crate::nugget::{
    NuggetPublicKeyScheme, NuggetSignature, NuggetSignedMessage, PublicKeyInSignatureGroup, PublicKeyInSisterGroup
};
use crate::schnorr_pop::SchnorrProof;
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, KeypairVT, PublicKey, SecretKeyVT, Signature};
use crate::{broken_derives, NuggetPublicKey};
use crate::{EngineBLS, Message, Signed};

/// BLS Public Key with sub keys in both groups.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DoublePublicKey<E: EngineBLS>(pub E::SignatureGroup, pub E::PublicKeyGroup);

impl <E: EngineBLS> NuggetPublicKey<E,E::SignatureGroup> for DoublePublicKey<E> where
    E::SignatureGroup : SerializableToBytes
{
        fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {self.0}

    fn into_bls_public_key(&self) -> PublicKey<E> {self.1}

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<E::SignatureGroup> {self.0}

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool {
        signature.verify(message, self)
    }
}
    
/// Serialization for DoublePublickey, We save one public key
impl<E: EngineBLS> SerializableToBytes for DoublePublicKey<E> {
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE;
}

pub trait DoublePublicKeyScheme<E: EngineBLS> {
    /// Returns the Public key in G1
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;

    /// Return a double public object containing public keys both in G1 and G2
    fn into_double_public_key(&self) -> DoublePublicKey<E>;

    fn sign(&mut self, message: &Message) -> NuggetSignature<E>;
}

impl<E: EngineBLS> DoublePublicKeyScheme<E> for SecretKeyVT<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    /// Returns the Public key in G1
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetPublicKeyScheme::<E, E::SignatureGroup>::into_public_key_in_signature_group(self)
    }

    fn into_double_public_key(&self) -> DoublePublicKey<E> {
        DoublePublicKey(
            DoublePublicKeyScheme::into_public_key_in_signature_group(self).0,
            self.into_public().0,
        )
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetPublicKeyScheme::<E, E::SignatureGroup>::sign(self, message)
    }
}

impl<E: EngineBLS> DoublePublicKeyScheme<E> for KeypairVT<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        DoublePublicKeyScheme::<E>::into_public_key_in_signature_group(&self.secret)
    }

    fn into_double_public_key(&self) -> DoublePublicKey<E> {
        self.secret.into_double_public_key()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        DoublePublicKeyScheme::sign(&mut self.secret, message)
    }
}

impl<E: EngineBLS> DoublePublicKeyScheme<E> for Keypair<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        DoublePublicKeyScheme::into_public_key_in_signature_group(&self.into_vartime())
    }

    fn into_double_public_key(&self) -> DoublePublicKey<E> {
        self.into_vartime().into_double_public_key()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        DoublePublicKeyScheme::sign(&mut self.into_vartime(), message)
    }
}

/// Message with attached BLS signature
///
type DoubleSignedMessage<E: EngineBLS> = NuggetSignedMessage<E, E::SignatureGroup, DoublePublicKey<E>>;

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
    

    use crate::{EngineBLS, Message, TinyBLS, serialize::SerializableToBytes
    };

    fn double_public_serialization_test<
        EB: EngineBLS<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >(
        x: DoubleSignedMessage<EB>,
    ) -> DoubleSignedMessage<EB>
    where
        <P as Bls12Config>::G2Config: WBConfig,
    WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        EB::SignatureGroup : SerializableToBytes,
    {
        let DoubleSignedMessage {
            message,
            publickey,
            signature,
        } = x;

        let publickey = DoublePublicKey::<EB>::from_bytes(&publickey.to_bytes()).unwrap();
        let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

        let publickey = publickey.into_nugget_public_key();
        DoubleSignedMessage {
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
    EB::SignatureGroup : SerializableToBytes,
    {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let public_key = DoublePublicKeyScheme::into_double_public_key(&mut keypair);
        let good_sig = DoublePublicKeyScheme::sign(&mut keypair, &good);

        assert!(
            public_key.verify(&good, &good_sig),
            "Verification of a valid signature failed!"
        );

        let bad = Message::new(b"ctx", b"wrong message");
        let bad_sig = DoublePublicKeyScheme::sign(&mut keypair, &bad);

        assert!(bad_sig.verify(
            &bad,
            &DoublePublicKeyScheme::into_double_public_key(&keypair)
        ));

        assert!(good != bad, "good == bad");
        assert!(good_sig.0 != bad_sig.0, "good sig == bad sig");

        assert!(
            !bad_sig.verify(
                &good,
                &DoublePublicKeyScheme::into_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            !good_sig.verify(
                &bad,
                &DoublePublicKeyScheme::into_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
    }

    #[test]
    fn test_double_public_key_double_signature_serialization_for_bls12_377() {
        let mut keypair =
            Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = DoublePublicKeyScheme::sign(&mut keypair, &message);

        let signed_message = DoubleSignedMessage {
            message: message,
            publickey: DoublePublicKey(
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
        let good_sig0 = DoublePublicKeyScheme::sign(&mut keypair, &message);

        let signed_message = DoubleSignedMessage {
            message: message,
            publickey: DoublePublicKey(
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
