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

use ark_ec::PrimeGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::DualScalarMultiplication;
use crate::nugget::{
    NuggetBLS, NuggetSignature, NuggetSignedMessage, PublicKeyInSignatureGroup,
    PublicKeyInSisterGroup,
};
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, KeypairVT, PublicKey, SecretKeyVT};
use crate::NuggetPublicKey;
use crate::{EngineBLS, Message};

/// BLS Public Key with sub keys in both groups.
/// It also stores signature group generator plus public key for Strauss-Shamir
/// speed up.
#[derive(Debug, Clone)]
pub struct NuggetDoublePublicKey<E: EngineBLS>(
    pub E::SignatureGroup,
    pub E::PublicKeyGroup,
    /// gen + public_key - precomputed for Strauss-Shamir, not serialized
    E::SignatureGroup,
);

/// Manual serialization - only serialize the two public keys, not the precomputed sum
impl<E: EngineBLS> CanonicalSerialize for NuggetDoublePublicKey<E> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(&mut writer, compress)?;
        self.1.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress) + self.1.serialized_size(compress)
    }
}

impl<E: EngineBLS> Valid for NuggetDoublePublicKey<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()?;
        self.1.check()?;
        Ok(())
    }
}

/// Manual deserialization - deserialize two public keys and recompute the precomputed sum
impl<E: EngineBLS> CanonicalDeserialize for NuggetDoublePublicKey<E> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let public_key_in_signature_group =
            E::SignatureGroup::deserialize_with_mode(&mut reader, compress, validate)?;
        let public_key = E::PublicKeyGroup::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self::new(public_key_in_signature_group, public_key))
    }
}

impl<E: EngineBLS> NuggetDoublePublicKey<E> {
    /// Creates a new NuggetDoublePublicKey from the public key components.
    /// The third element (gen + public_key) is computed automatically for Strauss-Shamir optimization.
    pub fn new(
        public_key_in_signature_group: E::SignatureGroup,
        public_key: E::PublicKeyGroup,
    ) -> Self {
        let gen_plus_public_key =
            <E::SignatureGroup as PrimeGroup>::generator() + public_key_in_signature_group;
        Self(
            public_key_in_signature_group,
            public_key,
            gen_plus_public_key,
        )
    }
}

pub trait DoubleNuggetBLS<E: EngineBLS>: NuggetBLS<E, E::SignatureGroup> {
    /// Return a double public object containing public keys both in G1 and G2
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E>;
}

impl<E: EngineBLS, H: FixedOutputReset + Default + Clone>
    ChaumPedersenVerifier<E, E::SignatureGroup, H> for NuggetDoublePublicKey<E>
where
    E::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
{
}

impl<E: EngineBLS> NuggetPublicKey<E, E::SignatureGroup> for NuggetDoublePublicKey<E>
where
    E::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup(self.0)
    }

    fn into_bls_public_key(&self) -> PublicKey<E> {
        PublicKey(self.1)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<E::SignatureGroup> {
        PublicKeyInSisterGroup(self.0)
    }

    fn straus_sister_group_precomputed_points(&self) -> &[E::SignatureGroup] {
        core::slice::from_ref(&self.2)
    }

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool {
        signature.verify::<E::SignatureGroup, Sha256, Self>(message, self)
    }
}

/// Serialization for DoublePublickey, We save one public key
impl<E: EngineBLS> SerializableToBytes for NuggetDoublePublicKey<E> {
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE;
}

impl<E: EngineBLS> DoubleNuggetBLS<E> for SecretKeyVT<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E> {
        NuggetDoublePublicKey::new(
            <SecretKeyVT<E> as NuggetBLS::<E, E::SignatureGroup>>::into_public_key_in_signature_group(self).0,
            self.into_public().0,
        )
    }
}

impl<E: EngineBLS> DoubleNuggetBLS<E> for KeypairVT<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E> {
        self.secret.into_nugget_double_public_key()
    }
}

impl<E: EngineBLS> DoubleNuggetBLS<E> for Keypair<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E> {
        self.into_vartime().into_nugget_double_public_key()
    }
}

/// Message with attached BLS signature
///
pub type DoubleSignedMessage<E> =
    NuggetSignedMessage<E, <E as EngineBLS>::SignatureGroup, NuggetDoublePublicKey<E>>;

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand::thread_rng;

    use super::*;

    use core::marker::PhantomData;

    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12Config;
    use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ec::pairing::Pairing as PairingEngine;

    use crate::{serialize::SerializableToBytes, EngineBLS, Message, Signed, TinyBLS};

    fn double_nugget_public_key_serialization_test<
        EB: EngineBLS<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >(
        x: DoubleSignedMessage<EB>,
    ) -> DoubleSignedMessage<EB>
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        EB::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
    {
        let DoubleSignedMessage {
            message,
            publickey,
            signature,
            ..
        } = x;

        let publickey = NuggetDoublePublicKey::<EB>::from_bytes(&publickey.to_bytes()).unwrap();
        let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

        DoubleSignedMessage {
            message,
            publickey,
            signature,
            _phantom: PhantomData,
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
        EB::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
    {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let public_key = DoubleNuggetBLS::into_nugget_double_public_key(&mut keypair);
        let good_sig =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &good);

        assert!(
            public_key.verify(&good, &good_sig),
            "Verification of a valid signature failed!"
        );

        let bad = Message::new(b"ctx", b"wrong message");
        let bad_sig = <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &bad);

        assert!(bad_sig.verify::<_, Sha256, _>(
            &bad,
            &DoubleNuggetBLS::into_nugget_double_public_key(&keypair)
        ));

        assert!(good != bad, "good == bad");
        assert!(good_sig.0 != bad_sig.0, "good sig == bad sig");

        assert!(
            !bad_sig.verify::<_, Sha256, _>(
                &good,
                &DoubleNuggetBLS::into_nugget_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            !good_sig.verify::<_, Sha256, _>(
                &bad,
                &DoubleNuggetBLS::into_nugget_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
    }

    #[test]
    fn test_double_public_key_double_signature_serialization_for_bls12_377() {
        type EB = TinyBLS<Bls12_377, ark_bls12_377::Config>;
        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let signed_message = DoubleSignedMessage {
            message: message,
            publickey: keypair.into_nugget_double_public_key(),
            signature: good_sig0,
            _phantom: PhantomData,
        };

        assert!(
            signed_message.verify(),
            "valid double signed message should verify"
        );

        let deserialized_signed_message = double_nugget_public_key_serialization_test::<
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
        type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let signed_message = DoubleSignedMessage {
            message: message,
            publickey: keypair.into_nugget_double_public_key(),
            signature: good_sig0,
            _phantom: PhantomData,
        };

        assert!(
            signed_message.verify(),
            "valid double signed message should verify"
        );

        let deserialized_signed_message = double_nugget_public_key_serialization_test::<
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
