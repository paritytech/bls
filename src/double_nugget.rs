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

use ark_ec::PrimeGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::NuggetPublicKey;
use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::DualScalarMultiplication;
use crate::nugget::{
    NuggetBLS, NuggetSignature, NuggetSignedMessage, PublicKeyInSignatureGroup,
    PublicKeyInSisterGroup,
};
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, KeypairVT, PublicKey, SecretKeyVT};
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
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E>;
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
    fn to_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup(self.0)
    }

    fn to_bls_public_key(&self) -> PublicKey<E> {
        PublicKey(self.1)
    }

    fn to_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<E::SignatureGroup> {
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

/// Ergonomic newtype over [`NuggetSignature<E>`] for the Nugget double-public-key
/// construction. Verifies against either [`NuggetDoublePublicKey<E>`] (plain) or
/// [`NuggetDoublePublicKeyGLV<E>`](crate::NuggetDoublePublicKeyGLV) (GLV-precomputed)
///
/// Byte-identical to [`NuggetSignature<E>`] and cryptographically interchangeable
/// with it. The newtype exists only so that `sig.verify(&msg, &pk)` reads cleanly
/// without supplying the `<S, H, P>` turbofish required by
/// [`NuggetSignature::verify`].
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DoubleNuggetSignature<E: EngineBLS>(pub NuggetSignature<E>);

impl<E: EngineBLS> DoubleNuggetSignature<E>
where
    E::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
{
    /// Verify this signature against any Nugget double public key — either the
    /// plain [`NuggetDoublePublicKey`] or the GLV-optimized
    /// [`NuggetDoublePublicKeyGLV`](crate::NuggetDoublePublicKeyGLV).  Rust
    /// infers `P` from the pubkey type, so the call site is turbofish-free:
    ///
    /// ```ignore
    /// sig.verify(&msg, &pk);      // plain pubkey: GLV scalar-mul with runtime 16-elt table
    /// sig.verify(&msg, &pk_glv);  // GLV pubkey:   GLV scalar-mul with 256-elt precomputed table
    /// ```
    pub fn verify<P>(&self, message: &Message, publickey: &P) -> bool
    where
        P: NuggetPublicKey<E, E::SignatureGroup>,
        E::SignatureGroup: ark_ec::PrimeGroup<ScalarField = E::Scalar>,
    {
        publickey.verify(message, &self.0)
    }
}

impl<E: EngineBLS> SerializableToBytes for DoubleNuggetSignature<E> {
    const SERIALIZED_BYTES_SIZE: usize =
        <NuggetSignature<E> as SerializableToBytes>::SERIALIZED_BYTES_SIZE;
}

impl<E: EngineBLS> From<NuggetSignature<E>> for DoubleNuggetSignature<E> {
    fn from(sig: NuggetSignature<E>) -> Self {
        DoubleNuggetSignature(sig)
    }
}

impl<E: EngineBLS> DoubleNuggetBLS<E> for SecretKeyVT<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E> {
        NuggetDoublePublicKey::new(
            <SecretKeyVT<E> as NuggetBLS<E, E::SignatureGroup>>::to_public_key_in_signature_group(
                self,
            )
            .0,
            self.to_public().0,
        )
    }
}

impl<E: EngineBLS> DoubleNuggetBLS<E> for KeypairVT<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E> {
        self.secret.to_nugget_double_public_key()
    }
}

impl<E: EngineBLS> DoubleNuggetBLS<E> for Keypair<E>
where
    E::SignatureGroup: SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKey<E> {
        self.to_vartime().to_nugget_double_public_key()
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

    use crate::{EngineBLS, Message, Signed, TinyBLS, serialize::SerializableToBytes};

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
        let bad = Message::new(b"ctx", b"wrong message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let pk = DoubleNuggetBLS::to_nugget_double_public_key(&keypair);

        let good_sig: DoubleNuggetSignature<EB> =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &good).into();
        let bad_sig: DoubleNuggetSignature<EB> =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &bad).into();

        assert!(
            good_sig.verify(&good, &pk),
            "Verification of a valid signature failed!"
        );
        assert!(
            bad_sig.verify(&bad, &pk),
            "Verification of a valid signature failed!"
        );

        assert!(good != bad, "good == bad");
        assert!(good_sig.0.0 != bad_sig.0.0, "good sig == bad sig");

        assert!(
            !bad_sig.verify(&good, &pk),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            !good_sig.verify(&bad, &pk),
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
            publickey: keypair.to_nugget_double_public_key(),
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
            publickey: keypair.to_nugget_double_public_key(),
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
