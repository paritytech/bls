//! ## GLV-optimized BLS key pair with public key in both G1 and G2
//!
//! This module provides a GLV-optimized variant of the double nugget public key
//! for curves that support the GLV endomorphism.

use ark_ec::short_weierstrass::Projective;
use ark_ec::PrimeGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::{BLSGLVConfig, StrausPrecomputedTable};
use crate::nugget::{NuggetSignature, PublicKeyInSignatureGroup, PublicKeyInSisterGroup};
use crate::serialize::SerializableToBytes;
use crate::single::PublicKey;
use crate::NuggetPublicKey;
use crate::{EngineBLS, Message};

/// BLS Public Key with sub keys in both groups, optimized for curves supporting GLV endomorphism.
/// This variant requires the signature group's curve config to implement GLVConfig,
/// enabling faster scalar multiplication through GLV decomposition.
#[derive(Debug, Clone)]
pub struct NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
{
    pub public_key_in_signature_group: Projective<C>,
    pub public_key: E::PublicKeyGroup,
    /// GLV-decomposed precomputed table for Strauss-Shamir, not serialized
    glv_decomposition_of_gen_and_pubkey_sums: StrausPrecomputedTable<Projective<C>>,
}

/// Manual serialization - only serialize the two public keys, not the precomputed GLV table
impl<E, C> CanonicalSerialize for NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.public_key_in_signature_group
            .serialize_with_mode(&mut writer, compress)?;
        self.public_key.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.public_key_in_signature_group.serialized_size(compress)
            + self.public_key.serialized_size(compress)
    }
}

impl<E, C> Valid for NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.public_key_in_signature_group.check()?;
        self.public_key.check()?;
        Ok(())
    }
}

/// Manual deserialization - deserialize two public keys and recompute the GLV table
impl<E, C> CanonicalDeserialize for NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let public_key_in_signature_group =
            Projective::<C>::deserialize_with_mode(&mut reader, compress, validate)?;
        let public_key = E::PublicKeyGroup::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self::new(public_key_in_signature_group, public_key))
    }
}

impl<E, C> NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
{
    /// Creates a new NuggetDoublePublicKeyGLV from the public key components.
    /// The Straus table is precomputed automatically for GLV-optimized verification.
    pub fn new(
        public_key_in_signature_group: Projective<C>,
        public_key: E::PublicKeyGroup,
    ) -> Self {
        let generator = <Projective<C> as PrimeGroup>::generator();
        let glv_decomposition_of_gen_and_pubkey_sums =
            StrausPrecomputedTable::new(generator, public_key_in_signature_group);
        Self {
            public_key_in_signature_group,
            public_key,
            glv_decomposition_of_gen_and_pubkey_sums,
        }
    }
}

impl<E, C, H> ChaumPedersenVerifier<E, Projective<C>, H> for NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
    Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = E::Scalar>,
    H: FixedOutputReset + Default + Clone,
{
}

impl<E, C> NuggetPublicKey<E, Projective<C>> for NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
    Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = E::Scalar>,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup(self.public_key_in_signature_group)
    }

    fn into_bls_public_key(&self) -> PublicKey<E> {
        PublicKey(self.public_key)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<Projective<C>> {
        PublicKeyInSisterGroup(self.public_key_in_signature_group)
    }

    fn straus_sister_group_precomputed_points(&self) -> &[Projective<C>] {
        &self.glv_decomposition_of_gen_and_pubkey_sums.table
    }

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool {
        signature.verify::<Projective<C>, Sha256, Self>(message, self)
    }
}

/// Serialization for NuggetDoublePublicKeyGLV
impl<E, C> SerializableToBytes for NuggetDoublePublicKeyGLV<E, C>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
{
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE;
}

use crate::nugget::{NuggetBLS, NuggetSignedMessage};
use crate::single::{Keypair, KeypairVT, SecretKeyVT};

pub trait DoubleNuggetBLSGLV<E, C>: NuggetBLS<E, Projective<C>>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
    Projective<C>: PrimeGroup<ScalarField = E::Scalar>,
{
    /// Return a double public object containing public keys both in G1 and G2
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E, C>;
}

impl<E, C> DoubleNuggetBLSGLV<E, C> for SecretKeyVT<E>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
    Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = E::Scalar>,
{
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E, C> {
        NuggetDoublePublicKeyGLV::new(
            <SecretKeyVT<E> as NuggetBLS<E, Projective<C>>>::into_public_key_in_signature_group(
                self,
            )
            .0,
            self.into_public().0,
        )
    }
}

impl<E, C> DoubleNuggetBLSGLV<E, C> for KeypairVT<E>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
    Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = E::Scalar>,
{
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E, C> {
        self.secret.into_nugget_double_public_key()
    }
}

impl<E, C> DoubleNuggetBLSGLV<E, C> for Keypair<E>
where
    E: EngineBLS<SignatureGroup = Projective<C>>,
    C: BLSGLVConfig,
    Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = E::Scalar>,
{
    fn into_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E, C> {
        self.into_vartime().into_nugget_double_public_key()
    }
}

/// Message with attached BLS signature using GLV-optimized double public key
pub type DoubleSignedMessageGLV<E, C> =
    NuggetSignedMessage<E, <E as EngineBLS>::SignatureGroup, NuggetDoublePublicKeyGLV<E, C>>;

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

    fn double_nugget_public_key_glv_serialization_test<
        EB: EngineBLS<Engine = E, SignatureGroup = Projective<C>>,
        E: PairingEngine,
        P: Bls12Config,
        C: BLSGLVConfig,
    >(
        x: DoubleSignedMessageGLV<EB, C>,
    ) -> DoubleSignedMessageGLV<EB, C>
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = EB::Scalar>,
    {
        let DoubleSignedMessageGLV {
            message,
            publickey,
            signature,
            ..
        } = x;

        let publickey =
            NuggetDoublePublicKeyGLV::<EB, C>::from_bytes(&publickey.to_bytes()).unwrap();
        let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

        DoubleSignedMessageGLV {
            message,
            publickey,
            signature,
            _phantom: PhantomData,
        }
    }

    fn test_single_bls_message_double_signature_scheme_glv<
        EB: EngineBLS<Engine = E, SignatureGroup = Projective<C>>,
        E: PairingEngine,
        P: Bls12Config,
        C: BLSGLVConfig,
    >()
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        Projective<C>: SerializableToBytes + PrimeGroup<ScalarField = EB::Scalar>,
    {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let public_key = DoubleNuggetBLSGLV::into_nugget_double_public_key(&mut keypair);
        let good_sig = <Keypair<EB> as NuggetBLS<EB, Projective<C>>>::sign(&mut keypair, &good);

        assert!(
            public_key.verify(&good, &good_sig),
            "Verification of a valid signature failed!"
        );

        let bad = Message::new(b"ctx", b"wrong message");
        let bad_sig = <Keypair<EB> as NuggetBLS<EB, Projective<C>>>::sign(&mut keypair, &bad);

        assert!(bad_sig.verify::<_, Sha256, _>(
            &bad,
            &DoubleNuggetBLSGLV::into_nugget_double_public_key(&keypair)
        ));

        assert!(good != bad, "good == bad");
        assert!(good_sig.0 != bad_sig.0, "good sig == bad sig");

        assert!(
            !bad_sig.verify::<_, Sha256, _>(
                &good,
                &DoubleNuggetBLSGLV::into_nugget_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            !good_sig.verify::<_, Sha256, _>(
                &bad,
                &DoubleNuggetBLSGLV::into_nugget_double_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
    }

    #[test]
    fn test_double_public_key_glv_double_signature_serialization_for_bls12_377() {
        type EB = TinyBLS<Bls12_377, ark_bls12_377::Config>;
        type C = ark_bls12_377::g1::Config;
        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let signed_message = DoubleSignedMessageGLV {
            message: message,
            publickey: keypair.into_nugget_double_public_key(),
            signature: good_sig0,
            _phantom: PhantomData,
        };

        assert!(
            signed_message.verify(),
            "valid double signed message should verify"
        );

        let deserialized_signed_message = double_nugget_public_key_glv_serialization_test::<
            TinyBLS<Bls12_377, ark_bls12_377::Config>,
            Bls12_377,
            ark_bls12_377::Config,
            C,
        >(signed_message);

        assert!(
            deserialized_signed_message.verify(),
            "deserialized valid double signed message should verify"
        );
    }

    #[test]
    fn test_double_public_key_glv_double_signature_serialization_for_bls12_381() {
        type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;
        type C = ark_bls12_381::g1::Config;

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let signed_message = DoubleSignedMessageGLV {
            message: message,
            publickey: keypair.into_nugget_double_public_key(),
            signature: good_sig0,
            _phantom: PhantomData,
        };

        assert!(
            signed_message.verify(),
            "valid double signed message should verify"
        );

        let deserialized_signed_message = double_nugget_public_key_glv_serialization_test::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            Bls12_381,
            ark_bls12_381::Config,
            C,
        >(signed_message);

        assert!(
            deserialized_signed_message.verify(),
            "deserialized valid double signed message should verify"
        );
    }

    #[test]
    fn test_single_bls_message_double_signature_scheme_glv_for_bls12_377() {
        test_single_bls_message_double_signature_scheme_glv::<
            TinyBLS<Bls12_377, ark_bls12_377::Config>,
            Bls12_377,
            ark_bls12_377::Config,
            ark_bls12_377::g1::Config,
        >();
    }

    #[test]
    fn test_single_bls_message_double_signature_scheme_glv_for_bls12_381() {
        test_single_bls_message_double_signature_scheme_glv::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            Bls12_381,
            ark_bls12_381::Config,
            ark_bls12_381::g1::Config,
        >();
    }
}
