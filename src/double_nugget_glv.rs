//! ## GLV-optimized BLS key pair with public key in both G1 and G2
//!
//! This module provides a GLV-optimized variant of the double nugget public key
//! for engines whose signature group has a GLV endomorphism.  The engine is
//! bound by [`EngineBLSGLV`](crate::dual_scalar_mul::EngineBLSGLV), which
//! enforce its Signature curve to be  `BLSGLVConfig` capable.

use ark_ec::PrimeGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::{EngineBLSGLV, StrausPrecomputedTable};
use crate::nugget::{NuggetSignature, PublicKeyInSignatureGroup, PublicKeyInSisterGroup};
use crate::serialize::SerializableToBytes;
use crate::single::PublicKey;
use crate::NuggetPublicKey;
use crate::{EngineBLS, Message};

/// BLS Public Key with sub keys in both groups, optimized for curves supporting GLV endomorphism.
/// The engine type `E` is bound by [`EngineBLSGLV`], which implies that
/// `E::SignatureGroup = Projective<C>` for some `C: BLSGLVConfig`.
#[derive(Debug, Clone)]
pub struct NuggetDoublePublicKeyGLV<E: EngineBLSGLV> {
    pub public_key_in_signature_group: E::SignatureGroup,
    pub public_key: E::PublicKeyGroup,
    /// GLV-decomposed precomputed table for Strauss-Shamir, not serialized
    glv_decomposition_of_gen_and_pubkey_sums: StrausPrecomputedTable<E::SignatureGroup>,
}

/// Manual serialization - only serialize the two public keys, not the precomputed GLV table
impl<E: EngineBLSGLV> CanonicalSerialize for NuggetDoublePublicKeyGLV<E> {
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

impl<E: EngineBLSGLV> Valid for NuggetDoublePublicKeyGLV<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.public_key_in_signature_group.check()?;
        self.public_key.check()?;
        Ok(())
    }
}

/// Manual deserialization - deserialize two public keys and recompute the GLV table
impl<E: EngineBLSGLV> CanonicalDeserialize for NuggetDoublePublicKeyGLV<E> {
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

impl<E: EngineBLSGLV> NuggetDoublePublicKeyGLV<E> {
    /// Creates a new NuggetDoublePublicKeyGLV from the public key components.
    /// The Straus table is precomputed automatically for GLV-optimized verification.
    pub fn new(
        public_key_in_signature_group: E::SignatureGroup,
        public_key: E::PublicKeyGroup,
    ) -> Self {
        let generator = <E::SignatureGroup as PrimeGroup>::generator();
        let glv_decomposition_of_gen_and_pubkey_sums =
            StrausPrecomputedTable::new(generator, public_key_in_signature_group);
        Self {
            public_key_in_signature_group,
            public_key,
            glv_decomposition_of_gen_and_pubkey_sums,
        }
    }
}

impl<E, H> ChaumPedersenVerifier<E, E::SignatureGroup, H> for NuggetDoublePublicKeyGLV<E>
where
    E: EngineBLSGLV,
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    H: FixedOutputReset + Default + Clone,
{
}

impl<E: EngineBLSGLV> NuggetPublicKey<E, E::SignatureGroup> for NuggetDoublePublicKeyGLV<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup(self.public_key_in_signature_group)
    }

    fn to_bls_public_key(&self) -> PublicKey<E> {
        PublicKey(self.public_key)
    }

    fn to_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<E::SignatureGroup> {
        PublicKeyInSisterGroup(self.public_key_in_signature_group)
    }

    fn straus_sister_group_precomputed_points(&self) -> &[E::SignatureGroup] {
        &self.glv_decomposition_of_gen_and_pubkey_sums.table
    }

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool {
        signature.verify::<E::SignatureGroup, Sha256, Self>(message, self)
    }
}

/// Serialization for NuggetDoublePublicKeyGLV
impl<E: EngineBLSGLV> SerializableToBytes for NuggetDoublePublicKeyGLV<E> {
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE;
}

use crate::nugget::{NuggetBLS, NuggetSignedMessage};
use crate::single::{Keypair, KeypairVT, SecretKeyVT};

pub trait DoubleNuggetBLSGLV<E: EngineBLSGLV>: NuggetBLS<E, E::SignatureGroup>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    /// Return a double public object containing public keys both in G1 and G2
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E>;
}

impl<E: EngineBLSGLV> DoubleNuggetBLSGLV<E> for SecretKeyVT<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E> {
        NuggetDoublePublicKeyGLV::new(
            <SecretKeyVT<E> as NuggetBLS<E, E::SignatureGroup>>::to_public_key_in_signature_group(
                self,
            )
            .0,
            self.to_public().0,
        )
    }
}

impl<E: EngineBLSGLV> DoubleNuggetBLSGLV<E> for KeypairVT<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E> {
        self.secret.to_nugget_double_public_key()
    }
}

impl<E: EngineBLSGLV> DoubleNuggetBLSGLV<E> for Keypair<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyGLV<E> {
        self.to_vartime().to_nugget_double_public_key()
    }
}

/// Message with attached BLS signature using GLV-optimized double public key
pub type DoubleSignedMessageGLV<E> =
    NuggetSignedMessage<E, <E as EngineBLS>::SignatureGroup, NuggetDoublePublicKeyGLV<E>>;

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
        EB: EngineBLSGLV<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >(
        x: DoubleSignedMessageGLV<EB>,
    ) -> DoubleSignedMessageGLV<EB>
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        EB::SignatureGroup: PrimeGroup<ScalarField = EB::Scalar> + SerializableToBytes,
    {
        let DoubleSignedMessageGLV {
            message,
            publickey,
            signature,
            ..
        } = x;

        let publickey =
            NuggetDoublePublicKeyGLV::<EB>::from_bytes(&publickey.to_bytes()).unwrap();
        let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

        DoubleSignedMessageGLV {
            message,
            publickey,
            signature,
            _phantom: PhantomData,
        }
    }

    fn test_single_bls_message_double_signature_scheme_glv<
        EB: EngineBLSGLV<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >()
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        EB::SignatureGroup: PrimeGroup<ScalarField = EB::Scalar> + SerializableToBytes,
    {
        use crate::double_nugget::{DoubleNuggetBLS, DoubleNuggetSignature, NuggetDoublePublicKey};

        let good = Message::new(b"ctx", b"test message");
        let bad = Message::new(b"ctx", b"wrong message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());

        // Build both pubkey shapes from the same keypair.
        let pk: NuggetDoublePublicKey<EB> = DoubleNuggetBLS::to_nugget_double_public_key(&keypair);
        let pk_glv: NuggetDoublePublicKeyGLV<EB> =
            DoubleNuggetBLSGLV::to_nugget_double_public_key(&keypair);

        let good_sig: DoubleNuggetSignature<EB> =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &good).into();
        let bad_sig: DoubleNuggetSignature<EB> =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &bad).into();

        // Route 1: verify through the plain pubkey (GLV scalar-mul, runtime 16-elt table).
        assert!(good_sig.verify(&good, &pk), "plain pk + good sig should verify");
        assert!(bad_sig.verify(&bad, &pk), "plain pk + bad sig should verify");
        assert!(
            !bad_sig.verify(&good, &pk),
            "plain pk + wrong-message sig should fail"
        );
        assert!(
            !good_sig.verify(&bad, &pk),
            "plain pk + wrong-message sig should fail"
        );

        // Route 2: verify through the GLV pubkey (GLV scalar-mul + 256-elt precomputed table).
        assert!(
            good_sig.verify(&good, &pk_glv),
            "GLV pk + good sig should verify"
        );
        assert!(
            bad_sig.verify(&bad, &pk_glv),
            "GLV pk + bad sig should verify"
        );
        assert!(
            !bad_sig.verify(&good, &pk_glv),
            "GLV pk + wrong-message sig should fail"
        );
        assert!(
            !good_sig.verify(&bad, &pk_glv),
            "GLV pk + wrong-message sig should fail"
        );

        assert!(good != bad, "good == bad");
        assert!(good_sig.0 .0 != bad_sig.0 .0, "good sig == bad sig");
    }

    #[test]
    fn test_double_public_key_glv_double_signature_serialization_for_bls12_377() {
        type EB = TinyBLS<Bls12_377, ark_bls12_377::Config>;
        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let signed_message = DoubleSignedMessageGLV {
            message: message,
            publickey: keypair.to_nugget_double_public_key(),
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
        >(signed_message);

        assert!(
            deserialized_signed_message.verify(),
            "deserialized valid double signed message should verify"
        );
    }

    #[test]
    fn test_double_public_key_glv_double_signature_serialization_for_bls12_381() {
        type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let message = Message::new(b"ctx", b"test message");
        let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let signed_message = DoubleSignedMessageGLV {
            message: message,
            publickey: keypair.to_nugget_double_public_key(),
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
        >();
    }

    #[test]
    fn test_single_bls_message_double_signature_scheme_glv_for_bls12_381() {
        test_single_bls_message_double_signature_scheme_glv::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            Bls12_381,
            ark_bls12_381::Config,
        >();
    }
}