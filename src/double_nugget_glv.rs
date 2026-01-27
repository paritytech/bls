//! ## GLV-optimized BLS key pair with public key in both G1 and G2
//!
//! This module provides a GLV-optimized variant of the double nugget public key
//! for curves that support the GLV endomorphism.

use ark_ec::short_weierstrass::Projective;
use ark_ec::PrimeGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate, Write};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::{BLSGLVConfig, StrausPrecomputedTable};
use crate::nugget::{
    NuggetSignature, PublicKeyInSignatureGroup, PublicKeyInSisterGroup,
};
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
    fn serialize_with_mode<W: Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        self.public_key_in_signature_group.serialize_with_mode(&mut writer, compress)?;
        self.public_key.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.public_key_in_signature_group.serialized_size(compress) + self.public_key.serialized_size(compress)
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
    fn deserialize_with_mode<R: Read>(mut reader: R, compress: Compress, validate: Validate) -> Result<Self, SerializationError> {
        let public_key_in_signature_group = Projective::<C>::deserialize_with_mode(&mut reader, compress, validate)?;
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
        let glv_decomposition_of_gen_and_pubkey_sums = StrausPrecomputedTable::new(generator, public_key_in_signature_group);
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
