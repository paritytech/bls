//! ## Precomputed-table variant of the double-nugget BLS public key — GLV-only
//!
//! **This module is for GLV-capable engines only.** Every type here is bound by
//! [`EngineBLSGLV`](crate::dual_scalar_mul::EngineBLSGLV); the 256-entry table
//! layout literally depends on the sister curve's `BLSGLVConfig` endomorphism
//! for its signed-point enumeration, so there is no non-GLV code path and no
//! way to instantiate these types for a non-GLV engine (`ZBLS`, `NonGLVCurve`
//! test curves, etc.). Use the plain
//! [`NuggetDoublePublicKey`](crate::NuggetDoublePublicKey) for those.
//!
//! The verifier skips the per-call 16-element subset-sum build by picking
//! them from the 256 precomputed entries (results in about 5% speed-up in release).
//!
//! Note that the GLV scalar decomposition and 4-base Strauss-Shamir main loop
//! are **not** unique to this variant — the plain pubkey runs the same GLV
//! path when the sig group has a `BLSGLVConfig` endomorphism; it just rebuilds
//! the subset-sum table on every verify.
//!

use ark_ec::PrimeGroup;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::NuggetPublicKey;
use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::{EngineBLSGLV, StrausPrecomputedTable};
use crate::nugget::{NuggetSignature, PublicKeyInSignatureGroup, PublicKeyInSisterGroup};
use crate::serialize::SerializableToBytes;
use crate::single::PublicKey;
use crate::{EngineBLS, Message};

/// Double public key carrying a precomputed 256-entry GLV-specific Straus-Shamir
/// subset-sumtable so verifiers skip the per-call table-build cost. See the module
/// doc for the GLV / `BLSGLVConfig` relationship and the memory/CPU tradeoff.
#[derive(Debug, Clone)]
pub struct NuggetDoublePublicKeyPrecomp<E: EngineBLSGLV> {
    pub public_key_in_signature_group: E::SignatureGroup,
    pub public_key: E::PublicKeyGroup,
    /// GLV-decomposed precomputed table for Strauss-Shamir, not serialized
    glv_decomposition_of_gen_and_pubkey_sums: StrausPrecomputedTable<E::SignatureGroup>,
}

/// Manual serialization - only serialize the two public keys, not the precomputed GLV table
impl<E: EngineBLSGLV> CanonicalSerialize for NuggetDoublePublicKeyPrecomp<E> {
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

impl<E: EngineBLSGLV> Valid for NuggetDoublePublicKeyPrecomp<E> {
    fn check(&self) -> Result<(), SerializationError> {
        self.public_key_in_signature_group.check()?;
        self.public_key.check()?;
        Ok(())
    }
}

/// Manual deserialization - deserialize two public keys and recompute the GLV table
impl<E: EngineBLSGLV> CanonicalDeserialize for NuggetDoublePublicKeyPrecomp<E> {
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

impl<E: EngineBLSGLV> NuggetDoublePublicKeyPrecomp<E> {
    /// Creates a new NuggetDoublePublicKeyPrecomp from the public key components.
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

impl<E, H> ChaumPedersenVerifier<E, E::SignatureGroup, H> for NuggetDoublePublicKeyPrecomp<E>
where
    E: EngineBLSGLV,
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    H: FixedOutputReset + Default + Clone,
{
}

impl<E: EngineBLSGLV> NuggetPublicKey<E, E::SignatureGroup> for NuggetDoublePublicKeyPrecomp<E>
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

/// Serialization for NuggetDoublePublicKeyPrecomp
impl<E: EngineBLSGLV> SerializableToBytes for NuggetDoublePublicKeyPrecomp<E> {
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE;
}

/// Strip the precomputed table and return the plain variant.
///
/// Enables reusing APIs that are specialised on
/// [`NuggetDoublePublicKey`](crate::double_nugget::NuggetDoublePublicKey) —
/// most notably the `ProofOfPossession` impls for `NuggetBLSPoP` and
/// `NuggetBLSnCPPoP`, which only have blanket impls for the plain pubkey
/// shape. Call site: `NuggetBLSPoP::verify(&pop, &(&pk_precomp).into())`.
///
impl<E: EngineBLSGLV> From<&NuggetDoublePublicKeyPrecomp<E>>
    for crate::double_nugget::NuggetDoublePublicKey<E>
{
    fn from(p: &NuggetDoublePublicKeyPrecomp<E>) -> Self {
        crate::double_nugget::NuggetDoublePublicKey::new(
            p.public_key_in_signature_group,
            p.public_key,
        )
    }
}

use crate::nugget::{NuggetBLS, NuggetSignedMessage};
use crate::single::{Keypair, KeypairVT, SecretKeyVT};

pub trait DoubleNuggetBLSPrecomp<E: EngineBLSGLV>: NuggetBLS<E, E::SignatureGroup>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    /// Return a double public object containing public keys both in G1 and G2
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyPrecomp<E>;
}

impl<E: EngineBLSGLV> DoubleNuggetBLSPrecomp<E> for SecretKeyVT<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyPrecomp<E> {
        NuggetDoublePublicKeyPrecomp::new(
            <SecretKeyVT<E> as NuggetBLS<E, E::SignatureGroup>>::to_public_key_in_signature_group(
                self,
            )
            .0,
            self.to_public().0,
        )
    }
}

impl<E: EngineBLSGLV> DoubleNuggetBLSPrecomp<E> for KeypairVT<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyPrecomp<E> {
        self.secret.to_nugget_double_public_key()
    }
}

impl<E: EngineBLSGLV> DoubleNuggetBLSPrecomp<E> for Keypair<E>
where
    E::SignatureGroup: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn to_nugget_double_public_key(&self) -> NuggetDoublePublicKeyPrecomp<E> {
        self.to_vartime().to_nugget_double_public_key()
    }
}

/// Message with attached BLS signature using GLV-optimized double public key
pub type DoubleSignedMessagePrecomp<E> =
    NuggetSignedMessage<E, <E as EngineBLS>::SignatureGroup, NuggetDoublePublicKeyPrecomp<E>>;

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

    fn double_nugget_public_key_glv_serialization_test<
        EB: EngineBLSGLV<Engine = E>,
        E: PairingEngine,
        P: Bls12Config,
    >(
        x: DoubleSignedMessagePrecomp<EB>,
    ) -> DoubleSignedMessagePrecomp<EB>
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        EB::SignatureGroup: PrimeGroup<ScalarField = EB::Scalar> + SerializableToBytes,
    {
        let DoubleSignedMessagePrecomp {
            message,
            publickey,
            signature,
            ..
        } = x;

        let publickey =
            NuggetDoublePublicKeyPrecomp::<EB>::from_bytes(&publickey.to_bytes()).unwrap();
        let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

        DoubleSignedMessagePrecomp {
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
        let pk_glv: NuggetDoublePublicKeyPrecomp<EB> =
            DoubleNuggetBLSPrecomp::to_nugget_double_public_key(&keypair);

        let good_sig: DoubleNuggetSignature<EB> =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &good).into();
        let bad_sig: DoubleNuggetSignature<EB> =
            <Keypair<EB> as NuggetBLS<EB, EB::SignatureGroup>>::sign(&mut keypair, &bad).into();

        // Route 1: verify through the plain pubkey (GLV scalar-mul, runtime 16-elt table).
        assert!(
            good_sig.verify(&good, &pk),
            "plain pk + good sig should verify"
        );
        assert!(
            bad_sig.verify(&bad, &pk),
            "plain pk + bad sig should verify"
        );
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
        assert!(good_sig.0.0 != bad_sig.0.0, "good sig == bad sig");
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

        let signed_message = DoubleSignedMessagePrecomp {
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

        let signed_message = DoubleSignedMessagePrecomp {
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

    /// Round-trip: build a precomp pubkey, convert via `From<&Precomp>` to the
    /// plain pubkey, and confirm the recovered plain pubkey matches a directly
    /// constructed plain pubkey (same stored G1/G2 points, same bytes).
    #[test]
    fn precomp_to_plain_conversion_round_trips() {
        use crate::double_nugget::{DoubleNuggetBLS, NuggetDoublePublicKey};

        type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;
        let keypair = Keypair::<EB>::generate(thread_rng());

        let pk_precomp: NuggetDoublePublicKeyPrecomp<EB> =
            DoubleNuggetBLSPrecomp::to_nugget_double_public_key(&keypair);
        let pk_from_precomp: NuggetDoublePublicKey<EB> = (&pk_precomp).into();
        let pk_direct: NuggetDoublePublicKey<EB> =
            DoubleNuggetBLS::to_nugget_double_public_key(&keypair);

        assert_eq!(
            pk_from_precomp.to_bytes(),
            pk_direct.to_bytes(),
            "serialized precomp→plain conversion must match a directly built plain pubkey"
        );
    }

    /// End-to-end PoP flow: generate a `NuggetBLSPoP`
    /// against the (plain) `NuggetDoublePublicKey` the generator trait requires,
    /// then verify it against the plain pubkey recovered from a precomp pubkey
    /// via `(&pk_precomp).into()`.
    ///
    #[test]
    fn pop_verify_via_precomp_conversion() {
        use crate::double_nugget::NuggetDoublePublicKey;
        use crate::nugget_pop::NuggetBLSPoP;
        use crate::{ProofOfPossession, ProofOfPossessionGenerator};
        use sha2::Sha256;

        type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;
        let mut keypair = Keypair::<EB>::generate(thread_rng());

        // Generate PoP against the plain pubkey shape (the only shape the
        // existing `ProofOfPossessionGenerator` impl supports).
        let pop = <Keypair<EB> as ProofOfPossessionGenerator<
            EB,
            Sha256,
            NuggetDoublePublicKey<EB>,
            NuggetBLSPoP<EB>,
        >>::generate_pok(&mut keypair);

        // Caller holds only the precomp pubkey; recover a plain view
        // conversion and verify.
        let pk_precomp: NuggetDoublePublicKeyPrecomp<EB> =
            DoubleNuggetBLSPrecomp::to_nugget_double_public_key(&keypair);
        let pk_plain: NuggetDoublePublicKey<EB> = (&pk_precomp).into();

        assert!(
            <NuggetBLSPoP<EB> as ProofOfPossession<EB, Sha256, NuggetDoublePublicKey<EB>>>::verify(
                &pop, &pk_plain,
            ),
            "PoP must verify against the plain pubkey recovered from the precomp pubkey"
        );
    }
}
