use ark_ec::{CurveGroup, PrimeGroup};

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::dual_scalar_mul::DualScalarMultiplication;
use crate::nugget::{
    NuggetBLS, NuggetPublicKey, NuggetSignature, PublicKeyInSignatureGroup, PublicKeyInSisterGroup,
};
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, KeypairVT, PublicKey, SecretKeyVT};
use crate::{EngineBLS, Message};

/// BLS Public Key with sub keys in both G1 and G2 and on a third curve with same prime order group.
/// It also precomputes generator plus public key for Strauss-Shamir speed up.
#[derive(Debug, Clone)]
pub struct NuggetTriplePublicKey<E: EngineBLS, S: CurveGroup>(
    pub E::SignatureGroup,
    pub E::PublicKeyGroup,
    pub S,
    /// gen + public_key_in_sister_group - precomputed for Strauss-Shamir, not serialized
    S,
)
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes;

impl<E: EngineBLS, S: CurveGroup> NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    /// Creates a new NuggetTriplePublicKey from the public key components.
    /// The fourth element (gen + public_key_in_sister_group) is computed automatically.
    pub fn new(
        public_key_in_signature_group: E::SignatureGroup,
        public_key: E::PublicKeyGroup,
        public_key_in_sister_group: S,
    ) -> Self {
        let gen_plus_pub = <S as PrimeGroup>::generator() + public_key_in_sister_group;
        Self(
            public_key_in_signature_group,
            public_key,
            public_key_in_sister_group,
            gen_plus_pub,
        )
    }
}

/// Manual serialization - only serialize the three public keys, not the precomputed sum
impl<E: EngineBLS, S: CurveGroup> CanonicalSerialize for NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn serialize_with_mode<W: Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(&mut writer, compress)?;
        self.1.serialize_with_mode(&mut writer, compress)?;
        self.2.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
            + self.1.serialized_size(compress)
            + self.2.serialized_size(compress)
    }
}

impl<E: EngineBLS, S: CurveGroup> Valid for NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.0.check()?;
        self.1.check()?;
        self.2.check()?;
        Ok(())
    }
}

/// Manual deserialization - deserialize three public keys and recompute the precomputed sum
impl<E: EngineBLS, S: CurveGroup> CanonicalDeserialize for NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let public_key_in_signature_group =
            E::SignatureGroup::deserialize_with_mode(&mut reader, compress, validate)?;
        let public_key = E::PublicKeyGroup::deserialize_with_mode(&mut reader, compress, validate)?;
        let public_key_in_sister_group = S::deserialize_with_mode(&mut reader, compress, validate)?;
        Ok(Self::new(
            public_key_in_signature_group,
            public_key,
            public_key_in_sister_group,
        ))
    }
}

pub trait TripleNuggetBLS<
    E: EngineBLS,
    S: CurveGroup + PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
>: NuggetBLS<E, S>
{
    fn into_nugget_triple_public_key(&self) -> NuggetTriplePublicKey<E, S>;
}

impl<
        E: EngineBLS,
        S: CurveGroup + DualScalarMultiplication,
        H: FixedOutputReset + Default + Clone,
    > ChaumPedersenVerifier<E, S, H> for NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    E::SignatureGroup: DualScalarMultiplication,
{
}

impl<E: EngineBLS, S: CurveGroup + DualScalarMultiplication> NuggetPublicKey<E, S>
    for NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    E::SignatureGroup: DualScalarMultiplication,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup::<E>(self.0)
    }

    fn into_bls_public_key(&self) -> PublicKey<E> {
        PublicKey::<E>(self.1)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        PublicKeyInSisterGroup::<S>(self.2)
    }

    fn straus_sister_group_precomputed_points(&self) -> &[S] {
        core::slice::from_ref(&self.3)
    }

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool {
        signature.verify::<S, Sha256, Self>(message, self)
    }
}

/// Serialization for NuggetPublickey
/// Serialize size depends on the size of the public key of the thrid curve
/// so S, the sister curve  need to implement SerializableToBytes
impl<E: EngineBLS, S: CurveGroup> SerializableToBytes for NuggetTriplePublicKey<E, S>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    const SERIALIZED_BYTES_SIZE: usize =
        E::SIGNATURE_SERIALIZED_SIZE + E::PUBLICKEY_SERIALIZED_SIZE + S::SERIALIZED_BYTES_SIZE;
}

impl<E: EngineBLS, S: CurveGroup> TripleNuggetBLS<E, S> for SecretKeyVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_nugget_triple_public_key(&self) -> NuggetTriplePublicKey<E, S> {
        NuggetTriplePublicKey::new(
            NuggetBLS::<E, S>::into_public_key_in_signature_group(self).0,
            self.into_public().0,
            self.into_public_key_in_sister_group().0,
        )
    }
}

impl<E: EngineBLS, S: CurveGroup> TripleNuggetBLS<E, S> for KeypairVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_nugget_triple_public_key(&self) -> NuggetTriplePublicKey<E, S> {
        NuggetTriplePublicKey::new(
            NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.secret).0,
            self.secret.into_public().0,
            self.secret.into_public_key_in_sister_group().0,
        )
    }
}

impl<E: EngineBLS, S: CurveGroup> TripleNuggetBLS<E, S> for Keypair<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_nugget_triple_public_key(&self) -> NuggetTriplePublicKey<E, S> {
        NuggetTriplePublicKey::new(
            NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.into_vartime()).0,
            self.into_vartime().public.0,
            self.into_vartime().into_public_key_in_sister_group().0,
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand::thread_rng;

    use super::*;

    use ark_bls12_381::Bls12_381;
    use ark_ec::bls12::Bls12Config;
    use ark_ec::hashing::curve_maps::wb::{WBConfig, WBMap};
    use ark_ec::hashing::map_to_curve_hasher::MapToCurve;
    use ark_ec::pairing::Pairing as PairingEngine;
    use ark_ed_by_bls12_381;
    use ark_sw_by_bls12_381;

    use crate::{EngineBLS, Message, TinyBLS};

    //TODO test for triple public key serialization
    fn test_single_bls_message_double_signature_triple_publickey_scheme<
        EB: EngineBLS<Engine = E>,
        S: CurveGroup
            + PrimeGroup<ScalarField = EB::Scalar>
            + SerializableToBytes
            + DualScalarMultiplication,
        E: PairingEngine,
        P: Bls12Config,
    >()
    where
        <P as Bls12Config>::G2Config: WBConfig,
        WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
        EB::SignatureGroup: DualScalarMultiplication,
    {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let public_key = TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair);
        let good_sig = NuggetBLS::<EB, S>::sign(&mut keypair, &good);

        assert!(
            public_key.verify(&good, &good_sig),
            "Verification of a valid signature failed!"
        );

        let bad = Message::new(b"ctx", b"wrong message");
        let bad_sig = NuggetBLS::<EB, S>::sign(&mut keypair, &bad);

        assert!(bad_sig.verify::<_, Sha256, _>(
            &bad,
            &TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair)
        ));

        assert!(good != bad, "good == bad");
        assert!(good_sig.0 != bad_sig.0, "good sig == bad sig");

        assert!(
            !bad_sig.verify::<_, Sha256, _>(
                &good,
                &TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
        assert!(
            !good_sig.verify::<_, Sha256, _>(
                &bad,
                &TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair)
            ),
            "Verification of a signature on a different message passed!"
        );
    }

    // We don't have a curve for bls12-377 yet
    // #[test]
    // fn test_single_bls_message_double_signature_triple_publickey_scheme_for_bls12_377() {
    //     test_single_bls_message_double_signature_triple_publickey_scheme::<
    //         TinyBLS<Bls12_377, ark_bls12_377::Config>,
    //         twisted_edwards::Projective<ark_ed_by_bls12_381::EdwardsConfig>,
    //         Bls12_377,
    //         ark_bls12_377::Config,

    //     >();
    // }

    impl SerializableToBytes for ark_ed_by_bls12_381::EdwardsProjective {
        const SERIALIZED_BYTES_SIZE: usize = 40;
    }

    impl SerializableToBytes for ark_sw_by_bls12_381::SWProjective {
        const SERIALIZED_BYTES_SIZE: usize = 33;
    }

    // Mark test curves as NonGLVCurve to get the Strauss-Shamir implementation
    use crate::dual_scalar_mul::NonGLVCurve;
    impl NonGLVCurve for ark_ed_by_bls12_381::EdwardsProjective {}

    #[test]
    fn test_single_bls_message_double_signature_triple_publickey_scheme_for_bls12_381_edwards() {
        test_single_bls_message_double_signature_triple_publickey_scheme::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            ark_ed_by_bls12_381::EdwardsProjective,
            Bls12_381,
            ark_bls12_381::Config,
        >();
    }

    #[test]
    fn test_single_bls_message_double_signature_triple_publickey_scheme_for_bls12_381_weierstrass()
    {
        test_single_bls_message_double_signature_triple_publickey_scheme::<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            ark_sw_by_bls12_381::SWProjective,
            Bls12_381,
            ark_bls12_381::Config,
        >();
    }

    //NuggetSignedMessage<E, <E as EngineBLS>::SignatureGroup, NuggetDoublePublicKey<E>>;
    // fn triple_nugget_public_key_serialization_test<
    //     EB: EngineBLS<Engine = E>,
    //     E: PairingEngine,
    //     S: CurveGroup + PrimeGroup<ScalarField = EB::Scalar> + SerializableToBytes,
    //     P: Bls12Config,
    // >(
    //     x: NuggetSignedMessage<EB, S, NuggetTriplePublicKey<EB, S>>,
    // ) -> NuggetSignedMessage<EB, S, NuggetTriplePublicKey<EB, S>>
    // where
    //     <P as Bls12Config>::G2Config: WBConfig,
    //     WBMap<<P as Bls12Config>::G2Config>: MapToCurve<<E as PairingEngine>::G2>,
    //     EB::SignatureGroup: SerializableToBytes,
    // {
    //     let NuggetSignedMessage::<EB, S, NuggetTriplePublicKey<EB, S>> {
    //         message,
    //         publickey,
    //         signature,
    //         ..
    //     } = x;

    //     let publickey = NuggetTriplePublicKey::<EB, S>::from_bytes(&publickey.to_bytes()).unwrap();
    //     let signature = NuggetSignature::<EB>::from_bytes(&signature.to_bytes()).unwrap();

    //     NuggetSignedMessage::<EB, S, NuggetTriplePublicKey<EB, S>> {
    //         message,
    //         publickey,
    //         signature,
    //         _phantom: PhantomData,
    //     }
    // }

    #[test]
    fn test_serialize_triple_public_key_for_bls12_381_sw() {
        type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;
        type S = ark_sw_by_bls12_381::SWProjective;

        let keypair = Keypair::<EB>::generate(thread_rng());
        let deserialized_sister_public_key = S::from_bytes(
            &NuggetBLS::<EB, S>::into_public_key_in_sister_group(&keypair)
                .0
                .to_bytes(),
        )
        .unwrap();

        assert!(
            deserialized_sister_public_key
                == NuggetBLS::<EB, S>::into_public_key_in_sister_group(&keypair).0,
            "deserialized public key in the sister group should be the same as the original"
        );

        // let deserialized_public_key = NuggetTriplePublicKey::<EB, S>::from_bytes(&TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair).to_bytes()).unwrap();

        // assert!(
        //     deserialized_public_key.0 == TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair).0,
        //     "deserialized public key should be the same as the original"
        // );
    }

    // #[test]
    // fn test_triple_public_key_for_bls12_381_sw() {
    //     type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;
    //     type S = sw_by_bls12_381::SWProjective;

    //     let mut keypair = Keypair::<EB>::generate(thread_rng());
    //     let message = Message::new(b"ctx", b"test message");
    //     let good_sig0 = <Keypair<_> as NuggetBLS<_, S>::sign(
    //         &mut keypair,
    //         &message,
    //     );

    //     let signed_message = DoubleSignedMessage {
    //         message: message,
    //         publickey: keypair.into_nugget_double_public_key(),
    //         signature: good_sig0,
    //         _phantom: PhantomData,
    //     };

    //     assert!(
    //         signed_message.verify(),
    //         "valid double signed message should verify"
    //     );

    //     let deserialized_signed_message = double_nugget_public_key_serialization_test::<
    //         TinyBLS<Bls12_381, ark_bls12_381::Config>,
    //         Bls12_381,
    //         ark_bls12_381::Config,
    //     >(signed_message);

    //     assert!(
    //         deserialized_signed_message.verify(),
    //         "deserialized valid double signed message should verify"
    //     );
    // }
}
