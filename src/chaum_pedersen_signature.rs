use alloc::vec;
use alloc::vec::Vec;

use ark_ec::{CurveGroup, PrimeGroup, VariableBaseMSM};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};

use digest::FixedOutputReset;

#[cfg(feature = "benchmark")]
use std::time::Instant;

use crate::dual_scalar_mul::DualScalarMultiplication;
use crate::engine::EngineBLS;
use crate::nugget::{NuggetBLS, NuggetPublicKey, NuggetSignature};
use crate::schnorr_pop::SchnorrProof;
use crate::serialize::SerializableToBytes;
use crate::{Message, SecretKeyVT};

pub type ChaumPedersenSignature<E> = NuggetSignature<E>;

/// ProofOfPossion trait which should be implemented by secret
pub trait ChaumPedersenSigner<E: EngineBLS, S: CurveGroup, H: FixedOutputReset + Default + Clone>
where
    S: PrimeGroup<ScalarField = E::Scalar>,
{
    /// The proof of possession generator is supposed to
    /// to produce a schnoor signature of the message using
    /// the secret key which it claim to possess.
    fn generate_cp_signature(&mut self, message: &Message) -> ChaumPedersenSignature<E>;

    fn generate_witness_scaler(
        &self,
        message_point_as_bytes: &Vec<u8>,
    ) -> <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField;

    fn generate_dleq_proof(
        &mut self,
        message: &Message,
        bls_signature: E::SignatureGroup,
    ) -> SchnorrProof<E>;
}

/// This should be implemented by public key
pub trait ChaumPedersenVerifier<
    E: EngineBLS,
    S: CurveGroup + DualScalarMultiplication + SerializableToBytes,
    H: FixedOutputReset + Default + Clone,
>: NuggetPublicKey<E, S> where
    S: PrimeGroup<ScalarField = E::Scalar>,
    E::SignatureGroup: DualScalarMultiplication,
{
    #[allow(non_snake_case)]
    fn verify_cp_signature_naive(
        &self,
        message: &Message,
        signature_proof: &ChaumPedersenSignature<E>,
    ) -> bool {
        #[cfg(feature = "benchmark")]
        let total_start = Instant::now();

        let signature_as_scalars_of_sister_group: (S::ScalarField, S::ScalarField) =
            (signature_proof.1 .0, signature_proof.1 .1);
        let message_as_point_on_signature_curve = message.hash_to_signature_curve::<E>();

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let A_check_point = <S as PrimeGroup>::generator() * signature_as_scalars_of_sister_group.1
            + self.into_public_key_in_sister_group().0 * signature_as_scalars_of_sister_group.0;
        #[cfg(feature = "benchmark")]
        println!(
            "[Naive] A_check_point (2 scalar muls + add): {:?}",
            start.elapsed()
        );

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let B_check_point = message_as_point_on_signature_curve * signature_proof.1 .1
            + signature_proof.0 * signature_proof.1 .0;
        #[cfg(feature = "benchmark")]
        println!(
            "[Naive] B_check_point (2 scalar muls + add): {:?}",
            start.elapsed()
        );

        let A_point_as_bytes = A_check_point.to_bytes();
        let B_point_as_bytes = E::signature_point_to_byte(&B_check_point);

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_proof.0);
        let message_point_as_bytes =
            E::signature_point_to_byte(&message_as_point_on_signature_curve);
        let public_key_in_signature_group_as_bytes =
            E::signature_point_to_byte(&self.into_public_key_in_signature_group().0);

        let resulting_proof_basis = [
            message_point_as_bytes,
            public_key_in_signature_group_as_bytes,
            signature_point_as_bytes,
            A_point_as_bytes,
            B_point_as_bytes,
        ]
        .concat();

        let hasher = <DefaultFieldHasher<H> as HashToField<
            <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField,
        >>::new(&[]);
        let c_check: <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField =
            hasher.hash_to_field::<1>(resulting_proof_basis.as_slice())[0];

        #[cfg(feature = "benchmark")]
        println!("[Naive] TOTAL: {:?}", total_start.elapsed());

        c_check == signature_proof.1 .0
    }

    #[allow(non_snake_case)]
    fn verify_cp_signature(
        &self,
        message: &Message,
        signature_proof: &ChaumPedersenSignature<E>,
    ) -> bool {
        #[cfg(feature = "benchmark")]
        let total_start = Instant::now();

        let signature_as_scalars_of_sister_group: (S::ScalarField, S::ScalarField) =
            (signature_proof.1 .0, signature_proof.1 .1);
        let gen = <S as PrimeGroup>::generator();
        let pubkey = self.into_public_key_in_sister_group().0;

        let message_as_point_on_signature_curve = message.hash_to_signature_curve::<E>();
        let message_point_as_bytes =
            E::signature_point_to_byte(&message_as_point_on_signature_curve);


        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let A_check_point = S::dual_scalar_mul(
            &signature_as_scalars_of_sister_group.1,
            &signature_as_scalars_of_sister_group.0,
            &gen,
            &pubkey,
            Some(self.straus_sister_group_precomputed_points()),
        );
        #[cfg(feature = "benchmark")]
        println!(
            "[CP] A_check_point (dual_scalar_mul): {:?}",
            start.elapsed()
        );

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        let B_check_point = E::SignatureGroup::dual_scalar_mul(
            &signature_proof.1 .0,
            &signature_proof.1 .1,
            &signature_proof.0,
            &message_as_point_on_signature_curve,
            None, //not precomputed //Some(&[signature_proof.0 + message.hash_to_signature_curve::<E>()]),
        );
        #[cfg(feature = "benchmark")]
        println!(
            "[CP] B_check_point (dual_scalar_mul): {:?}",
            start.elapsed()
        );

        let A_point_as_bytes = A_check_point.to_bytes();
        let B_point_as_bytes = E::signature_point_to_byte(&B_check_point);

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_proof.0);
        let public_key_in_signature_group_as_bytes =
            E::signature_point_to_byte(&self.into_public_key_in_signature_group().0);

        let resulting_proof_basis = [
            message_point_as_bytes,
            public_key_in_signature_group_as_bytes,
            signature_point_as_bytes,
            A_point_as_bytes,
            B_point_as_bytes,
        ]
        .concat();

        let hasher = <DefaultFieldHasher<H> as HashToField<
            <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField,
        >>::new(&[]);
        let c_check: <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField =
            hasher.hash_to_field::<1>(resulting_proof_basis.as_slice())[0];

        #[cfg(feature = "benchmark")]
        println!("[CP] TOTAL: {:?}", total_start.elapsed());

        c_check == signature_proof.1 .0
    }

    #[allow(non_snake_case)]
    fn verify_cp_signature_with_msm_optimization(
        &self,
        message: &Message,
        signature_proof: &ChaumPedersenSignature<E>,
    ) -> bool {
        let signature_as_scalars_of_sister_group: (S::ScalarField, S::ScalarField) =
            (signature_proof.1 .0, signature_proof.1 .1);

        let message_as_point_on_signature_curve = message.hash_to_signature_curve::<E>();

        let A_check_point = S::msm(
            (vec![
                <S as PrimeGroup>::generator().into_affine(),
                self.into_public_key_in_sister_group().0.into_affine(),
            ])
            .as_slice(),
            (vec![
                signature_as_scalars_of_sister_group.1,
                signature_as_scalars_of_sister_group.0,
            ])
            .as_slice(),
        )
        .unwrap();

        let B_check_point = E::SignatureGroup::msm(
            (vec![
                signature_proof.0.into_affine(),
                message_as_point_on_signature_curve.into_affine(),
            ])
            .as_slice(),
            (vec![signature_proof.1 .0, signature_proof.1 .1]).as_slice(),
        )
        .unwrap();

        let A_point_as_bytes = A_check_point.to_bytes();
        let B_point_as_bytes = E::signature_point_to_byte(&B_check_point);

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_proof.0);
        let message_point_as_bytes =
            E::signature_point_to_byte(&message_as_point_on_signature_curve);
        let public_key_in_signature_group_as_bytes =
            E::signature_point_to_byte(&self.into_public_key_in_signature_group().0);

        let resulting_proof_basis = [
            message_point_as_bytes,
            public_key_in_signature_group_as_bytes,
            signature_point_as_bytes,
            A_point_as_bytes,
            B_point_as_bytes,
        ]
        .concat();

        let hasher = <DefaultFieldHasher<H> as HashToField<
            <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField,
        >>::new(&[]);
        let c_check: <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField =
            hasher.hash_to_field::<1>(resulting_proof_basis.as_slice())[0];

        c_check == signature_proof.1 .0
    }
}

impl<E: EngineBLS, S: CurveGroup, H: FixedOutputReset + Default + Clone>
    ChaumPedersenSigner<E, S, H> for SecretKeyVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn generate_cp_signature(&mut self, message: &Message) -> ChaumPedersenSignature<E> {
        //First we generate a vanila BLS Signature;
        let bls_signature = SecretKeyVT::sign(self, message);
        NuggetSignature(
            bls_signature.0,
            <SecretKeyVT<E> as ChaumPedersenSigner<E, S, H>>::generate_dleq_proof(
                self,
                message,
                bls_signature.0,
            ),
        )
    }

    #[allow(non_snake_case)]
    fn generate_dleq_proof(
        &mut self,
        message: &Message,
        bls_signature: E::SignatureGroup,
    ) -> SchnorrProof<E> {
        let signature_point = bls_signature;
        let message_point = message.hash_to_signature_curve::<E>();

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_point);
        let message_point_as_bytes = E::signature_point_to_byte(&message_point);
        let public_key_in_signature_group_as_bytes = E::signature_point_to_byte(
            &NuggetBLS::<E, S>::into_public_key_in_signature_group(self).0,
        );

        let mut k = <SecretKeyVT<E> as ChaumPedersenSigner<E, S, H>>::generate_witness_scaler(
            self,
            &message_point_as_bytes,
        );

        let A_point = <S as PrimeGroup>::generator() * k;
        let B_point = message_point * k;

        let A_point_as_bytes = A_point.to_bytes();
        let B_point_as_bytes = E::signature_point_to_byte(&B_point);

        let proof_basis = [
            message_point_as_bytes,
            public_key_in_signature_group_as_bytes,
            signature_point_as_bytes,
            A_point_as_bytes,
            B_point_as_bytes,
        ]
        .concat();

        let hasher = <DefaultFieldHasher<H> as HashToField<
            <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField,
        >>::new(&[]);

        let c = hasher.hash_to_field::<1>(proof_basis.as_slice())[0];

        let s = k - c * self.0;

        ::zeroize::Zeroize::zeroize(&mut k); //clear secret witness from memory

        (c, s)
    }

    fn generate_witness_scaler(
        &self,
        message_point_as_bytes: &Vec<u8>,
    ) -> <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField {
        let secret_key_as_bytes = self.to_bytes();

        let mut secret_key_hasher = H::default();
        secret_key_hasher.update(secret_key_as_bytes.as_slice());
        let hashed_secret_key = secret_key_hasher.finalize_fixed_reset().to_vec();

        let hasher = <DefaultFieldHasher<H> as HashToField<
            <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField,
        >>::new(&[]);
        let scalar_seed = [hashed_secret_key, message_point_as_bytes.clone()].concat();
        hasher.hash_to_field::<1>(scalar_seed.as_slice())[0]
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use rand::thread_rng;

    use super::*;

    use crate::double_nugget_glv::{DoubleNuggetBLSGLV, NuggetDoublePublicKeyGLV};
    use crate::{DoubleNuggetBLS, Keypair, NuggetDoublePublicKey, TinyBLS381};
    use sha2::Sha256;

    #[test]
    fn test_chaum_pedersen_verification() {
        type EB = TinyBLS381;

        let message = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let good_sig = <Keypair<EB> as NuggetBLS<EB, <EB as EngineBLS>::SignatureGroup>>::sign(
            &mut keypair,
            &message,
        );

        let publickey: NuggetDoublePublicKey<EB> =
            DoubleNuggetBLS::<EB>::into_nugget_double_public_key(&keypair);

        assert!(ChaumPedersenVerifier::<
            EB,
            <EB as EngineBLS>::SignatureGroup,
            Sha256,
        >::verify_cp_signature_naive(
            &publickey, &message, &good_sig,
        ));

        assert!(ChaumPedersenVerifier::<
            EB,
            <EB as EngineBLS>::SignatureGroup,
            Sha256,
        >::verify_cp_signature(
            &publickey, &message, &good_sig,
        ));

        assert!(ChaumPedersenVerifier::<
            EB,
            <EB as EngineBLS>::SignatureGroup,
            Sha256,
        >::verify_cp_signature_with_msm_optimization(
            &publickey, &message, &good_sig,
        ));

        let publickey_glv: NuggetDoublePublicKeyGLV<EB, ark_bls12_381::g1::Config> =
            DoubleNuggetBLSGLV::<EB, ark_bls12_381::g1::Config>::into_nugget_double_public_key(
                &keypair,
            );

        assert!(ChaumPedersenVerifier::<
            EB,
            <EB as EngineBLS>::SignatureGroup,
            Sha256,
        >::verify_cp_signature(
            &publickey_glv, &message, &good_sig,
        ));
    }

    #[test]
    fn test_chaum_pedersen_verification_weierstrass_sister_curve() {
        #[cfg(feature = "benchmark")]
        use std::time::Instant;

        use crate::triple_nugget::{NuggetTriplePublicKey, TripleNuggetBLS};
        use ark_sw_by_bls12_381::SWProjective;

        type EB = TinyBLS381;
        type S = SWProjective;

        let message = Message::new(b"ctx", b"test message");

        let mut keypair = Keypair::<EB>::generate(thread_rng());
        let good_sig = <Keypair<EB> as NuggetBLS<EB, S>>::sign(&mut keypair, &message);

        let publickey: NuggetTriplePublicKey<EB, S> =
            TripleNuggetBLS::<EB, S>::into_nugget_triple_public_key(&keypair);

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        assert!(ChaumPedersenVerifier::<EB, S, Sha256>::verify_cp_signature_naive(
            &publickey,
            &message,
            &good_sig,
        ));
        #[cfg(feature = "benchmark")]
        println!("[SW Test] verify_cp_signature_naive: {:?}", start.elapsed());

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        assert!(ChaumPedersenVerifier::<EB, S, Sha256>::verify_cp_signature(
            &publickey, &message, &good_sig,
        ));
        #[cfg(feature = "benchmark")]
        println!(
            "[SW Test] verify_cp_signature (Strauss-Shamir): {:?}",
            start.elapsed()
        );

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        assert!(ChaumPedersenVerifier::<EB, S, Sha256>::verify_cp_signature_with_msm_optimization(
            &publickey,
            &message,
            &good_sig,
        ));
        #[cfg(feature = "benchmark")]
        println!("[SW Test] verify_cp_signature_with_msm_optimization: {:?}", start.elapsed());

        // Also test with G1 as the sister group (GLV path)
        let good_sig_g1_as_sister = <Keypair<EB> as NuggetBLS<
            EB,
            <EB as EngineBLS>::SignatureGroup,
        >>::sign(&mut keypair, &message);

        let publickey_glv: NuggetDoublePublicKeyGLV<EB, ark_bls12_381::g1::Config> =
            DoubleNuggetBLSGLV::<EB, ark_bls12_381::g1::Config>::into_nugget_double_public_key(
                &keypair,
            );

        #[cfg(feature = "benchmark")]
        let start = Instant::now();
        assert!(ChaumPedersenVerifier::<
            EB,
            <EB as EngineBLS>::SignatureGroup,
            Sha256,
        >::verify_cp_signature(
            &publickey_glv,
            &message,
            &good_sig_g1_as_sister,
        ));
        #[cfg(feature = "benchmark")]
        println!(
            "[G1 Test] verify_cp_signature (Straus+GLV G1 as Sister): {:?}",
            start.elapsed()
        );
    }
}
