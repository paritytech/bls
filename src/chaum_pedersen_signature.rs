use alloc::vec::Vec;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{
    field_hashers::{DefaultFieldHasher, HashToField},
    AdditiveGroup,
};
use ark_ff::{BigInteger, PrimeField};

use ark_ff::Zero;
use digest::FixedOutputReset;

use crate::engine::EngineBLS;
use crate::nugget::{NuggetBLS, NuggetPublicKey, NuggetSignature};
use crate::schnorr_pop::SchnorrProof;
use crate::serialize::SerializableToBytes;
use crate::single::Signature;
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
    S: CurveGroup + SerializableToBytes,
    H: FixedOutputReset + Default + Clone,
>: NuggetPublicKey<E, S> where
    S: PrimeGroup<ScalarField = E::Scalar>,
{
    #[allow(non_snake_case)]
    fn verify_cp_signature(
        &self,
        message: &Message,
        signature_proof: &ChaumPedersenSignature<E>,
    ) -> bool {
        let signature_as_scalars_of_sister_group: (S::ScalarField, S::ScalarField) =
            (signature_proof.1 .0, signature_proof.1 .1);
        let A_check_point = <S as PrimeGroup>::generator() * signature_as_scalars_of_sister_group.1
            + self.into_public_key_in_sister_group().0 * signature_as_scalars_of_sister_group.0;

        let B_check_point = message.hash_to_signature_curve::<E>() * signature_proof.1 .1
            + signature_proof.0 * signature_proof.1 .0;

        let A_point_as_bytes = A_check_point.to_bytes();
        let B_point_as_bytes = E::signature_point_to_byte(&B_check_point);

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_proof.0);
        let message_point_as_bytes =
            E::signature_point_to_byte(&message.hash_to_signature_curve::<E>());
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

    #[allow(non_snake_case)]
    fn verify_cp_signature_with_strauss_shamir_optimization(
        &self,
        message: &Message,
        signature_proof: &ChaumPedersenSignature<E>,
    ) -> bool {
        let signature_as_scalars_of_sister_group: (S::ScalarField, S::ScalarField) =
            (signature_proof.1 .0, signature_proof.1 .1);
        let A_check_point = <S as PrimeGroup>::generator() * signature_as_scalars_of_sister_group.1
            + self.into_public_key_in_sister_group().0 * signature_as_scalars_of_sister_group.0;

        let B_check_point = message.hash_to_signature_curve::<E>() * signature_proof.1 .1
            + signature_proof.0 * signature_proof.1 .0;

        let A_point_as_bytes = A_check_point.to_bytes();
        let B_point_as_bytes = E::signature_point_to_byte(&B_check_point);

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_proof.0);
        let message_point_as_bytes =
            E::signature_point_to_byte(&message.hash_to_signature_curve::<E>());
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

    fn strauss_shamir_dual_scalar_multiplications(
        &self,
        generator_scalar: S::ScalarField,
        public_key_scalar: S::ScalarField,
    ) -> S {
        // Use Straus–Shamir (interleaved double-and-add) for the two-scalar multiplication:
        // compute G * s + PK_sister * c more efficiently by interleaving doublings and conditional adds.

        // base points
        let gen = <S as PrimeGroup>::generator(); // corresponds to G
        let pubkey = self.into_public_key_in_sister_group().0; // corresponds to PK_sister

        let gen_scalar_bits = ark_ff::BitIteratorBE::new(generator_scalar.into_bigint());
        let pub_scalar_bits = ark_ff::BitIteratorBE::new(public_key_scalar.into_bigint());

        let mut res = <S as Zero>::zero();

        let first_non_zero_bit_reached = false;
        for (gen_scalar_bit, pub_scalar_bit) in gen_scalar_bits.zip(pub_scalar_bits) {
            if (gen_scalar_bit, pub_scalar_bit) == (false, false) {
                if first_non_zero_bit_reached {
                    res.double_in_place();
                } else {
                    continue;
                }
            } else {
                // let (gen_scalar_bit, pub_scalar_bit) =  match (gen_scalar_bit, pub_scalar_bit) {
                //     (Some(gen_scalar_bit), Some(pub_scalar_bit)) => (gen_scalar_bit, pub_scalar_bit),
                //     (Some(gen_scalar_bit), None) => (gen_scalar_bit,false),
                //     (None, Some(pub_scalar_bit)) => (false, pub_scalar_bit),
                //     _ => continue,
                // };
                res.double_in_place();
                res += match (gen_scalar_bit, pub_scalar_bit) {
                    (true, true) => self.sister_gen_plus_public_key(),
                    (true, false) => gen,
                    (false, true) => pubkey,
                    _ => <S as Zero>::zero(), //we already accounted for this and should never reach this anyway
                }
            }
        }

        res
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
