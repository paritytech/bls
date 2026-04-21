//! ## Algorithms for optimized verification of aggregate and batched BLS signatures.
//!
//!
//!

use core::borrow::Borrow;

// We use BTreeMap instead of HashMap for no_std compatibility.
use alloc::collections::BTreeMap;
use ark_ec::AffineRepr;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use digest::FixedOutputReset;

use ark_ec::CurveGroup;

use alloc::vec;
use alloc::vec::Vec;

use super::*;

// We define these convenience type alias here instead of engine.rs
// because seemingly only verifier implementations really employ them.
// And we `pub use engine::*` in lib.rs.

/// Convenience type alias for projective form of `PublicKeyGroup`
pub type PublicKeyProjective<E> = <E as EngineBLS>::PublicKeyGroup;

/// Convenience type alias for affine form of `PublicKeyGroup`
pub type PublicKeyAffine<E> = <<E as EngineBLS>::PublicKeyGroup as CurveGroup>::Affine;

/// Convenience type alias for projective form of `SignatureGroup`
pub type SignatureProjective<E> = <E as EngineBLS>::SignatureGroup;

/// Convenience type alias for affine form of `SignatureGroup`
pub type SignatureAffine<E> = <<E as EngineBLS>::SignatureGroup as CurveGroup>::Affine;

// ── Shared helpers ──────────────────────────────────────────────────

/// Verify from fully normalized (affine) inputs.
/// All public keys, messages, and the signature must already be in affine form.
/// This prepares the pairing inputs and calls `verify_prepared`.
fn verify_normalized<E: EngineBLS>(
    affine_publickeys: &[PublicKeyAffine<E>],
    affine_messages: &[SignatureAffine<E>],
    affine_signature: SignatureAffine<E>,
) -> bool {
    let prepared_sig = E::prepare_signature(affine_signature);
    let prepared = affine_publickeys
        .iter()
        .zip(affine_messages)
        .map(|(pk, m)| (E::prepare_public_key(*pk), E::prepare_signature(*m)))
        .collect::<Vec<_>>();
    E::verify_prepared(prepared_sig, prepared.iter())
}

/// Collect messages and public keys from a `Signed` value, hashing
/// messages to the signature curve.
///
/// We call `messages_and_publickeys()` only once to support unstable iterators.
fn collect_messages_and_publickeys<S: Signed>(
    s: S,
) -> (
    SignatureProjective<S::E>,
    Vec<PublicKeyProjective<S::E>>,
    Vec<SignatureProjective<S::E>>,
) {
    let signature = s.signature().0;
    // We could write this more idiomatically using iterator adaptors,
    // and avoiding an unecessary allocation for publickeys, but only
    // by calling self.messages_and_publickeys() repeatedly.
    let itr = s.messages_and_publickeys();
    let l = {
        let (lower, upper) = itr.size_hint();
        upper.unwrap_or(lower)
    };
    let mut publickeys = Vec::with_capacity(l);
    let mut messages = Vec::with_capacity(l);
    for (message, publickey) in itr {
        publickeys.push(publickey.public_key().0);
        messages.push(message.borrow().hash_to_signature_curve::<S::E>());
    }
    (signature, publickeys, messages)
}

/// Accumulate message points that share the same signer, reducing the
/// number of pairings needed for verification.
///
/// We could avoid the allocation here if we sorted both arrays in
/// parallel.  This might mean (a) some sort function using
/// `ops::IndexMut` instead of slices, and (b) wrapper types to make
/// tuples of slices satisfy `ops::IndexMut`.
// TODO:  Impl PartialEq, Eq, Hash for pairing::EncodedPoint
// to avoid  struct H(E::PublicKeyGroup::Affine::Uncompressed);
fn merge_by_signer<E: EngineBLS>(
    affine_publickeys: Vec<PublicKeyAffine<E>>,
    messages: Vec<SignatureProjective<E>>,
) -> (Vec<PublicKeyAffine<E>>, Vec<SignatureProjective<E>>) {
    type PkMsg<E> = (PublicKeyAffine<E>, SignatureProjective<E>);
    let mut pks_n_ms: BTreeMap<Vec<u8>, PkMsg<E>> = BTreeMap::new();
    for (pk, m) in affine_publickeys.into_iter().zip(messages) {
        let mut pk_bytes = vec![0; pk.uncompressed_size()];
        pk.serialize_uncompressed(&mut pk_bytes[..]).unwrap();
        pks_n_ms
            .entry(pk_bytes)
            .and_modify(|(_, m0)| *m0 += m)
            .or_insert((pk, m));
    }
    pks_n_ms.into_values().unzip()
}

/// Like `merge_by_signer` but keyed on `(public_key, aux_public_key)`.
/// Only message points are merged for entries sharing the same signer pair.
/// Like `merge_by_signer` but also carries auxiliary public keys.
/// Keyed on the public key; returns `None` if the same public key
/// appears with conflicting auxiliary keys.
fn merge_by_signer_with_aux<E: EngineBLS>(
    affine_publickeys: Vec<PublicKeyAffine<E>>,
    aux_keys: Vec<SignatureProjective<E>>,
    messages: Vec<SignatureProjective<E>>,
) -> Option<(
    Vec<PublicKeyAffine<E>>,
    Vec<SignatureAffine<E>>,
    Vec<SignatureProjective<E>>,
)> {
    type PkAuxMsg<E> = (
        PublicKeyAffine<E>,
        SignatureAffine<E>,
        SignatureProjective<E>,
    );
    let mut map: BTreeMap<Vec<u8>, PkAuxMsg<E>> = BTreeMap::new();
    for ((pk, aux), m) in affine_publickeys
        .into_iter()
        .zip(aux_keys)
        .zip(messages)
    {
        let aux_affine = aux.into_affine();
        let mut pk_bytes = vec![0; pk.uncompressed_size()];
        pk.serialize_uncompressed(&mut pk_bytes[..]).unwrap();
        match map.entry(pk_bytes) {
            alloc::collections::btree_map::Entry::Occupied(mut e) => {
                let (_, existing_aux, existing_msg) = e.get_mut();
                if *existing_aux != aux_affine {
                    return None;
                }
                *existing_msg += m;
            }
            alloc::collections::btree_map::Entry::Vacant(e) => {
                e.insert((pk, aux_affine, m));
            }
        }
    }
    let mut pks = Vec::with_capacity(map.len());
    let mut auxs = Vec::with_capacity(map.len());
    let mut msgs = Vec::with_capacity(map.len());
    for (pk, aux, m) in map.into_values() {
        pks.push(pk);
        auxs.push(aux);
        msgs.push(m);
    }
    Some((pks, auxs, msgs))
}

/// Batch-normalize projective public keys, or convert to affine individually
/// when they are already expected to be normalized.
fn normalize_publickeys<E: EngineBLS>(
    publickeys: &[PublicKeyProjective<E>],
    batch_normalize: bool,
) -> Vec<PublicKeyAffine<E>> {
    if batch_normalize {
        E::PublicKeyGroup::normalize_batch(publickeys)
    } else {
        publickeys.iter().map(|pk| pk.into_affine()).collect()
    }
}


/// Batch-normalize message points together with the aggregate signature,
/// returning the affine messages and the affine signature separately.
// TODO: Assess if we could cache normalized message hashes anyplace
// using interior mutability, but probably this does not work well
// with our optimization of collecting messages with the same signer.
fn normalize_messages_and_signature<E: EngineBLS>(
    mut messages: Vec<SignatureProjective<E>>,
    signature: SignatureProjective<E>,
) -> (Vec<SignatureAffine<E>>, SignatureAffine<E>) {
    messages.push(signature);
    let mut affine = E::SignatureGroup::normalize_batch(&messages);
    let signature = affine.pop().unwrap();
    (affine, signature)
}

// ── Public verification functions ───────────────────────────────────

/// Simple unoptimized BLS signature verification.  Useful for testing.
pub fn verify_unoptimized<S: Signed>(s: S) -> bool {
    let signature = S::E::prepare_signature(s.signature().0);
    let prepared = s
        .messages_and_publickeys()
        .map(|(message, public_key)| {
            (
                S::E::prepare_public_key(public_key.public_key().0),
                S::E::prepare_signature(message.borrow().hash_to_signature_curve::<S::E>()),
            )
        })
        .collect::<Vec<(_, _)>>();
    S::E::verify_prepared(signature, prepared.iter())
}

/// Simple universal BLS signature verification
///
/// We support an unstable `Signed::messages_and_publickeys()`
/// securely by calling it only once and batch normalizing all
/// points, as do most other verification routines here.
/// We do no optimizations that reduce the number of pairings
/// by combining repeated messages or signers.
pub fn verify_simple<S: Signed>(s: S) -> bool {
    let (signature, publickeys, messages) = collect_messages_and_publickeys(s);
    let affine_pks = PublicKeyProjective::<S::E>::normalize_batch(&publickeys);
    let (affine_msgs, affine_sig) =
        normalize_messages_and_signature::<S::E>(messages, signature);
    verify_normalized::<S::E>(&affine_pks, &affine_msgs, affine_sig)
}

/// BLS signature verification optimized for all unique messages
///
/// Assuming all messages are distinct, the minimum number of pairings
/// is the number of unique signers, which we achieve here.
/// We do not verify message uniqueness here, but leave this to the
/// aggregate signature type, like `DistinctMessages`.
///
/// We merge any messages with identical signers and batch normalize
/// message points and the signature itself.
/// We optionally batch normalize the public keys in the event that
/// they are provided by algerbaic operaations, but this sounds
/// unlikely given our requirement that messages be distinct.
pub fn verify_with_distinct_messages<S: Signed>(signed: S, normalize_public_keys: bool) -> bool {
    // We first hash the messages to the signature curve and
    // normalize the public keys to operate on them as bytes.
    let (signature, publickeys, messages) = collect_messages_and_publickeys(signed);
    let affine_publickeys = normalize_publickeys::<S::E>(&publickeys, normalize_public_keys);

    // We next accumulate message points with the same signer.
    let (merged_pks, merged_msgs) = merge_by_signer::<S::E>(affine_publickeys, messages);

    // And verify the aggregate signature.
    let (affine_msgs, affine_sig) =
        normalize_messages_and_signature::<S::E>(merged_msgs, signature);
    verify_normalized::<S::E>(&merged_pks, &affine_msgs, affine_sig)
}

/// BLS signature verification optimized for all unique messages
/// with auxiliary public keys.
///
/// Similar to `verify_with_distinct_messages` but for each merged
/// (signer, message) entry, derives a per-entry pseudo-random scalar
/// and folds the auxiliary key contribution into the message point
/// and signature.
// e(asig + \sum_i t_i apk_i,1 , g_2) = \sum_i e (H(m_i) + t_i g_1,apk_i,2)

pub fn verify_using_aggregated_auxiliary_public_keys<
    E: EngineBLS,
    H: FixedOutputReset + Default + Clone,
>(
    signed: &pop_aggregator::SignatureAggregatorAssumingPoP<E>,
    normalize_public_keys: bool,
) -> bool {
    let mut signature = Signed::signature(&signed).0;

    let mut signature_as_bytes = vec![0; signature.compressed_size()];
    signature
        .serialize_compressed(&mut signature_as_bytes[..])
        .expect("compressed size has been alocated");

    let itr = signed.messages_and_publickeys();
    let l = {
        let (lower, upper) = itr.size_hint();
        upper.unwrap_or(lower)
    };

    // Collect public keys, auxiliary keys, and message points.
    let mut publickeys = Vec::with_capacity(l);
    let mut aux_keys = Vec::with_capacity(l);
    let mut messages = Vec::with_capacity(l);
    for (m, pk) in itr {
        publickeys.push(pk.0.0);
        aux_keys.push(pk.1.0);
        messages.push(m.hash_to_signature_curve::<E>());
    }

    let affine_publickeys = normalize_publickeys::<E>(&publickeys, normalize_public_keys);

    // Merge message points that share the same signer.
    // Returns None if same public key appears with conflicting aux keys.
    let (merged_pks, merged_aux, mut merged_msgs) = match
        merge_by_signer_with_aux::<E>(affine_publickeys, aux_keys, messages)
    {
        Some(v) => v,
        None => return false,
    };

    // For each merged entry, compute a per-entry pseudo-random scalar
    // and fold the auxiliary key contribution into message and signature.
    let hasher = <DefaultFieldHasher<H> as HashToField<E::Scalar>>::new(&[]);

    for i in 0..merged_pks.len() {
        let mut pk_bytes = vec![0; merged_pks[i].compressed_size()];
        merged_pks[i]
            .serialize_compressed(&mut pk_bytes[..])
            .expect("compressed size has been alocated");

        let mut aux_pk_bytes = vec![0; merged_aux[i].compressed_size()];
        merged_aux[i]
            .serialize_compressed(&mut aux_pk_bytes[..])
            .expect("compressed size has been alocated");

        let msg_bytes = E::signature_point_to_byte(&merged_msgs[i]);

        let pseudo_random_scalar_seed =
            [msg_bytes, pk_bytes, aux_pk_bytes, signature_as_bytes.clone()].concat();

        let pseudo_random_scalar: E::Scalar =
            hasher.hash_to_field::<1>(&pseudo_random_scalar_seed[..])[0];

        signature += merged_aux[i] * pseudo_random_scalar;
        merged_msgs[i] += E::SignatureGroupAffine::generator() * pseudo_random_scalar;
    }

    // And verify the aggregate signature.
    let (affine_msgs, affine_sig) =
        normalize_messages_and_signature::<E>(merged_msgs, signature);
    verify_normalized::<E>(&merged_pks, &affine_msgs, affine_sig)
}

/*
/// Excessively optimized BLS signature verification
///
/// We minimize the number of pairing operations by doing two
/// basis change operation using Gaussian elimination, first in the
/// message space and then in the signer space.  As a result, we
/// do only `1 + min(msg_d,pk_d)` pairings where `msg_d` and `pk_d`
/// are the numbers of distinct messages and signers, respectively.
///
/// We expect this to improve performance dramatically when both
/// signers and messages are repeated enough, simpler strategies
/// work as well or better when say messages are distinct.
///
/// Explination:
///
/// We consider the bipartite graph with vertex sets given by points
/// on the two curves and edges given by desired pairings between them.
/// We let $M$ denote the bipartite adjacency matrix for this graph,
/// so that multiplying $M$ on the the right and left by the vectors
/// of messages and signers respectively reproduces our original sum
/// of pairings.
///
/// We first use elementary "row" operations to make $M$ upper
/// triangular, as in Gaussian elimination, but at the cost of also
/// performing one-sided "change of basis" operations that collect
/// our original "basis vectors" into sums of curve points.
/// We next use elementary "column" operations to make $M$ diagonal,
/// again adjusting the basis with curve point operations.
///
/// In this, we regard $M$ as a matrix over the scalar field $F_p$
/// so we may do row or column swaps and row or column addition
/// operations with small scalars, but not lone row or column scalar
/// multiplication because these always involve divisions, which
/// produces large curve points that slow us down thereafter.
/// We do not require such divisions because we do not solve any
/// system of equations and do not need ones on the diagonal.
///
/// TODO:
/// We leave implementing this optimization to near future work
/// because it benifits from public keys being affine or having
/// another hashable representation.
///
///
/// As a curiosity, we note one interesting but suboptimal algorithm
/// that avoids small scalar multiplications when doing this:
///
/// If we ignore subtraction, then the minimal number of pairing
/// operations required to verify aggregated BLS signatures is the
/// minimal bipartite edge cover, aka bipartite dimension, of the
/// bipartite graph with vertices given by points on the two curves
/// and edges given by desired pairings.
/// In general, this problem is NP-hard even to approximate.
/// See:  https://en.wikipedia.org/wiki/Bipartite_dimension
///
/// There are polynomial time algorithms for bipartite edge cover in
/// special cases, with domino-free graphs being among the widest
/// known classes.  See:
/// Amilhastre, Jérôme; Janssen, Philippe; Vilarem, Marie-Catherine,
/// "Computing a minimum biclique cover is polynomial for bipartite domino-free graphs" (1997)
/// https://core.ac.uk/download/pdf/82546650.pdf
///
/// If we now exploit subtraction, then these dominos can be
/// completed into $K_{3,3}$s, like
///  $(a,x)+(a,y)+(b,x)+(b,y)+(b,z)+(c,y)+(c,z) = (a+b+c,x+y+z) - (a,z) - (c,z)$
/// which looks optimal for itself, and likely permits the further
/// aggregation, and maybe the subtracted terms can be aggregated later.
///
/// We could not however find the optimal numbers of pairings by
/// completing dominos like this because (a+b+c,x+y+z) - (b,y),
/// which looks optimal for itself, but only has one subtraction.
fn verify_with_gaussian_elimination<S: Signed>(s: S) -> bool {
    unimplemented!()
}

*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, Message, UsualBLS};
    use ark_bls12_381::Bls12_381;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    type EB = UsualBLS<Bls12_381, ark_bls12_381::Config>;

    #[test]
    fn verify_simple_single_signature() {
        let good = Message::new(b"ctx", b"test message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let signed = keypair.signed_message(&good);
        assert!(verify_simple(&signed));
    }

    #[test]
    fn verify_simple_rejects_wrong_message() {
        let good = Message::new(b"ctx", b"test message");
        let bad = Message::new(b"ctx", b"wrong message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let sig = keypair.sign(&good);
        let wrong_signed = single::SignedMessage {
            message: bad,
            publickey: keypair.public,
            signature: sig,
        };
        assert!(!verify_simple(&wrong_signed));
    }

    #[test]
    fn verify_unoptimized_single_signature() {
        let good = Message::new(b"ctx", b"test message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let signed = keypair.signed_message(&good);
        assert!(verify_unoptimized(&signed));
    }
}
