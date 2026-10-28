#[cfg(feature = "std")]
use rand::thread_rng;

#[cfg(feature = "std")]
use w3f_bls::{
    DoubleNuggetBLS, DoubleNuggetBLSGLV, DoubleNuggetSignature, EngineBLS, Keypair, Message,
    NuggetBLS, NuggetDoublePublicKey, NuggetDoublePublicKeyGLV, SerializableToBytes, TinyBLS381,
};

/// Sign a single message with Nugget BLS and verify it two ways:
///
/// 1. Against the plain [`NuggetDoublePublicKey`]. On `TinyBLS381` the
///    signature group is `Projective<g1::Config>` with `BLSGLVConfig`, so
///    trait resolution picks the GLV impl of `DualScalarMultiplication` —
///    the fast path fires, with a 16-element GLV decomposition computed at
///    verify time (no precomputed table on the plain pubkey).
///
/// 2. Against the GLV-optimized [`NuggetDoublePublicKeyGLV`], which caches a
///    256-entry Straus-Shamir GLV table so the verifier skips the per-call
///    decomposition entirely.
///
/// Both calls go through [`DoubleNuggetSignature::verify`], which is generic
/// over the pubkey type — Rust picks the right [`NuggetPublicKey::verify`]
/// impl from the pubkey's type, so the call site is identical in form.
///
/// Note: this example has **zero `ark_ec` imports**. All GLV machinery is
/// behind `TinyBLS381`, `EngineBLSGLV`, and the Nugget types.
///
/// Run with:
/// ```sh
/// cargo run --example nugget_glv
/// ```
fn main() {
    #[cfg(feature = "std")]
    {
        let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
        let message = Message::new(b"ctx", b"GLV verification demo");

        // Produce a Nugget signature (sig group element + DLEQ proof) via the
        // UFCS form so Rust picks the trait method over `Keypair::sign`, which
        // would return a plain `Signature`.
        let raw_sig = <Keypair<TinyBLS381> as NuggetBLS<
            TinyBLS381,
            <TinyBLS381 as EngineBLS>::SignatureGroup,
        >>::sign(&mut keypair, &message);
        let sig: DoubleNuggetSignature<TinyBLS381> = raw_sig.into();

        let pk: NuggetDoublePublicKey<TinyBLS381> =
            DoubleNuggetBLS::to_nugget_double_public_key(&keypair);
        let pk_glv: NuggetDoublePublicKeyGLV<TinyBLS381> =
            DoubleNuggetBLSGLV::to_nugget_double_public_key(&keypair);

        // Same signature, two pubkeys, same call shape — Rust picks the
        // appropriate `NuggetPublicKey::verify` impl from each pubkey type.
        assert!(
            sig.verify(&message, &pk),
            "plain pubkey verify should succeed (GLV scalar-mul, runtime 16-elt table)"
        );
        assert!(
            sig.verify(&message, &pk_glv),
            "GLV pubkey verify should succeed (GLV scalar-mul + 256-elt precomputed table)"
        );

        println!(
            "both verifies succeeded; serialized plain pk = {} bytes, GLV pk = {} bytes",
            pk.to_bytes().len(),
            pk_glv.to_bytes().len()
        );
    }
}
