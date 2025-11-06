use risc0_zkvm::guest::env;
use k256::PublicKey;
use musig2::{
    AggNonce, KeyAggContext, PubNonce, compute_challenge_hash_tweak,
};
use musig2::secp::{G, MaybePoint, MaybeScalar, Point, Scalar};
use std::str::FromStr;
use hex::ToHex;
use serde::{Deserialize, Serialize};
use k256::ProjectivePoint;
use k256::elliptic_curve::ops::LinearCombinationExt;

/// Journal output from the guest program
///
/// All data is wrapped in this single structure for atomic commitment.
/// This ensures that all values are committed to together in the zero-knowledge proof,
/// preventing selective disclosure or manipulation of individual fields.
///
/// All cryptographic values are hex-encoded strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalOutput {
    /// Public key of the signer (hex-encoded, 33 bytes compressed format)
    pubkey: String,

    /// Public nonce used by the signer (hex-encoded, 66 bytes)
    pubnonce: String,

    /// Parity bit for the challenge (0 or 1)
    /// Used to determine sign adjustments in the signature
    challenge_parity: u8,

    /// Parity bit for the signing nonce (0 or 1)
    /// Indicates whether the signing nonce has even Y coordinate
    nonce_parity: u8,

    /// Blinded nonce coefficient b' = b + gamma (hex-encoded scalar, 32 bytes)
    /// This is the nonce coefficient with the blinding factor applied
    b: String,

    /// Blinded challenge e' (hex-encoded scalar, 32 bytes)
    /// This is the challenge with key coefficient and blinding applied
    e: String,
}

struct BlindingFactors {
    alpha: Scalar,
    beta: Scalar,
    gamma: Scalar,
}

fn main() {
    // TODO: Implement your guest code here

    // read the input
    let i: u32 = env::read();
    let i = i as usize;
    let coeff_salt: [u8; 32] = env::read();
    let pubkeys: Vec<PublicKey>= env::read();
    let bf: Vec<([u8;32], [u8;32], [u8;32])> = env::read();
    let pn: Vec<String>= env::read();
    let message_hex: String = env::read();

    // Decode the hex message to bytes
    let message = hex::decode(&message_hex).expect("Failed to decode message hex");

    // TODO: where is the expensive bigint?
    let blinding_factors: Vec<BlindingFactors> = bf.iter().map(|(a,b,g)| {
        BlindingFactors {
            alpha: Scalar::from_slice(a.as_slice()).unwrap(),
            beta: Scalar::from_slice(b.as_slice()).unwrap(),
            gamma: Scalar::from_slice(g.as_slice()).unwrap(),
        }
    }).collect();

    let public_nonces: Vec<PubNonce> = pn.iter().map(|p| {
        PubNonce::from_hex(p).unwrap()
    }).collect();

    let (
        pubkeys,
        public_nonces,
        key_agg_ctx,
        aggregated_nonce,
    ) = aggregate_pubs(pubkeys, public_nonces, Some(&coeff_salt));

    let aas: MaybeScalar = blinding_factors.iter().map(|fac| fac.alpha).sum();

    // Use lincomb (multi-scalar multiplication) for bbs: Σ(beta_i * pubkey_i)
    // This is more efficient than individual multiplications + sum
    let bbs_pairs: Vec<(ProjectivePoint, k256::Scalar)> = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, fac)| {
            // pubkeys[i] is already k256::PublicKey, convert directly to ProjectivePoint
            let k256_point: ProjectivePoint = pubkeys[i].into();
            let k256_scalar: k256::Scalar = fac.beta.into();
            (k256_point, k256_scalar)
        })
        .collect();

    let bbs_result = ProjectivePoint::lincomb_ext(&bbs_pairs[..]);
    // Convert back: ProjectivePoint -> AffinePoint -> PublicKey -> Point
    let bbs: Point = k256::PublicKey::from_affine(bbs_result.into()).unwrap().into();

    // Use lincomb for ggs: Σ(gamma_i * R2_i)
    let ggs_pairs: Vec<(ProjectivePoint, k256::Scalar)> = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, fac)| {
            let r2_point: Point = public_nonces[i].R2;
            // Convert secp::Point to k256::ProjectivePoint via Into trait
            let k256_affine: k256::AffinePoint = r2_point.into();
            let k256_point: ProjectivePoint = k256_affine.into();
            let k256_scalar: k256::Scalar = fac.gamma.into();
            (k256_point, k256_scalar)
        })
        .collect();

    let ggs_result = ProjectivePoint::lincomb_ext(&ggs_pairs[..]);
    // Convert back: ProjectivePoint -> AffinePoint -> PublicKey -> Point
    let ggs: Point = k256::PublicKey::from_affine(ggs_result.into()).unwrap().into();

    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(tweaked_aggregated_pubkey, &message);
    let agg_nonce: Point = aggregated_nonce.final_nonce(b);
    let sign_nonce = agg_nonce + ggs + aas * G + bbs;

    let adaptor_point = MaybePoint::Infinity;
    let adapted_nonce = sign_nonce + adaptor_point;
    let nonce_x_bytes = adapted_nonce.serialize_xonly();

    let challenge_parity = tweaked_aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc();
    let nonce_parity = sign_nonce.parity();

    let e: MaybeScalar =
        compute_challenge_hash_tweak(&nonce_x_bytes, &tweaked_aggregated_pubkey.into(), &message);


    let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
    let pub_nonce: &PubNonce = &public_nonces[i];
    let key_coeff = key_agg_ctx.key_coefficient(their_pubkey).unwrap();

    let even_parity = bool::from(!challenge_parity);
    let ep = if sign_nonce.has_even_y() ^ even_parity {
        key_coeff * e - blinding_factors[i].beta
    } else {
        key_coeff * e + blinding_factors[i].beta
    };

    let bp = b + blinding_factors[i].gamma;

    let pks = hex::encode(their_pubkey.to_sec1_bytes());
    let bp_hex = hex::encode(bp.serialize());
    let ep_hex = hex::encode(ep.serialize());

    // Create a single JournalOutput structure with all data as hex strings
    let journal_output = JournalOutput {
        pubkey: pks,
        pubnonce: pub_nonce.to_string(),
        challenge_parity: challenge_parity.unwrap_u8(),
        nonce_parity: nonce_parity.unwrap_u8(),
        b: bp_hex,
        e: ep_hex,
    };

    // Commit the entire structure at once
    env::commit(&journal_output);
}

fn aggregate_pubs(
    pubkeys: Vec<PublicKey>,
    public_nonces: Vec<PubNonce>,
    key_coeff_salt: Option<&[u8]>,
) -> (Vec<PublicKey>, Vec<PubNonce>, KeyAggContext, AggNonce) {
    let mut key_agg_ctx = KeyAggContext::new(pubkeys.clone(), key_coeff_salt).unwrap();
    key_agg_ctx = key_agg_ctx.with_unspendable_taproot_tweak().unwrap();

    // We manually aggregate the nonces together and then construct our partial signature.
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();
    (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce)
}