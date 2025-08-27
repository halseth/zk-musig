use risc0_zkvm::guest::env;
use secp256k1::{PublicKey};
use musig2::{
    AggNonce, KeyAggContext, PartialSignature, PubNonce, SecNonce, compute_challenge_hash_tweak,
    verify_partial_challenge,
};
use musig2::secp::{G, MaybePoint, MaybeScalar, Point, Scalar};
use std::str::FromStr;
use hex::ToHex;

struct BlindingFactors {
    alpha: Scalar,
    beta: Scalar,
    gamma: Scalar,
}


fn main() {
    // TODO: Implement your guest code here

    // read the input
    let i: usize = env::read();
    let coeff_salt: [u8; 32] = env::read();
    let bf: Vec<(String,String,String)> = env::read();
    let pk: Vec<String>= env::read();
    let pn: Vec<String>= env::read();
    let message: String = env::read();


    let blinding_factors: Vec<BlindingFactors> = bf.iter().map(|(a,b,g)| {
        BlindingFactors {
            alpha: Scalar::from_str(a).unwrap(),
            beta: Scalar::from_str(b).unwrap(),
            gamma: Scalar::from_str(g).unwrap(),
        }
    }).collect();

    let pubkeys: Vec<PublicKey> = pk.iter().map(|p| {
        PublicKey::from_str(p).unwrap()
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
    let bbs: MaybePoint = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, fac)| {
            let pubkey: Point = pubkeys[i].into();
            fac.beta * pubkey
        })
        .sum();

    let ggs: MaybePoint = blinding_factors
        .iter()
        .enumerate()
        .map(|(i, fac)| {
            let nonce = public_nonces[i].clone();
            fac.gamma * nonce.R2
        })
        .sum();


    let tweaked_aggregated_pubkey: Point = key_agg_ctx.aggregated_pubkey();

    let b: MaybeScalar = aggregated_nonce.nonce_coefficient(tweaked_aggregated_pubkey, &message);
    let agg_nonce: MaybePoint = aggregated_nonce.final_nonce(b);
    let sign_nonce = agg_nonce + ggs + aas * G + bbs;

    let adaptor_point = MaybePoint::Infinity;
    let adapted_nonce = sign_nonce + adaptor_point;
    let nonce_x_bytes = adapted_nonce.serialize_xonly();

    let challenge_parity = tweaked_aggregated_pubkey.parity() ^ key_agg_ctx.parity_acc();
    let nonce_parity = sign_nonce.parity();

    let e: MaybeScalar =
        compute_challenge_hash_tweak(&nonce_x_bytes, &tweaked_aggregated_pubkey.into(), &message);


//    for (i, pubkey) in pubkeys.iter().enumerate() {
    let their_pubkey: PublicKey = key_agg_ctx.get_pubkey(i).unwrap();
    let pub_nonce: PubNonce = public_nonces[i].clone();
    let key_coeff = key_agg_ctx.key_coefficient(their_pubkey).unwrap();

    let even_parity = bool::from(!challenge_parity);
    let ep = if sign_nonce.has_even_y() ^ even_parity {
        key_coeff * e - blinding_factors[i].beta
    } else {
        key_coeff * e + blinding_factors[i].beta
    };

    let bp = b + blinding_factors[i].gamma;

    env::commit(&their_pubkey.to_string());
    env::commit(&pub_nonce.to_string());
    env::commit(&challenge_parity.unwrap_u8());
    env::commit(&nonce_parity.unwrap_u8());
    env::commit(&hex::encode(bp));
    env::commit(&hex::encode(ep));
}

fn aggregate_pubs(
    pubkeys:  Vec<PublicKey>,
    public_nonces: Vec<PubNonce>,
    key_coeff_salt: Option<&[u8]>,
) -> (Vec<PublicKey>, Vec<PubNonce>, KeyAggContext, AggNonce) {

    let mut key_agg_ctx = KeyAggContext::new(pubkeys.clone(), key_coeff_salt).unwrap();
    key_agg_ctx = key_agg_ctx.with_unspendable_taproot_tweak().unwrap();

    // We manually aggregate the nonces together and then construct our partial signature.
    let aggregated_nonce: AggNonce = public_nonces.iter().sum();
    (pubkeys, public_nonces, key_agg_ctx, aggregated_nonce)
}
