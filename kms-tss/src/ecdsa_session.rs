//! Threshold ECDSA signing session (robust protocol).
//!
//! 4-round online protocol: 3 presigning rounds + 1 signing round.
//! Uses the same DKG output (FROST keygen) as FROST Schnorr — only the
//! signing protocol differs.
//!
//! The coordinator (initiating node) aggregates signature shares in R4.
//! All other participants produce and send their share, then return no result.
//!
//! # References
//!
//! - **DJNPO20**: Damgård, Jakobsen, Nielsen, Pagter, Østergård.
//!   "Fast Threshold ECDSA with Honest Majority." 2020.
//!   <https://eprint.iacr.org/2020/501>
//!   Core protocol: degree-2t polynomial presigning avoids Beaver triple
//!   generation. Requires N ≥ 2t+1 participants.
//!
//! - **GS21**: Groth, Shoup. "Design and Analysis of a Distributed ECDSA
//!   Signing Service." IACR ePrint 2022/506 (originally presented 2021).
//!   <https://eprint.iacr.org/2022/506>
//!   Rerandomization technique for binding presignatures to signing context,
//!   preventing Wagner-style attacks. Not yet implemented here (presignatures
//!   are consumed inline, not stored).
//!
//! - **NEAR MPC**: Reference implementation in the NEAR threshold-signatures
//!   crate (`crates/threshold-signatures/src/ecdsa/robust_ecdsa/`).
//!   <https://github.com/near/mpc>
//!   Our implementation follows the same protocol structure.

use std::collections::BTreeMap;

use frost_core::Ciphersuite;
use frost_secp256k1::Secp256K1Sha256;
use k256::{
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint, Field as FFField},
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::curve::Curve;
use crate::storage::{Storage, StoredKey};
use crate::types::{OutgoingMessage, ProcessError, SessionResult, StepOutput};

// ---------------------------------------------------------------------------
// Wire types for inter-node messages (CBOR-encoded)
// ---------------------------------------------------------------------------

/// Round 1: private polynomial evaluations sent to each peer.
#[derive(Serialize, Deserialize)]
struct R1Private {
    /// 5 scalar evaluations: [k, a, b, d, e] at the recipient's identifier.
    evals: Vec<Vec<u8>>, // 5 × 32-byte scalars
}

/// Round 2: broadcast R_i and w_i.
#[derive(Serialize, Deserialize)]
struct R2Broadcast {
    /// R_i = g^{k_i} — compressed point (33 bytes).
    big_r: Vec<u8>,
    /// w_i = a_i * k_i + b_i — scalar (32 bytes).
    w: Vec<u8>,
}

/// Round 3: broadcast W_i = R^{a_i}.
#[derive(Serialize, Deserialize)]
struct R3Broadcast {
    /// W_i — compressed point (33 bytes).
    big_w: Vec<u8>,
}

/// Round 4: private signature share sent to coordinator.
#[derive(Serialize, Deserialize)]
struct R4Share {
    /// Linearized signature share s_i — scalar (32 bytes).
    s: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.to_bytes().to_vec()
}

fn bytes_to_scalar(b: &[u8]) -> Result<Scalar, String> {
    if b.len() != 32 {
        return Err(format!("scalar must be 32 bytes, got {}", b.len()));
    }
    use k256::elliptic_curve::PrimeField;
    let bytes: &k256::FieldBytes = b.into();
    Option::from(Scalar::from_repr(*bytes)).ok_or_else(|| "invalid scalar".to_string())
}

fn point_to_bytes(p: &ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

fn bytes_to_point(b: &[u8]) -> Result<ProjectivePoint, String> {
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    let encoded = k256::EncodedPoint::from_bytes(b)
        .map_err(|e| format!("invalid point encoding: {e}"))?;
    let opt: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
    opt.map(ProjectivePoint::from)
        .ok_or_else(|| "invalid curve point".to_string())
}

fn x_coordinate(point: &AffinePoint) -> Scalar {
    let encoded = point.to_encoded_point(false);
    let x_bytes = encoded.x().unwrap();
    <Scalar as Reduce<U256>>::reduce_bytes(x_bytes)
}

fn lagrange(i: &Scalar, participants: &[Scalar]) -> Scalar {
    let mut num = Scalar::ONE;
    let mut den = Scalar::ONE;
    for j in participants {
        if j == i { continue; }
        num = num * j;
        den = den * (*j - i);
    }
    num * den.invert().unwrap()
}

fn cbor_encode<T: Serialize>(val: &T) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).map_err(|e| format!("cbor encode: {e}"))?;
    Ok(buf)
}

fn cbor_decode<T: serde::de::DeserializeOwned>(data: &[u8]) -> Result<T, String> {
    ciborium::from_reader(data).map_err(|e| format!("cbor decode: {e}"))
}

/// Exponent interpolation: given (x_i, P_i) compute g^{f(target)} via
/// Lagrange in the exponent. target=None means evaluate at zero.
fn exponent_interpolation(
    xs: &[Scalar],
    points: &[ProjectivePoint],
    target: Option<&Scalar>,
) -> ProjectivePoint {
    let mut result = ProjectivePoint::IDENTITY;
    for (i, (x_i, p_i)) in xs.iter().zip(points.iter()).enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (j, x_j) in xs.iter().enumerate() {
            if i == j { continue; }
            let t = target.copied().unwrap_or(Scalar::ZERO);
            num = num * (t - x_j);
            den = den * (*x_i - x_j);
        }
        result = result + *p_i * (num * den.invert().unwrap());
    }
    result
}

/// Scalar interpolation at target (None = zero).
fn scalar_interpolation(xs: &[Scalar], ys: &[Scalar], target: Option<&Scalar>) -> Scalar {
    let mut result = Scalar::ZERO;
    for (i, (x_i, y_i)) in xs.iter().zip(ys.iter()).enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (j, x_j) in xs.iter().enumerate() {
            if i == j { continue; }
            let t = target.copied().unwrap_or(Scalar::ZERO);
            num = num * (t - x_j);
            den = den * (*x_i - x_j);
        }
        result = result + *y_i * (num * den.invert().unwrap());
    }
    result
}

/// Simple polynomial f(x) = a_0 + a_1*x + ... + a_d*x^d.
struct Polynomial {
    coeffs: Vec<Scalar>,
}

impl Polynomial {
    fn random(constant: Option<Scalar>, degree: usize) -> Self {
        let mut rng = thread_rng();
        let mut coeffs = Vec::with_capacity(degree + 1);
        coeffs.push(constant.unwrap_or_else(|| Scalar::random(&mut rng)));
        for _ in 0..degree {
            coeffs.push(Scalar::random(&mut rng));
        }
        Polynomial { coeffs }
    }

    fn eval(&self, x: &Scalar) -> Scalar {
        let mut result = *self.coeffs.last().unwrap();
        for coeff in self.coeffs[..self.coeffs.len() - 1].iter().rev() {
            result = result * x + coeff;
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Party identifier mapping (string ↔ scalar)
// ---------------------------------------------------------------------------

struct PartyScalars {
    ids: Vec<String>,
    scalars: Vec<Scalar>,
}

impl PartyScalars {
    fn new(party_ids: &[String]) -> Result<Self, String> {
        let mut scalars = Vec::with_capacity(party_ids.len());
        for pid in party_ids {
            let frost_id = frost_core::Identifier::<Secp256K1Sha256>::derive(pid.as_bytes())
                .map_err(|e| format!("derive identifier for {pid}: {e}"))?;
            let bytes = frost_id.serialize();
            let scalar = bytes_to_scalar(bytes.as_ref())?;
            scalars.push(scalar);
        }
        Ok(PartyScalars {
            ids: party_ids.to_vec(),
            scalars,
        })
    }

    fn scalar_of(&self, party_id: &str) -> Result<Scalar, String> {
        self.ids.iter().zip(&self.scalars)
            .find(|(id, _)| id.as_str() == party_id)
            .map(|(_, s)| *s)
            .ok_or_else(|| format!("unknown party: {party_id}"))
    }

    fn index_of(&self, party_id: &str) -> Result<usize, String> {
        self.ids.iter().position(|id| id == party_id)
            .ok_or_else(|| format!("unknown party: {party_id}"))
    }

    fn len(&self) -> usize { self.ids.len() }
}

// ---------------------------------------------------------------------------
// ECDSA session state
// ---------------------------------------------------------------------------

pub(crate) enum EcdsaState {
    /// Round 1: generating polynomials, sending evaluations.
    PresignR1 {
        session_id: String,
        params: crate::params::SignParams,
        parties: PartyScalars,
        self_id: String,
        max_malicious: usize,
        /// This party's 5 polynomials [fk, fa, fb, fd, fe].
        polynomials: [Polynomial; 5],
        /// Accumulated shares from other parties (5 scalars each).
        shares: [Scalar; 5], // k, a, b, d, e — accumulated
        /// Private key share for this party.
        secret_share: Scalar,
        /// Group public key.
        public_key: ProjectivePoint,
        /// Count of R1 messages received.
        r1_received: usize,
    },
    /// Round 2: exchanging R_i and w_i.
    PresignR2 {
        session_id: String,
        params: crate::params::SignParams,
        parties: PartyScalars,
        self_id: String,
        max_malicious: usize,
        shares: [Scalar; 5],
        secret_share: Scalar,
        public_key: ProjectivePoint,
        /// Collected R_i values per party.
        big_r_map: BTreeMap<String, ProjectivePoint>,
        /// Collected w_i values per party.
        w_map: BTreeMap<String, Scalar>,
    },
    /// Round 3: exchanging W_i, computing presignature.
    PresignR3 {
        session_id: String,
        params: crate::params::SignParams,
        parties: PartyScalars,
        self_id: String,
        max_malicious: usize,
        shares: [Scalar; 5],
        secret_share: Scalar,
        public_key: ProjectivePoint,
        big_r: ProjectivePoint,
        w: Scalar,
        /// Collected W_i values per party.
        big_w_map: BTreeMap<String, ProjectivePoint>,
    },
    /// Round 4: signing — each party sends s_i to coordinator.
    SignR4 {
        session_id: String,
        parties: PartyScalars,
        self_id: String,
        public_key: ProjectivePoint,
        big_r: AffinePoint,
        msg_hash: Scalar,
        /// Collected signature shares (coordinator only).
        sig_shares: BTreeMap<String, Scalar>,
        /// Whether this party is the coordinator.
        is_coordinator: bool,
    },
    Completed,
}

// ---------------------------------------------------------------------------
// ECDSA session (wraps state + pending buffer)
// ---------------------------------------------------------------------------

pub(crate) struct EcdsaSession {
    state: EcdsaState,
    pending: Vec<(String, String, Vec<u8>)>,
}

impl EcdsaSession {
    pub fn state_name(&self) -> &'static str {
        match &self.state {
            EcdsaState::PresignR1 { .. } => "EcdsaPresignR1",
            EcdsaState::PresignR2 { .. } => "EcdsaPresignR2",
            EcdsaState::PresignR3 { .. } => "EcdsaPresignR3",
            EcdsaState::SignR4 { .. } => "EcdsaSignR4",
            EcdsaState::Completed => "Completed",
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn start(
        session_id: &str,
        params: crate::params::SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let n = params.signer_ids.len();
        if n < 3 {
            return Err("ECDSA requires at least 3 signers".to_string());
        }
        // t = max malicious. For n signers, t = (n-1)/2 gives the maximum
        // malicious tolerance, so the protocol's own n >= 2t+1 requirement is
        // satisfied by construction — there is nothing to check here. The
        // constraint that *can* be violated involves the key's threshold, and
        // is enforced below once the KeyPackage has been loaded.
        let max_malicious = (n - 1) / 2;

        let parties = PartyScalars::new(&params.signer_ids)?;
        let self_idx = parties.index_of(&params.party_id)?;
        let self_scalar = parties.scalars[self_idx];

        // Load key from storage.
        let curve = Curve::EcdsaSecp256k1;
        let stored = storage
            .get_key(&params.group_id, &params.key_id, &curve)?
            .ok_or_else(|| format!("key not found: {}/{} curve={}", params.group_id, params.key_id, curve))?;

        // Extract private share scalar from FROST KeyPackage.
        let kp = frost_core::keys::KeyPackage::<Secp256K1Sha256>::deserialize(&stored.key_package)
            .map_err(|e| format!("deserialize key package: {e}"))?;
        let share_bytes = kp.signing_share().serialize();
        let secret_share = bytes_to_scalar(share_bytes.as_ref())?;
        // Reject signer sets too small for this key's threshold.
        //
        // `max_malicious` above is derived from the signer set and says nothing
        // about the key. The signature share carries
        // `beta_me = c_me * secret_share` (see the sign round), whose degree in
        // the party index is t + (T-1): t from the nonce polynomial fa, and
        // T-1 from the DKG polynomial the stored share lies on. The coordinator
        // reconstructs by Lagrange interpolation over the n participating
        // points, which is exact only up to degree n-1. Hence
        //
        //     (n-1)/2 + T - 1 <= n - 1   =>   n >= 2T - 1
        //
        // Below that bound the protocol still completes and emits a well-formed
        // signature — it simply is not a signature under the group key, so it
        // fails ecrecover/verify at the far end (a reverted EIP-3009 transfer,
        // say) rather than here. Failing the request is the whole point.
        //
        // Note this is NOT the same as the group's "T-of-N can sign" property:
        // FROST honours that directly, but this ECDSA construction needs a
        // wider signer set than T. A T-of-N group has ECDSA slack only when
        // N > 2T-1.
        let min_signers = *kp.min_signers() as usize;
        let required = 2 * min_signers.max(1) - 1;
        if n < required {
            return Err(format!(
                "ECDSA with a {min_signers}-of-N key requires at least {required} \
                 signers (n >= 2T-1), got {n}"
            ));
        }


        // Group public key.
        let public_key = bytes_to_point(&stored.group_key)?;

        // Generate 5 polynomials.
        let t = max_malicious;
        let polynomials = [
            Polynomial::random(None, t),     // fk — nonce
            Polynomial::random(None, t),     // fa — blinding
            Polynomial::random(Some(Scalar::ZERO), 2 * t), // fb — masking
            Polynomial::random(Some(Scalar::ZERO), 2 * t), // fd — alpha blinding
            Polynomial::random(Some(Scalar::ZERO), 2 * t), // fe — beta blinding
        ];

        // Evaluate own shares.
        let own_shares = [
            polynomials[0].eval(&self_scalar),
            polynomials[1].eval(&self_scalar),
            polynomials[2].eval(&self_scalar),
            polynomials[3].eval(&self_scalar),
            polynomials[4].eval(&self_scalar),
        ];

        // Send private evaluations to each peer.
        let mut messages = Vec::new();
        for (i, pid) in params.signer_ids.iter().enumerate() {
            if *pid == params.party_id { continue; }
            let evals: Vec<Vec<u8>> = (0..5)
                .map(|p| scalar_to_bytes(&polynomials[p].eval(&parties.scalars[i])))
                .collect();
            let data = cbor_encode(&R1Private { evals })?;
            messages.push(OutgoingMessage {
                session_id: session_id.to_string(),
                from: params.party_id.clone(),
                to: pid.clone(),
                payload: data,
            });
        }

        let self_id = params.party_id.clone();
        Ok((
            EcdsaSession {
                state: EcdsaState::PresignR1 {
                    session_id: session_id.to_string(),
                    params,
                    parties,
                    self_id,
                    max_malicious,
                    polynomials,
                    shares: own_shares,
                    secret_share,
                    public_key,
                    r1_received: 0,
                },
                pending: vec![],
            },
            StepOutput { messages, result: None },
        ))
    }

    pub fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        let prev_state = self.state_name();
        let state = std::mem::replace(&mut self.state, EcdsaState::Completed);
        let (new_state, output) = process_ecdsa(state, from, to, payload);
        self.state = new_state;

        match output {
            Ok(step) => {
                debug!(from, prev_state, new_state = self.state_name(), "ecdsa message processed");
                let mut combined = step;
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    for (f, t, p) in pending {
                        let s = std::mem::replace(&mut self.state, EcdsaState::Completed);
                        let (ns, result) = process_ecdsa(s, &f, &t, &p);
                        self.state = ns;
                        match result {
                            Ok(more) => {
                                combined.messages.extend(more.messages);
                                if let Some(r) = more.result { combined.result = Some(r); }
                            }
                            Err(ProcessError::WrongRound(_)) => { self.pending.push((f, t, p)); }
                            Err(ProcessError::Invalid(e)) => {
                                debug!(error = e.as_str(), "pending ecdsa message dropped");
                            }
                        }
                    }
                }
                Ok(combined)
            }
            Err(ProcessError::WrongRound(_)) => {
                self.pending.push((from.to_string(), to.to_string(), payload.to_vec()));
                Ok(StepOutput { messages: vec![], result: None })
            }
            Err(ProcessError::Invalid(e)) => {
                debug!(from, error = e.as_str(), "ecdsa message dropped (invalid)");
                Ok(StepOutput { messages: vec![], result: None })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// State machine transitions
// ---------------------------------------------------------------------------

fn process_ecdsa(
    state: EcdsaState,
    from: &str,
    _to: &str,
    payload: &[u8],
) -> (EcdsaState, Result<StepOutput, ProcessError>) {
    match state {
        // ---- Presign Round 1: collect polynomial evaluations ----
        EcdsaState::PresignR1 {
            session_id, params, parties, self_id, max_malicious,
            polynomials, mut shares, secret_share, public_key, mut r1_received,
        } => {
            let r1: R1Private = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (EcdsaState::PresignR1 {
                        session_id, params, parties, self_id, max_malicious,
                        polynomials, shares, secret_share, public_key, r1_received,
                    }, Err(ProcessError::WrongRound(e)));
                }
            };

            if r1.evals.len() != 5 {
                return (EcdsaState::PresignR1 {
                    session_id, params, parties, self_id, max_malicious,
                    polynomials, shares, secret_share, public_key, r1_received,
                }, Err(ProcessError::Invalid(format!("expected 5 evals, got {}", r1.evals.len()))));
            }

            // Accumulate shares.
            for (i, eval_bytes) in r1.evals.iter().enumerate() {
                let s = match bytes_to_scalar(eval_bytes) {
                    Ok(s) => s,
                    Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
                };
                shares[i] = shares[i] + s;
            }
            r1_received += 1;

            if r1_received < parties.len() - 1 {
                return (EcdsaState::PresignR1 {
                    session_id, params, parties, self_id, max_malicious,
                    polynomials, shares, secret_share, public_key, r1_received,
                }, Ok(StepOutput { messages: vec![], result: None }));
            }

            // All R1 received. Transition to R2.
            let k = shares[0];
            let a = shares[1];
            let _b = shares[2];

            let big_r_me = ProjectivePoint::GENERATOR * k;
            let w_me = a * k + shares[2]; // a * k + b

            let r2 = R2Broadcast {
                big_r: point_to_bytes(&big_r_me),
                w: scalar_to_bytes(&w_me),
            };
            let data = match cbor_encode(&r2) {
                Ok(d) => d,
                Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
            };

            let mut big_r_map = BTreeMap::new();
            let mut w_map = BTreeMap::new();
            big_r_map.insert(self_id.clone(), big_r_me);
            w_map.insert(self_id.clone(), w_me);

            (
                EcdsaState::PresignR2 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    parties, self_id: self_id.clone(), max_malicious,
                    shares, secret_share, public_key,
                    big_r_map, w_map,
                },
                Ok(StepOutput {
                    messages: vec![OutgoingMessage {
                        session_id,
                        from: self_id,
                        to: String::new(), // broadcast
                        payload: data,
                    }],
                    result: None,
                }),
            )
        }

        // ---- Presign Round 2: collect R_i and w_i ----
        EcdsaState::PresignR2 {
            session_id, params, parties, self_id, max_malicious,
            shares, secret_share, public_key,
            mut big_r_map, mut w_map,
        } => {
            let r2: R2Broadcast = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (EcdsaState::PresignR2 {
                        session_id, params, parties, self_id, max_malicious,
                        shares, secret_share, public_key, big_r_map, w_map,
                    }, Err(ProcessError::WrongRound(e)));
                }
            };

            let big_r_p = match bytes_to_point(&r2.big_r) {
                Ok(p) => p,
                Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
            };
            let w_p = match bytes_to_scalar(&r2.w) {
                Ok(s) => s,
                Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
            };

            big_r_map.insert(from.to_string(), big_r_p);
            w_map.insert(from.to_string(), w_p);

            if big_r_map.len() < parties.len() {
                return (EcdsaState::PresignR2 {
                    session_id, params, parties, self_id, max_malicious,
                    shares, secret_share, public_key, big_r_map, w_map,
                }, Ok(StepOutput { messages: vec![], result: None }));
            }

            // All R2 received. Compute R and w via interpolation.
            let t = max_malicious;
            let ordered_ids: Vec<String> = parties.ids.clone();
            let ordered_scalars: Vec<Scalar> = parties.scalars.clone();

            let big_r_ordered: Vec<ProjectivePoint> = ordered_ids.iter()
                .map(|id| big_r_map[id]).collect();
            let w_ordered: Vec<Scalar> = ordered_ids.iter()
                .map(|id| w_map[id]).collect();

            // Exponent interpolation of R using first t+1 points.
            let big_r = exponent_interpolation(
                &ordered_scalars[..t + 1],
                &big_r_ordered[..t + 1],
                None,
            );
            if big_r == ProjectivePoint::IDENTITY {
                return (EcdsaState::Completed, Err(ProcessError::Invalid("R is identity".into())));
            }

            // Verify R_j consistency for all j > t+1: the remaining points
            // must lie on the same degree-t polynomial. A malicious party
            // sending an inconsistent R_j is detected here.
            for j in (t + 1)..ordered_scalars.len() {
                let expected = exponent_interpolation(
                    &ordered_scalars[..t + 1],
                    &big_r_ordered[..t + 1],
                    Some(&ordered_scalars[j]),
                );
                if expected != big_r_ordered[j] {
                    return (EcdsaState::Completed, Err(ProcessError::Invalid(
                        format!("R_j inconsistent for party {}", ordered_ids[j])
                    )));
                }
            }

            // Scalar interpolation of w using all n points (degree 2t, needs ≥ 2t+1).
            let w = scalar_interpolation(&ordered_scalars, &w_ordered, None);
            if bool::from(w.is_zero()) {
                return (EcdsaState::Completed, Err(ProcessError::Invalid("w is zero".into())));
            }

            // Compute W_me = R^{a_me} and broadcast.
            let a_me = shares[1];
            let big_w_me = big_r * a_me;

            let r3 = R3Broadcast { big_w: point_to_bytes(&big_w_me) };
            let data = match cbor_encode(&r3) {
                Ok(d) => d,
                Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
            };

            let mut big_w_map = BTreeMap::new();
            big_w_map.insert(self_id.clone(), big_w_me);

            (
                EcdsaState::PresignR3 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    parties, self_id: self_id.clone(), max_malicious,
                    shares, secret_share, public_key,
                    big_r, w,
                    big_w_map,
                },
                Ok(StepOutput {
                    messages: vec![OutgoingMessage {
                        session_id,
                        from: self_id,
                        to: String::new(),
                        payload: data,
                    }],
                    result: None,
                }),
            )
        }

        // ---- Presign Round 3: collect W_i, verify, compute presig shares ----
        EcdsaState::PresignR3 {
            session_id, params, parties, self_id, max_malicious,
            shares, secret_share, public_key,
            big_r, w, mut big_w_map,
        } => {
            let r3: R3Broadcast = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (EcdsaState::PresignR3 {
                        session_id, params, parties, self_id, max_malicious,
                        shares, secret_share, public_key, big_r, w, big_w_map,
                    }, Err(ProcessError::WrongRound(e)));
                }
            };

            let big_w_p = match bytes_to_point(&r3.big_w) {
                Ok(p) => p,
                Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
            };

            big_w_map.insert(from.to_string(), big_w_p);

            if big_w_map.len() < parties.len() {
                return (EcdsaState::PresignR3 {
                    session_id, params, parties, self_id, max_malicious,
                    shares, secret_share, public_key, big_r, w, big_w_map,
                }, Ok(StepOutput { messages: vec![], result: None }));
            }

            // All R3 received. Verify W consistency.
            let t = max_malicious;
            let ordered_scalars: Vec<Scalar> = parties.scalars.clone();
            let ordered_ids: Vec<String> = parties.ids.clone();

            let big_w_ordered: Vec<ProjectivePoint> = ordered_ids.iter()
                .map(|id| big_w_map[id]).collect();

            let big_w = exponent_interpolation(
                &ordered_scalars[..t + 1],
                &big_w_ordered[..t + 1],
                None,
            );

            // Verify W_j consistency for all j > t+1.
            for j in (t + 1)..ordered_scalars.len() {
                let expected = exponent_interpolation(
                    &ordered_scalars[..t + 1],
                    &big_w_ordered[..t + 1],
                    Some(&ordered_scalars[j]),
                );
                if expected != big_w_ordered[j] {
                    return (EcdsaState::Completed, Err(ProcessError::Invalid(
                        format!("W_j inconsistent for party {}", ordered_ids[j])
                    )));
                }
            }

            // Verify W == g^w
            if big_w != ProjectivePoint::GENERATOR * w {
                return (EcdsaState::Completed, Err(ProcessError::Invalid("W != g^w".into())));
            }

            // Compute presignature values.
            let w_inv = w.invert().unwrap();
            let a_me = shares[1];
            let d_me = shares[3];
            let e_me = shares[4];

            let c_me = w_inv * a_me;
            let alpha_me = c_me + d_me;
            let beta_me = c_me * secret_share;

            // Compute signature share.
            let big_r_affine = big_r.to_affine();
            let big_r_x = x_coordinate(&big_r_affine);
            let msg_hash = bytes_to_scalar(&params.message)
                .unwrap_or_else(|_| <Scalar as Reduce<U256>>::reduce_bytes(
                    k256::FieldBytes::from_slice(&params.message),
                ));

            // Reject zero hash — enables algebraic split-view attacks (NEAR analysis).
            if bool::from(msg_hash.is_zero()) {
                return (EcdsaState::Completed, Err(ProcessError::Invalid(
                    "refusing to sign zero hash (algebraic attack vector)".into()
                )));
            }

            let beta_rx = beta_me * big_r_x + e_me;
            let s_me = msg_hash * alpha_me + beta_rx;
            let linearized = s_me * lagrange(
                &parties.scalar_of(&self_id).unwrap(),
                &ordered_scalars,
            );

            // The coordinator is this node's own party_id — only the
            // initiating node's session will have party_id matching its
            // own identity. Participants' sessions have their own party_id.
            // We use party_id as coordinator: the initiating node passes
            // its own party_id, and each participant passes theirs.
            // The coordinator is whoever initiated the sign request —
            // identified as signer_ids[0] (the Go node sorts signers and
            // the initiator is always first in the coord message's signer list).
            let coordinator = &params.signer_ids[0];
            let is_coordinator = self_id == *coordinator;

            if is_coordinator {
                // Coordinator stores own share and waits for others.
                let mut sig_shares = BTreeMap::new();
                sig_shares.insert(self_id.clone(), linearized);

                (
                    EcdsaState::SignR4 {
                        session_id,
                        parties, self_id,
                        public_key,
                        big_r: big_r_affine,
                        msg_hash,
                        sig_shares,
                        is_coordinator: true,
                    },
                    Ok(StepOutput { messages: vec![], result: None }),
                )
            } else {
                // Non-coordinator: send share to coordinator and complete.
                let r4 = R4Share { s: scalar_to_bytes(&linearized) };
                let data = match cbor_encode(&r4) {
                    Ok(d) => d,
                    Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
                };

                (
                    EcdsaState::Completed,
                    Ok(StepOutput {
                        messages: vec![OutgoingMessage {
                            session_id,
                            from: self_id,
                            to: coordinator.clone(),
                            payload: data,
                        }],
                        result: Some(SessionResult {
                            group_key: None,
                            verifying_share: None,
                            signature_r: None,
                            signature_z: None,
                        }),
                    }),
                )
            }
        }

        // ---- Sign Round 4: coordinator aggregates shares ----
        EcdsaState::SignR4 {
            session_id, parties, self_id, public_key,
            big_r, msg_hash, mut sig_shares, is_coordinator,
        } => {
            let r4: R4Share = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => {
                    return (EcdsaState::SignR4 {
                        session_id, parties, self_id, public_key,
                        big_r, msg_hash, sig_shares, is_coordinator,
                    }, Err(ProcessError::WrongRound(e)));
                }
            };

            let s_p = match bytes_to_scalar(&r4.s) {
                Ok(s) => s,
                Err(e) => return (EcdsaState::Completed, Err(ProcessError::Invalid(e))),
            };

            sig_shares.insert(from.to_string(), s_p);

            if sig_shares.len() < parties.len() {
                return (EcdsaState::SignR4 {
                    session_id, parties, self_id, public_key,
                    big_r, msg_hash, sig_shares, is_coordinator,
                }, Ok(StepOutput { messages: vec![], result: None }));
            }

            // All shares received. Aggregate.
            let mut s: Scalar = sig_shares.values().copied().fold(Scalar::ZERO, |acc, x| acc + x);
            if bool::from(s.is_zero()) {
                return (EcdsaState::Completed, Err(ProcessError::Invalid("s is zero".into())));
            }

            // Normalize to low-S.
            use k256::elliptic_curve::scalar::IsHigh;
            if bool::from(s.is_high()) {
                s = -s;
            }

            let r_scalar = x_coordinate(&big_r);

            // Return r and s as the signature components.
            // For EVM compatibility: r (32 bytes) + s (32 bytes).
            // Recovery ID (v) can be computed by the Go node from R and the public key.
            (
                EcdsaState::Completed,
                Ok(StepOutput {
                    messages: vec![],
                    result: Some(SessionResult {
                        group_key: None,
                        verifying_share: None,
                        signature_r: Some(scalar_to_bytes(&r_scalar)),
                        signature_z: Some(scalar_to_bytes(&s)),
                    }),
                }),
            )
        }

        EcdsaState::Completed => {
            (EcdsaState::Completed, Err(ProcessError::Invalid("session already completed".into())))
        }
    }
}
