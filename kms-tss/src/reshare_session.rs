//! Reshare session state machine, generic over Ciphersuite.

use std::collections::BTreeMap;

use frost_core::Ciphersuite;
use frost_core::{Field, Group};
use sha2::Digest;
use tracing::debug;

use crate::curve::Curve;
use crate::reshare::{
    self, Polynomial, ReshareParams, ReshareR1Payload, ReshareR2Payload, ReshareR3Payload,
};
use crate::storage::{KeyStatus, Storage, StoredKey};
use crate::types::{cbor_decode, cbor_encode, OutgoingMessage, ProcessError, SessionResult, StepOutput};

type Scalar<C> = <<<C as Ciphersuite>::Group as Group>::Field as Field>::Scalar;
type Element<C> = <<C as Ciphersuite>::Group as Group>::Element;

// ---------------------------------------------------------------------------
// ReshareState<C>
// ---------------------------------------------------------------------------

pub(crate) enum ReshareState<C: Ciphersuite> {
    R1 {
        session_id: String,
        params: ReshareParams,
        is_old: bool,
        is_new: bool,
        polynomial: Option<Polynomial<C>>,
        chain_key: Option<Vec<u8>>,
        old_scalars: Vec<Scalar<C>>,
        new_scalars: Vec<Scalar<C>>,
        self_old_scalar: Option<Scalar<C>>,
        self_new_scalar: Option<Scalar<C>>,
        old_secret: Option<Scalar<C>>,
        group_key: Vec<u8>,
        generation: u64,
        scope: Vec<u8>,
        r1_received: BTreeMap<String, ReshareR1Payload>,
        broadcast_sent: bool,
    },
    R2 {
        session_id: String,
        params: ReshareParams,
        is_old: bool,
        is_new: bool,
        polynomial: Option<Polynomial<C>>,
        old_scalars: Vec<Scalar<C>>,
        new_scalars: Vec<Scalar<C>>,
        self_new_scalar: Option<Scalar<C>>,
        group_key: Vec<u8>,
        generation: u64,
        scope: Vec<u8>,
        all_commitments: BTreeMap<String, Vec<Element<C>>>,
        chain_keys: Vec<(String, Vec<u8>)>,
        sub_shares: BTreeMap<String, Scalar<C>>,
    },
    R3 {
        session_id: String,
        params: ReshareParams,
        new_scalars: Vec<Scalar<C>>,
        self_new_scalar: Scalar<C>,
        group_key: Vec<u8>,
        generation: u64,
        scope: Vec<u8>,
        new_secret: Scalar<C>,
        chain_keys: Vec<(String, Vec<u8>)>,
        pub_shares: BTreeMap<String, Vec<u8>>,
    },
    Completed,
}

// ---------------------------------------------------------------------------
// ReshareSession<C>
// ---------------------------------------------------------------------------

pub(crate) struct ReshareSession<C: Ciphersuite> {
    state: ReshareState<C>,
    pending: Vec<(String, String, Vec<u8>)>,
}

impl<C: Ciphersuite> ReshareSession<C> {
    pub fn state_name(&self) -> &'static str {
        state_name(&self.state)
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn start(
        session_id: &str,
        params: ReshareParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let (state, output) = start_reshare::<C>(session_id, params, storage)?;
        debug!(state = state_name(&state), "reshare session started");
        Ok((ReshareSession { state, pending: vec![] }, output))
    }

    pub fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        let prev_state = state_name(&self.state);
        let state = std::mem::replace(&mut self.state, ReshareState::Completed);
        let (new_state, output) = process_reshare::<C>(state, from, to, payload, storage);
        self.state = new_state;

        match output {
            Ok(step) => {
                debug!(from, prev_state, new_state = state_name(&self.state), "reshare message processed");
                let mut combined = step;
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    for (f, t, p) in pending {
                        let s = std::mem::replace(&mut self.state, ReshareState::Completed);
                        let (ns, result) = process_reshare::<C>(s, &f, &t, &p, storage);
                        self.state = ns;
                        match result {
                            Ok(more) => {
                                combined.messages.extend(more.messages);
                                if let Some(r) = more.result { combined.result = Some(r); }
                            }
                            Err(ProcessError::WrongRound(_)) => { self.pending.push((f, t, p)); }
                            Err(ProcessError::Invalid(e)) => {
                                debug!(error = e.as_str(), "pending reshare message dropped");
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
                debug!(from, error = e.as_str(), "reshare message dropped (invalid)");
                Ok(StepOutput { messages: vec![], result: None })
            }
        }
    }
}

fn state_name<C: Ciphersuite>(state: &ReshareState<C>) -> &'static str {
    match state {
        ReshareState::R1 { .. } => "ReshareR1",
        ReshareState::R2 { .. } => "ReshareR2",
        ReshareState::R3 { .. } => "ReshareR3",
        ReshareState::Completed => "Completed",
    }
}

// ---------------------------------------------------------------------------
// start_reshare
// ---------------------------------------------------------------------------

fn derive_scalar<C: Ciphersuite>(pid: &str) -> Result<Scalar<C>, String> {
    let id = frost_core::Identifier::<C>::derive(pid.as_bytes())
        .map_err(|e| format!("derive identifier for {pid}: {e}"))?;
    reshare::identifier_to_scalar::<C>(&id)
}

fn start_reshare<C: Ciphersuite>(
    session_id: &str,
    params: ReshareParams,
    storage: &Storage,
) -> Result<(ReshareState<C>, StepOutput), String> {
    let is_old = params.old_party_ids.contains(&params.party_id);
    let is_new = params.new_party_ids.contains(&params.party_id);
    if !is_old && !is_new {
        return Err(format!("party {} not in old or new sets", params.party_id));
    }

    let old_scalars: Vec<Scalar<C>> = params.old_party_ids.iter()
        .map(|pid| derive_scalar::<C>(pid))
        .collect::<Result<_, _>>()?;
    let new_scalars: Vec<Scalar<C>> = params.new_party_ids.iter()
        .map(|pid| derive_scalar::<C>(pid))
        .collect::<Result<_, _>>()?;

    let self_old_scalar = if is_old { Some(derive_scalar::<C>(&params.party_id)?) } else { None };
    let self_new_scalar = if is_new { Some(derive_scalar::<C>(&params.party_id)?) } else { None };

    let curve = Curve::from_ciphersuite::<C>();
    let stored = storage.get_key(&params.group_id, &params.key_id, &curve)?;
    let (old_secret, group_key, generation, old_scope) = if is_old {
        let s = stored.ok_or_else(|| {
            format!("reshare: old party has no key for {}/{}", params.group_id, params.key_id)
        })?;
        let kp = frost_core::keys::KeyPackage::<C>::deserialize(&s.key_package)
            .map_err(|e| format!("deserialize key package: {e}"))?;
        let secret_bytes = kp.signing_share().serialize();
        let secret = reshare::deserialize_scalar::<C>(secret_bytes.as_ref())
            .map_err(|e| format!("decode secret scalar: {e}"))?;
        (Some(secret), s.group_key, s.generation, s.scope)
    } else {
        (None, vec![], 0, vec![])
    };

    let mut messages = Vec::new();
    let mut polynomial = None;
    let mut chain_key = None;
    let mut r1_received = BTreeMap::new();

    if is_old {
        let secret = old_secret.unwrap();
        let lambda = reshare::lagrange_coefficient::<C>(self_old_scalar.as_ref().unwrap(), &old_scalars);
        let weighted_secret = secret * lambda;

        let mut rng = rand::thread_rng();
        let poly = Polynomial::<C>::random(weighted_secret, (params.new_threshold - 1) as usize, &mut rng);

        let commitments = poly.commitments();
        let encoded_commitments: Vec<Vec<u8>> = commitments.iter()
            .map(|c| reshare::serialize_element::<C>(c))
            .collect::<Result<_, _>>()?;

        let mut ck = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut ck);

        let payload = ReshareR1Payload {
            commitments: encoded_commitments,
            chain_key: ck.to_vec(),
            generation,
            group_key: group_key.clone(),
        };

        r1_received.insert(params.party_id.clone(), payload.clone());

        let data = cbor_encode(&payload)?;
        messages.push(OutgoingMessage {
            session_id: session_id.to_string(),
            from: params.party_id.clone(),
            to: String::new(),
            payload: data,
        });

        polynomial = Some(poly);
        chain_key = Some(ck.to_vec());
    }

    Ok((
        ReshareState::R1 {
            session_id: session_id.to_string(),
            params, is_old, is_new, polynomial, chain_key,
            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
            old_secret, group_key, generation, scope: old_scope,
            r1_received,
            broadcast_sent: is_old,
        },
        StepOutput { messages, result: None },
    ))
}

// ---------------------------------------------------------------------------
// process_reshare
// ---------------------------------------------------------------------------

fn process_reshare<C: Ciphersuite>(
    state: ReshareState<C>,
    from: &str,
    _to: &str,
    payload: &[u8],
    storage: &Storage,
) -> (ReshareState<C>, Result<StepOutput, ProcessError>) {
    match state {
        // ---- Round 1 ----
        ReshareState::R1 {
            session_id, params, is_old, is_new, polynomial, chain_key,
            old_scalars, new_scalars, self_old_scalar, self_new_scalar,
            old_secret, group_key, generation, scope, mut r1_received, broadcast_sent,
        } => {
            let rebuild = |r1_received| ReshareState::R1 {
                session_id: session_id.clone(), params: params.clone(),
                is_old, is_new, polynomial: polynomial.clone(), chain_key: chain_key.clone(),
                old_scalars: old_scalars.clone(), new_scalars: new_scalars.clone(),
                self_old_scalar, self_new_scalar, old_secret,
                group_key: group_key.clone(), generation, scope: scope.clone(),
                r1_received, broadcast_sent,
            };

            let r1: ReshareR1Payload = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => return (rebuild(r1_received), Err(ProcessError::WrongRound(e))),
            };

            if !params.old_party_ids.contains(&from.to_string()) {
                return (rebuild(r1_received), Err(ProcessError::Invalid(format!("R1 from non-old party: {from}"))));
            }
            if r1_received.contains_key(from) {
                return (rebuild(r1_received), Err(ProcessError::Invalid(format!("duplicate R1 from {from}"))));
            }
            r1_received.insert(from.to_string(), r1);

            if r1_received.len() < params.old_party_ids.len() {
                return (rebuild(r1_received), Ok(StepOutput { messages: vec![], result: None }));
            }

            // All R1 received.
            let resolved_group_key = if group_key.is_empty() {
                r1_received.values().next().unwrap().group_key.clone()
            } else { group_key };
            let resolved_generation = if generation == 0 && !is_old {
                r1_received.values().next().unwrap().generation
            } else { generation };

            for (pid, r1) in &r1_received {
                if r1.group_key != resolved_group_key {
                    return (ReshareState::Completed, Err(ProcessError::Invalid(format!("group key mismatch from {pid}"))));
                }
            }

            let mut all_commitments: BTreeMap<String, Vec<Element<C>>> = BTreeMap::new();
            for (pid, r1) in &r1_received {
                let mut points = Vec::new();
                for raw in &r1.commitments {
                    match reshare::deserialize_element::<C>(raw) {
                        Ok(p) => points.push(p),
                        Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("bad commitment from {pid}: {e}")))),
                    }
                }
                all_commitments.insert(pid.clone(), points);
            }

            // Verify group key preservation.
            let group_key_element = match reshare::deserialize_element::<C>(&resolved_group_key) {
                Ok(p) => p,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("bad group key: {e}")))),
            };
            let mut commit_sum = <C::Group as Group>::identity();
            for (_, commits) in &all_commitments {
                commit_sum = commit_sum + commits[0];
            }
            if commit_sum != group_key_element {
                return (ReshareState::Completed, Err(ProcessError::Invalid("commitment constants don't sum to group key".into())));
            }

            let mut sorted_chain_keys: Vec<(String, Vec<u8>)> = r1_received.iter()
                .map(|(pid, r1)| (pid.clone(), r1.chain_key.clone())).collect();
            sorted_chain_keys.sort_by(|a, b| a.0.cmp(&b.0));

            let mut messages = Vec::new();
            if is_old {
                let poly = polynomial.as_ref().unwrap();
                for (i, new_pid) in params.new_party_ids.iter().enumerate() {
                    if *new_pid == params.party_id { continue; }
                    let sub_share = poly.evaluate(&new_scalars[i]);
                    let r2_payload = ReshareR2Payload {
                        sub_share: reshare::serialize_scalar::<C>(&sub_share),
                    };
                    let data = match cbor_encode(&r2_payload) {
                        Ok(d) => d,
                        Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
                    };
                    messages.push(OutgoingMessage {
                        session_id: session_id.clone(),
                        from: params.party_id.clone(),
                        to: new_pid.clone(),
                        payload: data,
                    });
                }
            }

            (
                ReshareState::R2 {
                    session_id, params, is_old, is_new, polynomial,
                    old_scalars, new_scalars, self_new_scalar,
                    group_key: resolved_group_key, generation: resolved_generation,
                    scope,
                    all_commitments, chain_keys: sorted_chain_keys, sub_shares: BTreeMap::new(),
                },
                Ok(StepOutput { messages, result: None }),
            )
        }

        // ---- Round 2 ----
        ReshareState::R2 {
            session_id, params, is_old, is_new, polynomial,
            old_scalars, new_scalars, self_new_scalar,
            group_key, generation, scope, all_commitments, chain_keys, mut sub_shares,
        } => {
            let rebuild = |sub_shares| ReshareState::R2 {
                session_id: session_id.clone(), params: params.clone(),
                is_old, is_new, polynomial: polynomial.clone(),
                old_scalars: old_scalars.clone(), new_scalars: new_scalars.clone(), self_new_scalar,
                group_key: group_key.clone(), generation, scope: scope.clone(),
                all_commitments: all_commitments.clone(),
                chain_keys: chain_keys.clone(), sub_shares,
            };

            let r2: ReshareR2Payload = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => return (rebuild(sub_shares), Err(ProcessError::WrongRound(e))),
            };

            if !params.old_party_ids.contains(&from.to_string()) {
                return (rebuild(sub_shares), Err(ProcessError::Invalid(format!("R2 from non-old party: {from}"))));
            }
            if sub_shares.contains_key(from) {
                return (rebuild(sub_shares), Err(ProcessError::Invalid(format!("duplicate R2 from {from}"))));
            }

            let sub_share = match reshare::deserialize_scalar::<C>(&r2.sub_share) {
                Ok(s) => s,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("bad sub-share from {from}: {e}")))),
            };

            let self_scalar = self_new_scalar.unwrap();
            if !reshare::verify_feldman::<C>(&self_scalar, &sub_share, &all_commitments[from]) {
                return (ReshareState::Completed, Err(ProcessError::Invalid(format!("Feldman verification failed for {from}"))));
            }

            sub_shares.insert(from.to_string(), sub_share);

            if is_old && !sub_shares.contains_key(&params.party_id) {
                let poly = polynomial.as_ref().unwrap();
                sub_shares.insert(params.party_id.clone(), poly.evaluate(&self_scalar));
            }

            if sub_shares.len() < params.old_party_ids.len() {
                return (rebuild(sub_shares), Ok(StepOutput { messages: vec![], result: None }));
            }

            if is_new {
                let mut new_secret: Scalar<C> = <<C::Group as Group>::Field as Field>::zero();
                for (_, share) in &sub_shares { new_secret = new_secret + *share; }

                let verifying_share = <C::Group as Group>::generator() * new_secret;
                let vs_bytes = match reshare::serialize_element::<C>(&verifying_share) {
                    Ok(b) => b,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
                };

                let data = match cbor_encode(&ReshareR3Payload { verifying_share: vs_bytes.clone() }) {
                    Ok(d) => d,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
                };
                let messages = vec![OutgoingMessage {
                    session_id: session_id.clone(),
                    from: params.party_id.clone(),
                    to: String::new(),
                    payload: data,
                }];

                let mut pub_shares = BTreeMap::new();
                pub_shares.insert(params.party_id.clone(), vs_bytes);

                (
                    ReshareState::R3 {
                        session_id, params, new_scalars,
                        self_new_scalar: self_scalar,
                        group_key, generation, scope, new_secret, chain_keys, pub_shares,
                    },
                    Ok(StepOutput { messages, result: None }),
                )
            } else {
                (
                    ReshareState::Completed,
                    Ok(StepOutput {
                        messages: vec![],
                        result: Some(SessionResult {
                            group_key: Some(group_key), verifying_share: None,
                            signature_r: None, signature_z: None,
                        }),
                    }),
                )
            }
        }

        // ---- Round 3 ----
        ReshareState::R3 {
            session_id, params, new_scalars, self_new_scalar,
            group_key, generation, scope, new_secret, chain_keys, mut pub_shares,
        } => {
            let rebuild = |pub_shares| ReshareState::R3 {
                session_id: session_id.clone(), params: params.clone(),
                new_scalars: new_scalars.clone(), self_new_scalar,
                group_key: group_key.clone(), generation, scope: scope.clone(),
                new_secret,
                chain_keys: chain_keys.clone(), pub_shares,
            };

            let r3: ReshareR3Payload = match cbor_decode(payload) {
                Ok(v) => v,
                Err(e) => return (rebuild(pub_shares), Err(ProcessError::WrongRound(e))),
            };

            if !params.new_party_ids.contains(&from.to_string()) {
                return (rebuild(pub_shares), Err(ProcessError::Invalid(format!("R3 from non-new party: {from}"))));
            }
            if pub_shares.contains_key(from) {
                return (rebuild(pub_shares), Err(ProcessError::Invalid(format!("duplicate R3 from {from}"))));
            }
            pub_shares.insert(from.to_string(), r3.verifying_share);

            if pub_shares.len() < params.new_party_ids.len() {
                return (rebuild(pub_shares), Ok(StepOutput { messages: vec![], result: None }));
            }

            let (_combined_chain_key, _rid) = reshare::combine_chain_keys(&chain_keys);

            let self_verifying_share = <C::Group as Group>::generator() * new_secret;
            let vs_bytes = match reshare::serialize_element::<C>(&self_verifying_share) {
                Ok(b) => b,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(e))),
            };

            // Build frost KeyPackage + PublicKeyPackage from reshare output.
            let self_frost_id = match frost_core::Identifier::<C>::derive(params.party_id.as_bytes()) {
                Ok(id) => id,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("derive frost id: {e}")))),
            };

            let mut frost_verifying_shares = BTreeMap::new();
            for (pid, share_bytes) in &pub_shares {
                let fid = match frost_core::Identifier::<C>::derive(pid.as_bytes()) {
                    Ok(id) => id,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("derive id for {pid}: {e}")))),
                };
                let vs = match frost_core::keys::VerifyingShare::<C>::deserialize(share_bytes) {
                    Ok(v) => v,
                    Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("deserialize verifying share for {pid}: {e}")))),
                };
                frost_verifying_shares.insert(fid, vs);
            }

            let group_verifying_key = match frost_core::VerifyingKey::<C>::deserialize(&group_key) {
                Ok(v) => v,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("deserialize group key: {e}")))),
            };

            let ss_bytes = reshare::serialize_scalar::<C>(&new_secret);
            let signing_share = match frost_core::keys::SigningShare::<C>::deserialize(&ss_bytes) {
                Ok(s) => s,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("build signing share: {e}")))),
            };

            let key_package = frost_core::keys::KeyPackage::<C>::new(
                self_frost_id,
                signing_share,
                *frost_verifying_shares.get(&self_frost_id).unwrap(),
                group_verifying_key,
                params.new_threshold,
            );
            let pub_key_package = frost_core::keys::PublicKeyPackage::<C>::new(
                frost_verifying_shares,
                group_verifying_key,
            );

            let kp_bytes = match key_package.serialize() {
                Ok(b) => b,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("serialize key package: {e}")))),
            };
            let pkp_bytes = match pub_key_package.serialize() {
                Ok(b) => b,
                Err(e) => return (ReshareState::Completed, Err(ProcessError::Invalid(format!("serialize pub key package: {e}")))),
            };

            let stored = StoredKey {
                key_package: kp_bytes.clone(),
                public_key_package: pkp_bytes.clone(),
                group_key: group_key.clone(),
                verifying_share: vs_bytes.clone(),
                generation: generation + 1,
                scope,
                status: KeyStatus::Active,
            };
            debug!(
                key_id = params.key_id.as_str(),
                kp_len = kp_bytes.len(),
                pkp_len = pkp_bytes.len(),
                kp_hash = %hex::encode(&sha2::Sha256::digest(&kp_bytes)[..8]),
                pkp_hash = %hex::encode(&sha2::Sha256::digest(&pkp_bytes)[..8]),
                "reshare: storing pending key"
            );
            let curve = Curve::from_ciphersuite::<C>();
            if let Err(e) = storage.put_pending(&params.group_id, &params.key_id, &curve, &stored) {
                return (ReshareState::Completed, Err(ProcessError::Invalid(format!("persist pending reshare: {e}"))));
            }

            (
                ReshareState::Completed,
                Ok(StepOutput {
                    messages: vec![],
                    result: Some(SessionResult {
                        group_key: Some(group_key),
                        verifying_share: Some(vs_bytes),
                        signature_r: None,
                        signature_z: None,
                    }),
                }),
            )
        }

        ReshareState::Completed => {
            (ReshareState::Completed, Err(ProcessError::Invalid("session already completed".into())))
        }
    }
}
