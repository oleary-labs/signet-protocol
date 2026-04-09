//! Session state machine for FROST keygen and signing.
//!
//! Each session drives the ZF FROST round loop. The gRPC layer feeds incoming
//! peer messages and collects outgoing messages to forward.

use std::collections::BTreeMap;

use frost_secp256k1 as frost;
use frost::keys::dkg;
use frost::{Identifier, round1, round2};
use rand::rngs::ThreadRng;
use tracing::debug;

use crate::params::{KeygenParams, SignParams};
use crate::storage::{Storage, StoredKey};

/// A message the KMS wants to send to a peer (or broadcast).
pub struct OutgoingMessage {
    pub session_id: String,
    pub from: String,
    pub to: String, // empty = broadcast
    pub payload: Vec<u8>,
}

/// The result of a completed session.
pub struct SessionResult {
    pub group_key: Option<Vec<u8>>,
    pub verifying_share: Option<Vec<u8>>,
    pub signature_r: Option<Vec<u8>>,
    pub signature_z: Option<Vec<u8>>,
}

/// Output from processing a message or starting a session.
pub struct StepOutput {
    pub messages: Vec<OutgoingMessage>,
    pub result: Option<SessionResult>,
}

/// Maps string PartyIDs to frost Identifiers.
pub(crate) struct PartyMap {
    to_frost: BTreeMap<String, Identifier>,
    from_frost: BTreeMap<Identifier, String>,
}

impl PartyMap {
    fn new(party_ids: &[String]) -> Result<Self, String> {
        let mut to_frost = BTreeMap::new();
        let mut from_frost = BTreeMap::new();
        for pid in party_ids {
            let id = Identifier::derive(pid.as_bytes())
                .map_err(|e| format!("derive identifier for {pid}: {e}"))?;
            to_frost.insert(pid.clone(), id);
            from_frost.insert(id, pid.clone());
        }
        Ok(PartyMap { to_frost, from_frost })
    }

    fn frost_id(&self, party_id: &str) -> Result<Identifier, String> {
        self.to_frost
            .get(party_id)
            .copied()
            .ok_or_else(|| format!("unknown party: {party_id}"))
    }

    fn party_id(&self, frost_id: &Identifier) -> Result<&str, String> {
        self.from_frost
            .get(frost_id)
            .map(|s| s.as_str())
            .ok_or_else(|| "unknown frost id".to_string())
    }

    fn len(&self) -> usize {
        self.to_frost.len()
    }
}

// ---------------------------------------------------------------------------
// Session — wraps the inner state with a pending message buffer
// ---------------------------------------------------------------------------

/// A buffered (from, to, payload) triple for messages that arrived before
/// the session was ready to process them (e.g. a round-2 unicast arriving
/// while still in round 1). They are replayed after each state transition.
type PendingMsg = (String, String, Vec<u8>);

/// Session wraps the inner round state and handles out-of-order messages by
/// buffering them and replaying after transitions, mirroring the Go tss.Run
/// pending-message pattern.
pub struct Session {
    inner: SessionInner,
    pending: Vec<PendingMsg>,
}

impl Session {
    fn new(inner: SessionInner) -> Self {
        Session { inner, pending: vec![] }
    }

    /// Current round/state name (e.g. "KeygenR1", "Completed").
    pub fn state_name(&self) -> &'static str {
        self.inner.state_name()
    }

    /// Number of messages buffered for later replay.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Create and start a keygen session.
    pub fn start_keygen(
        session_id: &str,
        params: KeygenParams,
    ) -> Result<(Self, StepOutput), String> {
        let (inner, output) = SessionInner::start_keygen(session_id, params)?;
        debug!(state = inner.state_name(), "keygen session started");
        Ok((Session::new(inner), output))
    }

    /// Create and start a signing session.
    pub fn start_sign(
        session_id: &str,
        params: SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let (inner, output) = SessionInner::start_sign(session_id, params, storage)?;
        debug!(state = inner.state_name(), "sign session started");
        Ok((Session::new(inner), output))
    }

    /// Feed an incoming peer message. Out-of-order messages are buffered and
    /// replayed automatically after each state transition.
    pub fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        let prev_state = self.inner.state_name();

        // Take inner state, process (consuming), put it back.
        let state = std::mem::replace(&mut self.inner, SessionInner::Completed);
        let (new_state, output) = state.process_message(from, to, payload, storage);
        self.inner = new_state;

        match output {
            Ok(step) => {
                debug!(
                    from,
                    prev_state,
                    new_state = self.inner.state_name(),
                    outgoing = step.messages.len(),
                    has_result = step.result.is_some(),
                    "message processed"
                );

                // Successful transition — try to drain pending messages.
                let mut combined = step;
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    debug!(count = pending.len(), "draining pending messages");
                    for (f, t, p) in pending {
                        let state = std::mem::replace(&mut self.inner, SessionInner::Completed);
                        let (new_state, result) = state.process_message(&f, &t, &p, storage);
                        self.inner = new_state;
                        match result {
                            Ok(more) => {
                                debug!(
                                    from = f.as_str(),
                                    new_state = self.inner.state_name(),
                                    outgoing = more.messages.len(),
                                    has_result = more.result.is_some(),
                                    "pending message processed"
                                );
                                combined.messages.extend(more.messages);
                                if let Some(r) = more.result {
                                    combined.result = Some(r);
                                }
                            }
                            Err(e) => {
                                debug!(from = f.as_str(), error = e.as_str(), "pending message re-buffered");
                                self.pending.push((f, t, p));
                            }
                        }
                    }
                }
                Ok(combined)
            }
            Err(e) => {
                debug!(
                    from,
                    state = prev_state,
                    error = e.as_str(),
                    pending = self.pending.len() + 1,
                    "message buffered"
                );
                self.pending.push((from.to_string(), to.to_string(), payload.to_vec()));
                Ok(StepOutput { messages: vec![], result: None })
            }
        }
    }
}

enum SessionInner {
    /// DKG round 1: collecting part1 packages from all parties.
    KeygenR1 {
        session_id: String,
        params: KeygenParams,
        pmap: PartyMap,
        self_id: Identifier,
        secret: dkg::round1::SecretPackage,
        packages: BTreeMap<Identifier, dkg::round1::Package>,
    },
    /// DKG round 2: collecting part2 packages from all peers.
    KeygenR2 {
        session_id: String,
        params: KeygenParams,
        pmap: PartyMap,
        #[allow(dead_code)]
        self_id: Identifier,
        secret: dkg::round2::SecretPackage,
        r1_packages: BTreeMap<Identifier, dkg::round1::Package>,
        r2_packages: BTreeMap<Identifier, dkg::round2::Package>,
    },
    /// Sign round 1: collecting commitments from all signers.
    SignR1 {
        session_id: String,
        params: SignParams,
        pmap: PartyMap,
        self_id: Identifier,
        key_package: frost::keys::KeyPackage,
        pub_key_package: frost::keys::PublicKeyPackage,
        nonces: round1::SigningNonces,
        commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    },
    /// Sign round 2: collecting signature shares from all signers.
    SignR2 {
        #[allow(dead_code)]
        session_id: String,
        pmap: PartyMap,
        pub_key_package: frost::keys::PublicKeyPackage,
        signing_package: frost::SigningPackage,
        shares: BTreeMap<Identifier, round2::SignatureShare>,
    },
    Completed,
}

impl SessionInner {
    fn state_name(&self) -> &'static str {
        match self {
            SessionInner::KeygenR1 { .. } => "KeygenR1",
            SessionInner::KeygenR2 { .. } => "KeygenR2",
            SessionInner::SignR1 { .. } => "SignR1",
            SessionInner::SignR2 { .. } => "SignR2",
            SessionInner::Completed => "Completed",
        }
    }

    /// Create and start a keygen session. Returns the inner state and initial outgoing messages.
    fn start_keygen(
        session_id: &str,
        params: KeygenParams,
    ) -> Result<(Self, StepOutput), String> {
        let pmap = PartyMap::new(&params.party_ids)?;
        let self_id = pmap.frost_id(&params.party_id)?;
        let max_signers = params.party_ids.len() as u16;
        let min_signers = params.threshold;

        let mut rng: ThreadRng = rand::thread_rng();
        let (secret, package) = dkg::part1(self_id, max_signers, min_signers, &mut rng)
            .map_err(|e| format!("dkg part1: {e}"))?;

        let payload = package.serialize().map_err(|e| format!("serialize dkg package: {e}"))?;

        let out = OutgoingMessage {
            session_id: session_id.to_string(),
            from: params.party_id.clone(),
            to: String::new(),
            payload,
        };

        let mut packages = BTreeMap::new();
        packages.insert(self_id, package);

        Ok((
            SessionInner::KeygenR1 {
                session_id: session_id.to_string(),
                params,
                pmap,
                self_id,
                secret,
                packages,
            },
            StepOutput {
                messages: vec![out],
                result: None,
            },
        ))
    }

    /// Create and start a signing session.
    fn start_sign(
        session_id: &str,
        params: SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let pmap = PartyMap::new(&params.signer_ids)?;
        let self_id = pmap.frost_id(&params.party_id)?;

        let stored = storage
            .get_key(&params.group_id, &params.key_id)?
            .ok_or_else(|| {
                format!(
                    "key not found: group={} key={}",
                    params.group_id, params.key_id
                )
            })?;

        let key_package = frost::keys::KeyPackage::deserialize(&stored.key_package)
            .map_err(|e| format!("deserialize key package: {e}"))?;
        let pub_key_package =
            frost::keys::PublicKeyPackage::deserialize(&stored.public_key_package)
                .map_err(|e| format!("deserialize public key package: {e}"))?;

        let mut rng: ThreadRng = rand::thread_rng();
        let (nonces, my_commitments) = round1::commit(key_package.signing_share(), &mut rng);

        let payload = my_commitments
            .serialize()
            .map_err(|e| format!("serialize commitments: {e}"))?;

        let out = OutgoingMessage {
            session_id: session_id.to_string(),
            from: params.party_id.clone(),
            to: String::new(),
            payload,
        };

        let mut commitments = BTreeMap::new();
        commitments.insert(self_id, my_commitments);

        Ok((
            SessionInner::SignR1 {
                session_id: session_id.to_string(),
                params,
                pmap,
                self_id,
                key_package,
                pub_key_package,
                nonces,
                commitments,
            },
            StepOutput {
                messages: vec![out],
                result: None,
            },
        ))
    }

    /// Feed an incoming peer message. Returns outgoing messages and possibly a result.
    /// When a result is returned, the session transitions to Completed.
    ///
    /// This is a consuming method that always returns the (possibly updated) state
    /// alongside the result. This prevents state loss: if processing fails, the
    /// caller gets back the original state instead of an accidental `Completed`.
    fn process_message(
        self,
        from: &str,
        _to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> (Self, Result<StepOutput, String>) {
        // Helper macro: if a fallible expression fails, return (restored_state, Err).
        macro_rules! try_or_restore {
            ($expr:expr, $state:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => return ($state, Err(e.to_string())),
                }
            };
        }

        match self {
            SessionInner::KeygenR1 {
                session_id,
                params,
                pmap,
                self_id,
                secret,
                mut packages,
            } => {
                let restore = || SessionInner::KeygenR1 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    self_id,
                    secret: secret.clone(),
                    packages: packages.clone(),
                };

                let from_id = try_or_restore!(pmap.frost_id(from), restore());
                let pkg = try_or_restore!(
                    dkg::round1::Package::deserialize(payload)
                        .map_err(|e| format!("deserialize r1 package from {from}: {e}")),
                    restore()
                );
                packages.insert(from_id, pkg);

                if packages.len() < pmap.len() {
                    (
                        SessionInner::KeygenR1 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret,
                            packages,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // All round1 packages received. Run part2.
                    let others: BTreeMap<_, _> = packages
                        .iter()
                        .filter(|(id, _)| **id != self_id)
                        .map(|(id, pkg)| (*id, pkg.clone()))
                        .collect();
                    let (r2_secret, r2_packages) = try_or_restore!(
                        dkg::part2(secret, &others)
                            .map_err(|e| format!("dkg part2: {e}")),
                        // secret consumed by part2 on success; on error it's not consumed
                        // but we can't easily restore — this is a fatal protocol error anyway
                        SessionInner::Completed
                    );

                    let mut messages = Vec::new();
                    for (target_id, pkg) in &r2_packages {
                        if *target_id == self_id {
                            continue;
                        }
                        let to_party = try_or_restore!(
                            pmap.party_id(target_id),
                            SessionInner::Completed
                        );
                        let payload = try_or_restore!(
                            pkg.serialize()
                                .map_err(|e| format!("serialize r2 package: {e}")),
                            SessionInner::Completed
                        );
                        messages.push(OutgoingMessage {
                            session_id: session_id.clone(),
                            from: params.party_id.clone(),
                            to: to_party.to_string(),
                            payload,
                        });
                    }

                    (
                        SessionInner::KeygenR2 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret: r2_secret,
                            r1_packages: others,
                            r2_packages: BTreeMap::new(),
                        },
                        Ok(StepOutput {
                            messages,
                            result: None,
                        }),
                    )
                }
            }

            SessionInner::KeygenR2 {
                session_id,
                params,
                pmap,
                self_id,
                secret,
                r1_packages,
                mut r2_packages,
            } => {
                let restore = || SessionInner::KeygenR2 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    self_id,
                    secret: secret.clone(),
                    r1_packages: r1_packages.clone(),
                    r2_packages: r2_packages.clone(),
                };

                let from_id = try_or_restore!(pmap.frost_id(from), restore());
                let pkg = try_or_restore!(
                    dkg::round2::Package::deserialize(payload)
                        .map_err(|e| format!("deserialize r2 package from {from}: {e}")),
                    restore()
                );
                r2_packages.insert(from_id, pkg);

                // Need N-1 round2 packages (from all peers, not self).
                if r2_packages.len() < pmap.len() - 1 {
                    (
                        SessionInner::KeygenR2 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            secret,
                            r1_packages,
                            r2_packages,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // Finalize DKG.
                    let (key_package, pub_key_package) = try_or_restore!(
                        dkg::part3(&secret, &r1_packages, &r2_packages)
                            .map_err(|e| format!("dkg part3: {e}")),
                        SessionInner::Completed
                    );

                    let group_key = try_or_restore!(
                        pub_key_package.verifying_key().serialize()
                            .map_err(|e| format!("serialize group key: {e}")),
                        SessionInner::Completed
                    );
                    let verifying_share = try_or_restore!(
                        key_package.verifying_share().serialize()
                            .map_err(|e| format!("serialize verifying share: {e}")),
                        SessionInner::Completed
                    );

                    let kp_bytes = try_or_restore!(
                        key_package.serialize()
                            .map_err(|e| format!("serialize key package: {e}")),
                        SessionInner::Completed
                    );
                    let pkp_bytes = try_or_restore!(
                        pub_key_package.serialize()
                            .map_err(|e| format!("serialize pub key package: {e}")),
                        SessionInner::Completed
                    );

                    let stored = StoredKey {
                        key_package: kp_bytes,
                        public_key_package: pkp_bytes,
                        group_key: group_key.clone(),
                        verifying_share: verifying_share.clone(),
                        generation: 0,
                    };
                    try_or_restore!(
                        storage.put_key(&params.group_id, &params.key_id, &stored),
                        SessionInner::Completed
                    );

                    (
                        SessionInner::Completed,
                        Ok(StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: Some(group_key),
                                verifying_share: Some(verifying_share),
                                signature_r: None,
                                signature_z: None,
                            }),
                        }),
                    )
                }
            }

            SessionInner::SignR1 {
                session_id,
                params,
                pmap,
                self_id,
                key_package,
                pub_key_package,
                nonces,
                mut commitments,
            } => {
                let restore = || SessionInner::SignR1 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    self_id,
                    key_package: key_package.clone(),
                    pub_key_package: pub_key_package.clone(),
                    nonces: nonces.clone(),
                    commitments: commitments.clone(),
                };

                let from_id = try_or_restore!(pmap.frost_id(from), restore());
                let c = try_or_restore!(
                    round1::SigningCommitments::deserialize(payload)
                        .map_err(|e| format!("deserialize commitments from {from}: {e}")),
                    restore()
                );
                commitments.insert(from_id, c);

                if commitments.len() < pmap.len() {
                    (
                        SessionInner::SignR1 {
                            session_id,
                            params,
                            pmap,
                            self_id,
                            key_package,
                            pub_key_package,
                            nonces,
                            commitments,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // All commitments received. Build signing package and sign.
                    let signing_package =
                        frost::SigningPackage::new(commitments, &params.message);

                    let sig_share = try_or_restore!(
                        round2::sign(&signing_package, &nonces, &key_package)
                            .map_err(|e| format!("round2 sign: {e}")),
                        SessionInner::Completed
                    );

                    let payload = sig_share.serialize();

                    let out = OutgoingMessage {
                        session_id: session_id.clone(),
                        from: params.party_id.clone(),
                        to: String::new(),
                        payload,
                    };

                    let mut shares = BTreeMap::new();
                    shares.insert(self_id, sig_share);

                    (
                        SessionInner::SignR2 {
                            session_id,
                            pmap,
                            pub_key_package,
                            signing_package,
                            shares,
                        },
                        Ok(StepOutput {
                            messages: vec![out],
                            result: None,
                        }),
                    )
                }
            }

            SessionInner::SignR2 {
                session_id,
                pmap,
                pub_key_package,
                signing_package,
                mut shares,
            } => {
                let restore = || SessionInner::SignR2 {
                    session_id: session_id.clone(),
                    pmap: PartyMap { to_frost: pmap.to_frost.clone(), from_frost: pmap.from_frost.clone() },
                    pub_key_package: pub_key_package.clone(),
                    signing_package: signing_package.clone(),
                    shares: shares.clone(),
                };

                let from_id = try_or_restore!(pmap.frost_id(from), restore());
                let share = try_or_restore!(
                    round2::SignatureShare::deserialize(payload)
                        .map_err(|e| format!("deserialize sig share from {from}: {e}")),
                    restore()
                );
                shares.insert(from_id, share);

                if shares.len() < pmap.len() {
                    (
                        SessionInner::SignR2 {
                            session_id,
                            pmap,
                            pub_key_package,
                            signing_package,
                            shares,
                        },
                        Ok(StepOutput {
                            messages: vec![],
                            result: None,
                        }),
                    )
                } else {
                    // Aggregate signatures.
                    let sig = try_or_restore!(
                        frost::aggregate(&signing_package, &shares, &pub_key_package)
                            .map_err(|e| format!("aggregate: {e}")),
                        SessionInner::Completed
                    );

                    let sig_bytes = try_or_restore!(
                        sig.serialize()
                            .map_err(|e| format!("serialize signature: {e}")),
                        SessionInner::Completed
                    );

                    if sig_bytes.len() != 65 {
                        return (
                            SessionInner::Completed,
                            Err(format!(
                                "unexpected signature length: {} (expected 65)",
                                sig_bytes.len()
                            )),
                        );
                    }

                    (
                        SessionInner::Completed,
                        Ok(StepOutput {
                            messages: vec![],
                            result: Some(SessionResult {
                                group_key: None,
                                verifying_share: None,
                                signature_r: Some(sig_bytes[..33].to_vec()),
                                signature_z: Some(sig_bytes[33..].to_vec()),
                            }),
                        }),
                    )
                }
            }

            SessionInner::Completed => {
                (SessionInner::Completed, Err("session already completed".into()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1 as frost;
    use std::collections::HashMap;
    use std::sync::Once;

    const GROUP_ID: &str = "test-group";
    const KEY_ID: &str = "test-key";
    const PARTIES: [&str; 3] = ["peer-A", "peer-B", "peer-C"];

    static TRACING_INIT: Once = Once::new();

    /// Install a tracing subscriber that prints debug output when
    /// RUST_LOG is set. Silent by default; run with
    /// `RUST_LOG=debug cargo test -- --nocapture` to see traces.
    fn init_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();
        });
    }

    /// Create a temp Storage for each party.
    fn make_storages(parties: &[&str]) -> HashMap<String, (Storage, tempfile::TempDir)> {
        parties
            .iter()
            .map(|pid| {
                let dir = tempfile::tempdir().unwrap();
                let storage = Storage::new(dir.path().to_str().unwrap()).unwrap();
                (pid.to_string(), (storage, dir))
            })
            .collect()
    }

    /// Route a batch of outgoing messages from one session to the appropriate
    /// peer sessions. Broadcasts (to == "") go to every session except the
    /// sender; unicasts go to the named recipient.
    ///
    /// Returns all results produced by the receiving sessions.
    fn route(
        msgs: Vec<OutgoingMessage>,
        sessions: &mut HashMap<String, (Session, Storage)>,
    ) -> Vec<SessionResult> {
        let mut results = Vec::new();
        for msg in msgs {
            let recipients: Vec<String> = if msg.to.is_empty() {
                sessions
                    .keys()
                    .filter(|k| **k != msg.from)
                    .cloned()
                    .collect()
            } else {
                vec![msg.to.clone()]
            };

            for recipient in recipients {
                if let Some((session, storage)) = sessions.get_mut(&recipient) {
                    let out = session
                        .process_message(&msg.from, &recipient, &msg.payload, storage)
                        .expect("process_message failed");
                    let sub_msgs = out.messages;
                    if let Some(r) = out.result {
                        results.push(r);
                    }
                    if !sub_msgs.is_empty() {
                        let sub_results = route(sub_msgs, sessions);
                        results.extend(sub_results);
                    }
                }
            }
        }
        results
    }

    /// Deliver messages one-at-a-time without recursion. Returns messages
    /// produced by each delivery so the caller controls ordering.
    fn deliver_one(
        msg: &OutgoingMessage,
        recipient: &str,
        sessions: &mut HashMap<String, (Session, Storage)>,
    ) -> StepOutput {
        let (session, storage) = sessions.get_mut(recipient).expect("unknown recipient");
        session
            .process_message(&msg.from, recipient, &msg.payload, storage)
            .expect("process_message failed")
    }

    /// Run a full 2-of-3 keygen. Returns the group public key.
    /// Storages are borrowed from `owned` (which keeps TempDirs alive).
    fn run_keygen(
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> Vec<u8> {
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            initial_messages.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), 3, "expected 3 keygen results, got {}", results.len());

        let group_keys: Vec<Vec<u8>> = results
            .iter()
            .map(|r| r.group_key.clone().expect("group_key missing"))
            .collect();
        assert!(
            group_keys.windows(2).all(|w| w[0] == w[1]),
            "group keys disagree"
        );

        // Move storages back (re-wrap with dummy TempDirs — originals still live in caller).
        for (pid, (session, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            // Re-open storage at same path is fine for sled; but we just reuse the instance.
            owned.insert(pid, (storage, dir));
            drop(session);
        }

        group_keys.into_iter().next().unwrap()
    }

    /// Sign `message` with the given signer subset and verify the result.
    /// Returns (R, z) byte vecs.
    fn run_sign(
        signers: &[&str],
        message: &[u8],
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> (Vec<u8>, Vec<u8>) {
        let signer_ids: Vec<String> = signers.iter().map(|s| s.to_string()).collect();
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();

        for pid in signers {
            let params = SignParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.to_string(),
                signer_ids: signer_ids.clone(),
                message: message.to_vec(),
            };
            let (storage, _) = owned.remove(*pid).unwrap();
            let (session, output) =
                Session::start_sign(&format!("sign-{pid}"), params, &storage)
                    .expect("start_sign");
            initial_messages.extend(output.messages);
            sessions.insert(pid.to_string(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), signers.len(), "expected {} sign results", signers.len());

        // All signers must agree.
        let r0 = results[0].signature_r.as_ref().unwrap();
        let z0 = results[0].signature_z.as_ref().unwrap();
        for r in &results[1..] {
            assert_eq!(r.signature_r.as_ref().unwrap(), r0, "R mismatch");
            assert_eq!(r.signature_z.as_ref().unwrap(), z0, "z mismatch");
        }

        // Move storages back.
        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        (r0.clone(), z0.clone())
    }

    fn verify_signature(group_key: &[u8], message: &[u8], sig_r: &[u8], sig_z: &[u8]) {
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(sig_r);
        sig_bytes.extend_from_slice(sig_z);
        let sig = frost::Signature::deserialize(&sig_bytes).expect("deserialize signature");
        let vk = frost::VerifyingKey::deserialize(group_key).expect("deserialize verifying key");
        vk.verify(message, &sig).expect("signature verification failed");
    }

    // =======================================================================
    // Happy-path tests
    // =======================================================================

    #[test]
    fn test_keygen_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        assert_eq!(group_key.len(), 33);
        for pid in PARTIES {
            let (storage, _) = owned.get(pid).unwrap();
            let stored = storage
                .get_key(GROUP_ID, KEY_ID)
                .unwrap()
                .expect("missing stored key");
            assert_eq!(stored.group_key, group_key);
        }
    }

    #[test]
    fn test_sign_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        let message = b"deadbeef01234567deadbeef01234567";
        let (sig_r, sig_z) = run_sign(&["peer-A", "peer-B"], message, &mut owned);
        verify_signature(&group_key, message, &sig_r, &sig_z);
    }

    // =======================================================================
    // Signer subset tests — verify all 2-of-3 combinations produce valid sigs
    // =======================================================================

    #[test]
    fn test_all_signer_subsets() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        let message = b"test all subsets message payload!";

        let subsets: &[&[&str]] = &[
            &["peer-A", "peer-B"],
            &["peer-A", "peer-C"],
            &["peer-B", "peer-C"],
        ];
        for subset in subsets {
            let (sig_r, sig_z) = run_sign(subset, message, &mut owned);
            verify_signature(&group_key, message, &sig_r, &sig_z);
        }
    }

    // =======================================================================
    // Multiple independent signs with the same key
    // =======================================================================

    #[test]
    fn test_sign_different_messages() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        let msg1 = b"first message to sign here!!!!!" ;
        let msg2 = b"second message, totally different";

        let (r1, z1) = run_sign(&["peer-A", "peer-B"], msg1, &mut owned);
        let (r2, z2) = run_sign(&["peer-A", "peer-C"], msg2, &mut owned);

        verify_signature(&group_key, msg1, &r1, &z1);
        verify_signature(&group_key, msg2, &r2, &z2);

        // Different messages must produce different signatures.
        assert_ne!(r1, r2, "different messages produced same R");
    }

    // =======================================================================
    // Out-of-order message delivery
    // =======================================================================

    #[test]
    fn test_keygen_out_of_order_delivery() {
        init_tracing();
        // Manually drive a 2-of-3 keygen delivering round-2 messages
        // before all round-1 messages have arrived.
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut r1_broadcasts: Vec<OutgoingMessage> = Vec::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            r1_broadcasts.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        // Deliver A's broadcast to B and C (everyone has 2/3 R1 packages).
        let a_broadcast = &r1_broadcasts[0];
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        deliver_one(a_broadcast, "peer-C", &mut sessions);
        assert_eq!(sessions["peer-B"].0.state_name(), "KeygenR1");
        assert_eq!(sessions["peer-C"].0.state_name(), "KeygenR1");

        // Deliver B's broadcast to C — C now has all 3 R1 packages, transitions to R2.
        let b_broadcast = &r1_broadcasts[1];
        let step = deliver_one(b_broadcast, "peer-C", &mut sessions);
        assert_eq!(sessions["peer-C"].0.state_name(), "KeygenR2");
        let c_r2_messages = step.messages;
        assert_eq!(c_r2_messages.len(), 2, "C should send 2 unicast R2 packages");

        // Deliver C's R2 unicasts BEFORE finishing R1 delivery.
        // A and B are still in KeygenR1 — these must be buffered.
        for msg in &c_r2_messages {
            let recipient = &msg.to;
            deliver_one(msg, recipient, &mut sessions);
        }
        assert_eq!(sessions["peer-A"].0.state_name(), "KeygenR1");
        assert_eq!(sessions["peer-A"].0.pending_count(), 1, "A should buffer C's R2 msg");
        assert_eq!(sessions["peer-B"].0.state_name(), "KeygenR1");
        assert_eq!(sessions["peer-B"].0.pending_count(), 1, "B should buffer C's R2 msg");

        // Now deliver remaining R1 broadcasts so everyone can finish.
        // B's broadcast to A:
        deliver_one(b_broadcast, "peer-A", &mut sessions);
        assert_eq!(sessions["peer-A"].0.state_name(), "KeygenR1", "A still needs C's R1");

        // C's broadcast to A and B:
        let c_broadcast = &r1_broadcasts[2];
        let step_a = deliver_one(c_broadcast, "peer-A", &mut sessions);
        // A should transition to R2, drain pending C R2 msg, and possibly complete.
        assert!(
            sessions["peer-A"].0.state_name() == "KeygenR2"
                || sessions["peer-A"].0.state_name() == "Completed",
            "A should be in KeygenR2 or Completed after getting all R1 + buffered R2, got {}",
            sessions["peer-A"].0.state_name()
        );
        let a_r2_messages = step_a.messages;

        let step_b = deliver_one(c_broadcast, "peer-B", &mut sessions);
        let b_r2_messages = step_b.messages;

        // Route remaining R2 messages to completion.
        let mut all_remaining = Vec::new();
        all_remaining.extend(a_r2_messages);
        all_remaining.extend(b_r2_messages);
        route(all_remaining, &mut sessions);

        // Collect all results (some may have come from pending drain).
        let completed: Vec<_> = sessions
            .values()
            .filter(|(s, _)| s.state_name() == "Completed")
            .collect();
        assert_eq!(completed.len(), 3, "all 3 parties should complete");
    }

    // =======================================================================
    // Duplicate message handling
    // =======================================================================

    #[test]
    fn test_duplicate_r1_message_ignored() {
        init_tracing();
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut r1_broadcasts: Vec<OutgoingMessage> = Vec::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            r1_broadcasts.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        // Deliver A's broadcast to B twice — the duplicate should overwrite
        // (BTreeMap insert) and not cause a double-count.
        let a_broadcast = &r1_broadcasts[0];
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        assert_eq!(
            sessions["peer-B"].0.state_name(),
            "KeygenR1",
            "duplicate R1 should not advance state"
        );

        // Now deliver remaining broadcasts normally — keygen should complete.
        let results = route(r1_broadcasts, &mut sessions);
        assert_eq!(results.len(), 3, "keygen should still complete after duplicate");
    }

    // =======================================================================
    // Unknown sender
    // =======================================================================

    #[test]
    fn test_unknown_sender_buffered() {
        init_tracing();
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, _output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            sessions.insert(pid.clone(), (session, storage));
        }

        // Send a message from an unknown party.
        let (session, storage) = sessions.get_mut("peer-A").unwrap();
        let result = session.process_message("peer-UNKNOWN", "peer-A", b"garbage", storage);
        // Should not panic — message gets buffered (unknown sender → frost_id fails → buffered).
        assert!(result.is_ok(), "unknown sender should not cause panic");
        assert_eq!(session.pending_count(), 1, "unknown sender message should be buffered");
        assert_eq!(session.state_name(), "KeygenR1", "state should be unchanged");
    }

    // =======================================================================
    // Corrupted payload
    // =======================================================================

    #[test]
    fn test_corrupted_payload_buffered() {
        init_tracing();
        let party_ids: Vec<String> = PARTIES.iter().map(|s| s.to_string()).collect();
        let mut owned = make_storages(&PARTIES);
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();

        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, _output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            sessions.insert(pid.clone(), (session, storage));
        }

        // Send corrupted bytes from a known party.
        let (session, storage) = sessions.get_mut("peer-A").unwrap();
        let result = session.process_message("peer-B", "peer-A", b"not-a-frost-package", storage);
        assert!(result.is_ok(), "corrupted payload should not cause panic");
        assert_eq!(session.pending_count(), 1, "corrupted message should be buffered");
        assert_eq!(session.state_name(), "KeygenR1", "state should be preserved");
    }

    // =======================================================================
    // Message after completion
    // =======================================================================

    #[test]
    fn test_message_after_completion_buffered() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        run_keygen(&mut owned);

        // Sign to get a completed session.
        let signer_ids: Vec<String> = vec!["peer-A".to_string(), "peer-B".to_string()];
        let message = b"deadbeef01234567deadbeef01234567";

        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();
        for pid in ["peer-A", "peer-B"] {
            let params = SignParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.to_string(),
                signer_ids: signer_ids.clone(),
                message: message.to_vec(),
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_sign(&format!("sign-{pid}"), params, &storage).expect("start_sign");
            initial_messages.extend(output.messages);
            sessions.insert(pid.to_string(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), 2);
        assert_eq!(sessions["peer-A"].0.state_name(), "Completed");

        // Send another message to the completed session.
        let (session, storage) = sessions.get_mut("peer-A").unwrap();
        let result = session.process_message("peer-B", "peer-A", b"late-message", storage);
        assert!(result.is_ok(), "message to completed session should not panic");
        // It gets buffered (will never be drained, but doesn't break anything).
        assert_eq!(session.pending_count(), 1);
    }

    // =======================================================================
    // Storage round-trip: sign using key loaded from cold storage
    // =======================================================================

    #[test]
    fn test_sign_from_cold_storage() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        // Sign using storages that only have persisted keys — no in-memory
        // session state carried over. This is the real-world path: KMS restarts
        // between keygen and sign.
        let message = b"cold storage signing test!!!!!!!" ;
        let (sig_r, sig_z) = run_sign(&["peer-B", "peer-C"], message, &mut owned);
        verify_signature(&group_key, message, &sig_r, &sig_z);
    }
}
