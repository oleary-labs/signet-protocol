//! Session state machine for FROST keygen and signing.
//!
//! `TypedSession<C>` is generic over `frost_core::Ciphersuite` and handles
//! keygen (DKG) and signing. Reshare is handled separately in
//! `reshare_session.rs` (secp256k1 only for now).
//!
//! The public `Session` enum dispatches between concrete ciphersuites and
//! the reshare path.

use std::collections::BTreeMap;

use frost_core::Ciphersuite;
use rand::rngs::ThreadRng;
use sha2::Digest;
use tracing::debug;

use crate::curve::Curve;
use crate::ecdsa_session::EcdsaSession;
use crate::params::{KeygenParams, SignParams};
use crate::reshare::ReshareParams;
use crate::reshare_session::ReshareSession;
use crate::storage::{KeyStatus, Storage, StoredKey};
use crate::types::{OutgoingMessage, ProcessError, SessionResult, StepOutput};


type PendingMsg = (String, String, Vec<u8>);

// ---------------------------------------------------------------------------
// PartyMap<C> — generic string ↔ frost Identifier mapping
// ---------------------------------------------------------------------------

struct PartyMap<C: Ciphersuite> {
    to_frost: BTreeMap<String, frost_core::Identifier<C>>,
    from_frost: BTreeMap<frost_core::Identifier<C>, String>,
}

impl<C: Ciphersuite> PartyMap<C> {
    fn new(party_ids: &[String]) -> Result<Self, String> {
        let mut to_frost = BTreeMap::new();
        let mut from_frost = BTreeMap::new();
        for pid in party_ids {
            let id = frost_core::Identifier::<C>::derive(pid.as_bytes())
                .map_err(|e| format!("derive identifier for {pid}: {e}"))?;
            to_frost.insert(pid.clone(), id);
            from_frost.insert(id, pid.clone());
        }
        Ok(PartyMap { to_frost, from_frost })
    }

    fn frost_id(&self, party_id: &str) -> Result<frost_core::Identifier<C>, String> {
        self.to_frost
            .get(party_id)
            .copied()
            .ok_or_else(|| format!("unknown party: {party_id}"))
    }

    fn party_id(&self, frost_id: &frost_core::Identifier<C>) -> Result<&str, String> {
        self.from_frost
            .get(frost_id)
            .map(|s| s.as_str())
            .ok_or_else(|| "unknown frost id".to_string())
    }

    fn len(&self) -> usize {
        self.to_frost.len()
    }

    fn clone_maps(&self) -> (BTreeMap<String, frost_core::Identifier<C>>, BTreeMap<frost_core::Identifier<C>, String>) {
        (self.to_frost.clone(), self.from_frost.clone())
    }
}

// ---------------------------------------------------------------------------
// TypedState<C> — generic keygen/sign state machine
// ---------------------------------------------------------------------------

enum TypedState<C: Ciphersuite> {
    KeygenR1 {
        session_id: String,
        params: KeygenParams,
        pmap: PartyMap<C>,
        self_id: frost_core::Identifier<C>,
        secret: frost_core::keys::dkg::round1::SecretPackage<C>,
        packages: BTreeMap<frost_core::Identifier<C>, frost_core::keys::dkg::round1::Package<C>>,
    },
    KeygenR2 {
        session_id: String,
        params: KeygenParams,
        pmap: PartyMap<C>,
        #[allow(dead_code)]
        self_id: frost_core::Identifier<C>,
        secret: frost_core::keys::dkg::round2::SecretPackage<C>,
        r1_packages: BTreeMap<frost_core::Identifier<C>, frost_core::keys::dkg::round1::Package<C>>,
        r2_packages: BTreeMap<frost_core::Identifier<C>, frost_core::keys::dkg::round2::Package<C>>,
    },
    SignR1 {
        session_id: String,
        params: SignParams,
        pmap: PartyMap<C>,
        self_id: frost_core::Identifier<C>,
        key_package: frost_core::keys::KeyPackage<C>,
        pub_key_package: frost_core::keys::PublicKeyPackage<C>,
        nonces: frost_core::round1::SigningNonces<C>,
        commitments: BTreeMap<frost_core::Identifier<C>, frost_core::round1::SigningCommitments<C>>,
    },
    SignR2 {
        #[allow(dead_code)]
        session_id: String,
        pmap: PartyMap<C>,
        pub_key_package: frost_core::keys::PublicKeyPackage<C>,
        signing_package: frost_core::SigningPackage<C>,
        shares: BTreeMap<frost_core::Identifier<C>, frost_core::round2::SignatureShare<C>>,
    },
    Completed,
}

// ---------------------------------------------------------------------------
// TypedSession<C> — buffered wrapper with pending-message replay
// ---------------------------------------------------------------------------

pub(crate) struct TypedSession<C: Ciphersuite> {
    state: TypedState<C>,
    pending: Vec<PendingMsg>,
}

impl<C: Ciphersuite> TypedSession<C> {
    fn state_name(&self) -> &'static str {
        match &self.state {
            TypedState::KeygenR1 { .. } => "KeygenR1",
            TypedState::KeygenR2 { .. } => "KeygenR2",
            TypedState::SignR1 { .. } => "SignR1",
            TypedState::SignR2 { .. } => "SignR2",
            TypedState::Completed => "Completed",
        }
    }

    fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn start_keygen(
        session_id: &str,
        params: KeygenParams,
    ) -> Result<(Self, StepOutput), String> {
        let pmap = PartyMap::<C>::new(&params.party_ids)?;
        let self_id = pmap.frost_id(&params.party_id)?;
        let max_signers = params.party_ids.len() as u16;
        let min_signers = params.threshold;

        let mut rng: ThreadRng = rand::thread_rng();
        let (secret, package) = frost_core::keys::dkg::part1::<C, _>(self_id, max_signers, min_signers, &mut rng)
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
            TypedSession {
                state: TypedState::KeygenR1 {
                    session_id: session_id.to_string(),
                    params,
                    pmap,
                    self_id,
                    secret,
                    packages,
                },
                pending: vec![],
            },
            StepOutput { messages: vec![out], result: None },
        ))
    }

    fn start_sign(
        session_id: &str,
        params: SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        let pmap = PartyMap::<C>::new(&params.signer_ids)?;
        let self_id = pmap.frost_id(&params.party_id)?;

        let curve = Curve::from_ciphersuite::<C>();
        let stored = storage
            .get_key(&params.group_id, &params.key_id, &curve)?
            .ok_or_else(|| format!("key not found: group={} key={} curve={}", params.group_id, params.key_id, curve))?;

        debug!(
            key_id = params.key_id.as_str(),
            kp_len = stored.key_package.len(),
            pkp_len = stored.public_key_package.len(),
            kp_hash = %hex::encode(&sha2::Sha256::digest(&stored.key_package)[..8]),
            pkp_hash = %hex::encode(&sha2::Sha256::digest(&stored.public_key_package)[..8]),
            generation = stored.generation,
            "sign: loading key from storage"
        );

        let key_package = frost_core::keys::KeyPackage::<C>::deserialize(&stored.key_package)
            .map_err(|e| format!("deserialize key package: {e}"))?;
        let pub_key_package = frost_core::keys::PublicKeyPackage::<C>::deserialize(&stored.public_key_package)
            .map_err(|e| format!("deserialize public key package: {e}"))?;

        let mut rng: ThreadRng = rand::thread_rng();
        let (nonces, my_commitments) = frost_core::round1::commit::<C, _>(key_package.signing_share(), &mut rng);

        let payload = my_commitments.serialize().map_err(|e| format!("serialize commitments: {e}"))?;

        let out = OutgoingMessage {
            session_id: session_id.to_string(),
            from: params.party_id.clone(),
            to: String::new(),
            payload,
        };

        let mut commitments = BTreeMap::new();
        commitments.insert(self_id, my_commitments);

        Ok((
            TypedSession {
                state: TypedState::SignR1 {
                    session_id: session_id.to_string(),
                    params,
                    pmap,
                    self_id,
                    key_package,
                    pub_key_package,
                    nonces,
                    commitments,
                },
                pending: vec![],
            },
            StepOutput { messages: vec![out], result: None },
        ))
    }

    fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        let prev_state = self.state_name();
        let state = std::mem::replace(&mut self.state, TypedState::Completed);
        let (new_state, output) = process_typed::<C>(state, from, to, payload, storage);
        self.state = new_state;

        match output {
            Ok(step) => {
                debug!(
                    from,
                    prev_state,
                    new_state = self.state_name(),
                    outgoing = step.messages.len(),
                    has_result = step.result.is_some(),
                    "message processed"
                );
                let mut combined = step;
                if !self.pending.is_empty() {
                    let pending = std::mem::take(&mut self.pending);
                    for (f, t, p) in pending {
                        let s = std::mem::replace(&mut self.state, TypedState::Completed);
                        let (ns, result) = process_typed::<C>(s, &f, &t, &p, storage);
                        self.state = ns;
                        match result {
                            Ok(more) => {
                                combined.messages.extend(more.messages);
                                if let Some(r) = more.result {
                                    combined.result = Some(r);
                                }
                            }
                            Err(ProcessError::WrongRound(_)) => {
                                self.pending.push((f, t, p));
                            }
                            Err(ProcessError::Invalid(e)) => {
                                debug!(error = e.as_str(), "pending message dropped");
                            }
                        }
                    }
                }
                Ok(combined)
            }
            Err(ProcessError::WrongRound(e)) => {
                debug!(from, error = e.as_str(), "message buffered (wrong round)");
                self.pending.push((from.to_string(), to.to_string(), payload.to_vec()));
                Ok(StepOutput { messages: vec![], result: None })
            }
            Err(ProcessError::Invalid(e)) => {
                debug!(from, error = e.as_str(), "message dropped (invalid)");
                Ok(StepOutput { messages: vec![], result: None })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// process_typed — generic keygen/sign state transitions
// ---------------------------------------------------------------------------

fn process_typed<C: Ciphersuite>(
    state: TypedState<C>,
    from: &str,
    _to: &str,
    payload: &[u8],
    storage: &Storage,
) -> (TypedState<C>, Result<StepOutput, ProcessError>) {
    macro_rules! try_wrong_round {
        ($expr:expr, $state:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ($state, Err(ProcessError::WrongRound(e.to_string()))),
            }
        };
    }
    macro_rules! try_invalid {
        ($expr:expr, $state:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return ($state, Err(ProcessError::Invalid(e.to_string()))),
            }
        };
    }

    match state {
        TypedState::KeygenR1 {
            session_id, params, pmap, self_id, secret, mut packages,
        } => {
            let restore = || {
                let (tf, ff) = pmap.clone_maps();
                TypedState::KeygenR1 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: tf, from_frost: ff },
                    self_id,
                    secret: secret.clone(),
                    packages: packages.clone(),
                }
            };

            let from_id = try_invalid!(pmap.frost_id(from), restore());
            let pkg = try_wrong_round!(
                frost_core::keys::dkg::round1::Package::<C>::deserialize(payload)
                    .map_err(|e| format!("deserialize r1 package from {from}: {e}")),
                restore()
            );
            packages.insert(from_id, pkg);

            if packages.len() < pmap.len() {
                (
                    TypedState::KeygenR1 { session_id, params, pmap, self_id, secret, packages },
                    Ok(StepOutput { messages: vec![], result: None }),
                )
            } else {
                let others: BTreeMap<_, _> = packages
                    .iter()
                    .filter(|(id, _)| **id != self_id)
                    .map(|(id, pkg)| (*id, pkg.clone()))
                    .collect();
                let (r2_secret, r2_packages) = try_invalid!(
                    frost_core::keys::dkg::part2::<C>(secret, &others)
                        .map_err(|e| format!("dkg part2: {e}")),
                    TypedState::Completed
                );

                let mut messages = Vec::new();
                for (target_id, pkg) in &r2_packages {
                    if *target_id == self_id { continue; }
                    let to_party = try_invalid!(pmap.party_id(target_id), TypedState::Completed);
                    let payload = try_invalid!(
                        pkg.serialize().map_err(|e| format!("serialize r2 package: {e}")),
                        TypedState::Completed
                    );
                    messages.push(OutgoingMessage {
                        session_id: session_id.clone(),
                        from: params.party_id.clone(),
                        to: to_party.to_string(),
                        payload,
                    });
                }

                (
                    TypedState::KeygenR2 {
                        session_id, params, pmap, self_id,
                        secret: r2_secret,
                        r1_packages: others,
                        r2_packages: BTreeMap::new(),
                    },
                    Ok(StepOutput { messages, result: None }),
                )
            }
        }

        TypedState::KeygenR2 {
            session_id, params, pmap, self_id, secret, r1_packages, mut r2_packages,
        } => {
            let restore = || {
                let (tf, ff) = pmap.clone_maps();
                TypedState::KeygenR2 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: tf, from_frost: ff },
                    self_id,
                    secret: secret.clone(),
                    r1_packages: r1_packages.clone(),
                    r2_packages: r2_packages.clone(),
                }
            };

            let from_id = try_invalid!(pmap.frost_id(from), restore());
            let pkg = try_wrong_round!(
                frost_core::keys::dkg::round2::Package::<C>::deserialize(payload)
                    .map_err(|e| format!("deserialize r2 package from {from}: {e}")),
                restore()
            );
            r2_packages.insert(from_id, pkg);

            if r2_packages.len() < pmap.len() - 1 {
                (
                    TypedState::KeygenR2 { session_id, params, pmap, self_id, secret, r1_packages, r2_packages },
                    Ok(StepOutput { messages: vec![], result: None }),
                )
            } else {
                let (key_package, pub_key_package) = try_invalid!(
                    frost_core::keys::dkg::part3::<C>(&secret, &r1_packages, &r2_packages)
                        .map_err(|e| format!("dkg part3: {e}")),
                    TypedState::Completed
                );

                let group_key = try_invalid!(
                    pub_key_package.verifying_key().serialize()
                        .map_err(|e| format!("serialize group key: {e}")),
                    TypedState::Completed
                );
                let verifying_share = try_invalid!(
                    key_package.verifying_share().serialize()
                        .map_err(|e| format!("serialize verifying share: {e}")),
                    TypedState::Completed
                );

                let kp_bytes = try_invalid!(
                    key_package.serialize().map_err(|e| format!("serialize key package: {e}")),
                    TypedState::Completed
                );
                let pkp_bytes = try_invalid!(
                    pub_key_package.serialize().map_err(|e| format!("serialize pub key package: {e}")),
                    TypedState::Completed
                );

                let stored = StoredKey {
                    key_package: kp_bytes,
                    public_key_package: pkp_bytes,
                    group_key: group_key.clone(),
                    verifying_share: verifying_share.clone(),
                    generation: 0,
                    scope: params.scope.clone(),
                    status: KeyStatus::Active,
                };
                try_invalid!(
                    storage.put_key(&params.group_id, &params.key_id, &params.curve, &stored),
                    TypedState::Completed
                );

                (
                    TypedState::Completed,
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

        TypedState::SignR1 {
            session_id, params, pmap, self_id,
            key_package, pub_key_package, nonces, mut commitments,
        } => {
            let restore = || {
                let (tf, ff) = pmap.clone_maps();
                TypedState::SignR1 {
                    session_id: session_id.clone(),
                    params: params.clone(),
                    pmap: PartyMap { to_frost: tf, from_frost: ff },
                    self_id,
                    key_package: key_package.clone(),
                    pub_key_package: pub_key_package.clone(),
                    nonces: nonces.clone(),
                    commitments: commitments.clone(),
                }
            };

            let from_id = try_invalid!(pmap.frost_id(from), restore());
            let c = try_wrong_round!(
                frost_core::round1::SigningCommitments::<C>::deserialize(payload)
                    .map_err(|e| format!("deserialize commitments from {from}: {e}")),
                restore()
            );
            commitments.insert(from_id, c);

            if commitments.len() < pmap.len() {
                (
                    TypedState::SignR1 {
                        session_id, params, pmap, self_id,
                        key_package, pub_key_package, nonces, commitments,
                    },
                    Ok(StepOutput { messages: vec![], result: None }),
                )
            } else {
                let signing_package = frost_core::SigningPackage::<C>::new(commitments, &params.message);

                let sig_share = try_invalid!(
                    frost_core::round2::sign::<C>(&signing_package, &nonces, &key_package)
                        .map_err(|e| format!("round2 sign: {e}")),
                    TypedState::Completed
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
                    TypedState::SignR2 {
                        session_id, pmap, pub_key_package, signing_package, shares,
                    },
                    Ok(StepOutput { messages: vec![out], result: None }),
                )
            }
        }

        TypedState::SignR2 {
            session_id, pmap, pub_key_package, signing_package, mut shares,
        } => {
            let restore = || {
                let (tf, ff) = pmap.clone_maps();
                TypedState::SignR2 {
                    session_id: session_id.clone(),
                    pmap: PartyMap { to_frost: tf, from_frost: ff },
                    pub_key_package: pub_key_package.clone(),
                    signing_package: signing_package.clone(),
                    shares: shares.clone(),
                }
            };

            let from_id = try_invalid!(pmap.frost_id(from), restore());
            let share = try_wrong_round!(
                frost_core::round2::SignatureShare::<C>::deserialize(payload)
                    .map_err(|e| format!("deserialize sig share from {from}: {e}")),
                restore()
            );
            shares.insert(from_id, share);

            if shares.len() < pmap.len() {
                (
                    TypedState::SignR2 { session_id, pmap, pub_key_package, signing_package, shares },
                    Ok(StepOutput { messages: vec![], result: None }),
                )
            } else {
                let sig = try_invalid!(
                    frost_core::aggregate::<C>(&signing_package, &shares, &pub_key_package)
                        .map_err(|e| format!("aggregate: {e}")),
                    TypedState::Completed
                );

                let sig_bytes = try_invalid!(
                    sig.serialize().map_err(|e| format!("serialize signature: {e}")),
                    TypedState::Completed
                );

                // Split signature into R and z components.
                // secp256k1: 65 bytes (R=33, z=32)
                // ed25519:   64 bytes (R=32, s=32)
                let sig_len = sig_bytes.len();
                let r_len = sig_len - 32; // R is everything except last 32 bytes

                (
                    TypedState::Completed,
                    Ok(StepOutput {
                        messages: vec![],
                        result: Some(SessionResult {
                            group_key: None,
                            verifying_share: None,
                            signature_r: Some(sig_bytes[..r_len].to_vec()),
                            signature_z: Some(sig_bytes[r_len..].to_vec()),
                        }),
                    }),
                )
            }
        }

        TypedState::Completed => {
            (TypedState::Completed, Err(ProcessError::Invalid("session already completed".into())))
        }
    }
}

// ---------------------------------------------------------------------------
// Session — public API, dispatches between ciphersuites and reshare
// ---------------------------------------------------------------------------

pub enum Session {
    Secp256k1(TypedSession<frost_secp256k1::Secp256K1Sha256>),
    Ed25519(TypedSession<frost_ed25519::Ed25519Sha512>),
    EcdsaSecp256k1(EcdsaSession),
    ReshareSecp256k1(ReshareSession<frost_secp256k1::Secp256K1Sha256>),
    ReshareEd25519(ReshareSession<frost_ed25519::Ed25519Sha512>),
}

impl Session {
    pub fn state_name(&self) -> &'static str {
        match self {
            Session::Secp256k1(s) => s.state_name(),
            Session::Ed25519(s) => s.state_name(),
            Session::EcdsaSecp256k1(s) => s.state_name(),
            Session::ReshareSecp256k1(s) => s.state_name(),
            Session::ReshareEd25519(s) => s.state_name(),
        }
    }

    pub fn pending_count(&self) -> usize {
        match self {
            Session::Secp256k1(s) => s.pending_count(),
            Session::Ed25519(s) => s.pending_count(),
            Session::EcdsaSecp256k1(s) => s.pending_count(),
            Session::ReshareSecp256k1(s) => s.pending_count(),
            Session::ReshareEd25519(s) => s.pending_count(),
        }
    }

    pub fn start_keygen(
        session_id: &str,
        params: KeygenParams,
    ) -> Result<(Self, StepOutput), String> {
        match params.curve {
            Curve::Secp256k1 | Curve::EcdsaSecp256k1 => {
                // Both FROST Schnorr and ECDSA use the same secp256k1 DKG.
                let (s, o) = TypedSession::<frost_secp256k1::Secp256K1Sha256>::start_keygen(session_id, params)?;
                Ok((Session::Secp256k1(s), o))
            }
            Curve::Ed25519 => {
                let (s, o) = TypedSession::<frost_ed25519::Ed25519Sha512>::start_keygen(session_id, params)?;
                Ok((Session::Ed25519(s), o))
            }
        }
    }

    pub fn start_sign(
        session_id: &str,
        params: SignParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        match params.curve {
            Curve::Secp256k1 => {
                let (s, o) = TypedSession::<frost_secp256k1::Secp256K1Sha256>::start_sign(session_id, params, storage)?;
                Ok((Session::Secp256k1(s), o))
            }
            Curve::Ed25519 => {
                let (s, o) = TypedSession::<frost_ed25519::Ed25519Sha512>::start_sign(session_id, params, storage)?;
                Ok((Session::Ed25519(s), o))
            }
            Curve::EcdsaSecp256k1 => {
                let (s, o) = EcdsaSession::start(session_id, params, storage)?;
                Ok((Session::EcdsaSecp256k1(s), o))
            }
        }
    }

    pub fn start_reshare(
        session_id: &str,
        params: ReshareParams,
        storage: &Storage,
    ) -> Result<(Self, StepOutput), String> {
        match params.curve {
            Curve::Secp256k1 | Curve::EcdsaSecp256k1 => {
                let (s, o) = ReshareSession::<frost_secp256k1::Secp256K1Sha256>::start(session_id, params, storage)?;
                Ok((Session::ReshareSecp256k1(s), o))
            }
            Curve::Ed25519 => {
                let (s, o) = ReshareSession::<frost_ed25519::Ed25519Sha512>::start(session_id, params, storage)?;
                Ok((Session::ReshareEd25519(s), o))
            }
        }
    }

    pub fn process_message(
        &mut self,
        from: &str,
        to: &str,
        payload: &[u8],
        storage: &Storage,
    ) -> Result<StepOutput, String> {
        match self {
            Session::Secp256k1(s) => s.process_message(from, to, payload, storage),
            Session::Ed25519(s) => s.process_message(from, to, payload, storage),
            Session::EcdsaSecp256k1(s) => s.process_message(from, to, payload, storage),
            Session::ReshareSecp256k1(s) => s.process_message(from, to, payload, storage),
            Session::ReshareEd25519(s) => s.process_message(from, to, payload, storage),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Once;

    const GROUP_ID: &str = "test-group";
    const KEY_ID: &str = "test-key";
    const PARTIES: [&str; 3] = ["peer-A", "peer-B", "peer-C"];

    static TRACING_INIT: Once = Once::new();

    fn init_tracing() {
        TRACING_INIT.call_once(|| {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
                .with_test_writer()
                .try_init();
        });
    }

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

    fn route(
        initial_msgs: Vec<OutgoingMessage>,
        sessions: &mut HashMap<String, (Session, Storage)>,
    ) -> Vec<SessionResult> {
        let mut results = Vec::new();
        let mut queue: std::collections::VecDeque<OutgoingMessage> = initial_msgs.into();

        while let Some(msg) = queue.pop_front() {
            let recipients: Vec<String> = if msg.to.is_empty() {
                sessions.keys().filter(|k| **k != msg.from).cloned().collect()
            } else {
                vec![msg.to.clone()]
            };

            for recipient in recipients {
                if let Some((session, storage)) = sessions.get_mut(&recipient) {
                    let out = session
                        .process_message(&msg.from, &recipient, &msg.payload, storage)
                        .expect("process_message failed");
                    if let Some(r) = out.result { results.push(r); }
                    for m in out.messages { queue.push_back(m); }
                }
            }
        }
        results
    }

    fn deliver_one(
        msg: &OutgoingMessage,
        recipient: &str,
        sessions: &mut HashMap<String, (Session, Storage)>,
    ) -> StepOutput {
        let (session, storage) = sessions.get_mut(recipient).expect("unknown recipient");
        session.process_message(&msg.from, recipient, &msg.payload, storage).expect("process_message failed")
    }

    // -----------------------------------------------------------------------
    // Generic keygen/sign helpers parameterized by curve
    // -----------------------------------------------------------------------

    fn run_keygen_with_curve(
        curve: Curve,
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
                curve,
                scope: vec![],
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
        assert!(group_keys.windows(2).all(|w| w[0] == w[1]), "group keys disagree");

        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        group_keys.into_iter().next().unwrap()
    }

    fn run_sign_with_curve(
        signers: &[&str],
        message: &[u8],
        curve: Curve,
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
                curve,
            };
            let (storage, _) = owned.remove(*pid).unwrap();
            let (session, output) =
                Session::start_sign(&format!("sign-{pid}"), params, &storage).expect("start_sign");
            initial_messages.extend(output.messages);
            sessions.insert(pid.to_string(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), signers.len());

        let r0 = results[0].signature_r.as_ref().unwrap();
        let z0 = results[0].signature_z.as_ref().unwrap();
        for r in &results[1..] {
            assert_eq!(r.signature_r.as_ref().unwrap(), r0, "R mismatch");
            assert_eq!(r.signature_z.as_ref().unwrap(), z0, "z mismatch");
        }

        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        (r0.clone(), z0.clone())
    }

    // Backwards compat wrappers
    fn run_keygen(owned: &mut HashMap<String, (Storage, tempfile::TempDir)>) -> Vec<u8> {
        run_keygen_with_curve(Curve::Secp256k1, owned)
    }

    fn run_sign(
        signers: &[&str],
        message: &[u8],
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> (Vec<u8>, Vec<u8>) {
        run_sign_with_curve(signers, message, Curve::Secp256k1, owned)
    }

    fn verify_signature_secp256k1(group_key: &[u8], message: &[u8], sig_r: &[u8], sig_z: &[u8]) {
        let mut sig_bytes = Vec::with_capacity(sig_r.len() + sig_z.len());
        sig_bytes.extend_from_slice(sig_r);
        sig_bytes.extend_from_slice(sig_z);
        let sig = frost_secp256k1::Signature::deserialize(&sig_bytes).expect("deserialize signature");
        let vk = frost_secp256k1::VerifyingKey::deserialize(group_key).expect("deserialize verifying key");
        vk.verify(message, &sig).expect("signature verification failed");
    }

    fn verify_signature_ed25519(group_key: &[u8], message: &[u8], sig_r: &[u8], sig_z: &[u8]) {
        let mut sig_bytes = Vec::with_capacity(sig_r.len() + sig_z.len());
        sig_bytes.extend_from_slice(sig_r);
        sig_bytes.extend_from_slice(sig_z);
        let sig = frost_ed25519::Signature::deserialize(&sig_bytes).expect("deserialize signature");
        let vk = frost_ed25519::VerifyingKey::deserialize(group_key).expect("deserialize verifying key");
        vk.verify(message, &sig).expect("signature verification failed");
    }

    // ===================================================================
    // secp256k1 tests (existing behavior)
    // ===================================================================

    #[test]
    fn test_keygen_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        assert_eq!(group_key.len(), 33);
    }

    #[test]
    fn test_sign_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        let message = b"deadbeef01234567deadbeef01234567";
        let (sig_r, sig_z) = run_sign(&["peer-A", "peer-B"], message, &mut owned);
        verify_signature_secp256k1(&group_key, message, &sig_r, &sig_z);
    }

    #[test]
    fn test_all_signer_subsets() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        let message = b"test all subsets message payload!";
        for subset in &[&["peer-A", "peer-B"][..], &["peer-A", "peer-C"][..], &["peer-B", "peer-C"][..]] {
            let (sig_r, sig_z) = run_sign(subset, message, &mut owned);
            verify_signature_secp256k1(&group_key, message, &sig_r, &sig_z);
        }
    }

    #[test]
    fn test_sign_different_messages() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        let msg1 = b"first message to sign here!!!!!" ;
        let msg2 = b"second message, totally different";
        let (r1, z1) = run_sign(&["peer-A", "peer-B"], msg1, &mut owned);
        let (r2, z2) = run_sign(&["peer-A", "peer-C"], msg2, &mut owned);
        verify_signature_secp256k1(&group_key, msg1, &r1, &z1);
        verify_signature_secp256k1(&group_key, msg2, &r2, &z2);
        assert_ne!(r1, r2, "different messages produced same R");
    }

    #[test]
    fn test_keygen_out_of_order_delivery() {
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
                curve: Curve::Secp256k1,
                scope: vec![],
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) = Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            r1_broadcasts.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        let a_broadcast = &r1_broadcasts[0];
        deliver_one(a_broadcast, "peer-B", &mut sessions);
        deliver_one(a_broadcast, "peer-C", &mut sessions);

        let b_broadcast = &r1_broadcasts[1];
        let step = deliver_one(b_broadcast, "peer-C", &mut sessions);
        assert_eq!(sessions["peer-C"].0.state_name(), "KeygenR2");
        let c_r2_messages = step.messages;

        for msg in &c_r2_messages {
            deliver_one(msg, &msg.to, &mut sessions);
        }
        assert_eq!(sessions["peer-A"].0.pending_count(), 1);

        deliver_one(b_broadcast, "peer-A", &mut sessions);

        let c_broadcast = &r1_broadcasts[2];
        let step_a = deliver_one(c_broadcast, "peer-A", &mut sessions);
        let step_b = deliver_one(c_broadcast, "peer-B", &mut sessions);

        let mut remaining = Vec::new();
        remaining.extend(step_a.messages);
        remaining.extend(step_b.messages);
        route(remaining, &mut sessions);

        let completed: Vec<_> = sessions.values().filter(|(s, _)| s.state_name() == "Completed").collect();
        assert_eq!(completed.len(), 3);
    }

    // ===================================================================
    // Ed25519 tests
    // ===================================================================

    #[test]
    fn test_ed25519_keygen_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen_with_curve(Curve::Ed25519, &mut owned);
        assert_eq!(group_key.len(), 32, "Ed25519 group key should be 32 bytes");
    }

    #[test]
    fn test_ed25519_sign_2_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen_with_curve(Curve::Ed25519, &mut owned);
        let message = b"deadbeef01234567deadbeef01234567";
        let (sig_r, sig_z) = run_sign_with_curve(&["peer-A", "peer-B"], message, Curve::Ed25519, &mut owned);
        verify_signature_ed25519(&group_key, message, &sig_r, &sig_z);
    }

    #[test]
    fn test_ed25519_all_signer_subsets() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen_with_curve(Curve::Ed25519, &mut owned);
        let message = b"ed25519 all subsets test message!";
        for subset in &[&["peer-A", "peer-B"][..], &["peer-A", "peer-C"][..], &["peer-B", "peer-C"][..]] {
            let (sig_r, sig_z) = run_sign_with_curve(subset, message, Curve::Ed25519, &mut owned);
            verify_signature_ed25519(&group_key, message, &sig_r, &sig_z);
        }
    }

    // ===================================================================
    // Reshare tests (secp256k1 only, via Session::start_reshare)
    // ===================================================================

    fn run_reshare(
        old_parties: &[&str],
        new_parties: &[&str],
        new_threshold: u16,
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> Vec<u8> {
        let old_ids: Vec<String> = old_parties.iter().map(|s| s.to_string()).collect();
        let new_ids: Vec<String> = new_parties.iter().map(|s| s.to_string()).collect();

        let mut all_parties: Vec<String> = old_ids.clone();
        for p in &new_ids {
            if !all_parties.contains(p) { all_parties.push(p.clone()); }
        }

        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();

        for pid in &all_parties {
            let params = ReshareParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                old_party_ids: old_ids.clone(),
                new_party_ids: new_ids.clone(),
                new_threshold,
                curve: Curve::Secp256k1,
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_reshare(&format!("reshare-{pid}"), params, &storage).expect("start_reshare");
            initial_messages.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), all_parties.len());

        let group_keys: Vec<Vec<u8>> = results.iter().map(|r| r.group_key.clone().unwrap()).collect();
        assert!(group_keys.windows(2).all(|w| w[0] == w[1]));

        for pid in &new_ids {
            let (_, storage) = sessions.get(pid).unwrap();
            storage.commit_reshare(GROUP_ID, KEY_ID, &Curve::Secp256k1).unwrap();
        }

        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        group_keys.into_iter().next().unwrap()
    }

    #[test]
    fn test_reshare_same_committee() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);

        let msg1 = b"before reshare, signing works!!!";
        let (r1, z1) = run_sign(&["peer-A", "peer-B"], msg1, &mut owned);
        verify_signature_secp256k1(&group_key, msg1, &r1, &z1);

        let reshare_group_key = run_reshare(
            &["peer-A", "peer-B", "peer-C"],
            &["peer-A", "peer-B", "peer-C"],
            2,
            &mut owned,
        );
        assert_eq!(group_key, reshare_group_key);

        let msg2 = b"after reshare, still works!!!!!!";
        let (r2, z2) = run_sign(&["peer-A", "peer-C"], msg2, &mut owned);
        verify_signature_secp256k1(&group_key, msg2, &r2, &z2);
    }

    #[test]
    fn test_sign_from_cold_storage() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_keygen(&mut owned);
        let message = b"cold storage signing test!!!!!!!";
        let (sig_r, sig_z) = run_sign(&["peer-B", "peer-C"], message, &mut owned);
        verify_signature_secp256k1(&group_key, message, &sig_r, &sig_z);
    }

    // ===================================================================
    // Threshold ECDSA tests
    // ===================================================================

    fn run_ecdsa_keygen(
        owned: &mut HashMap<String, (Storage, tempfile::TempDir)>,
    ) -> Vec<u8> {
        run_keygen_with_curve(Curve::EcdsaSecp256k1, owned)
    }

    fn run_ecdsa_sign(
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
                curve: Curve::EcdsaSecp256k1,
            };
            let (storage, _) = owned.remove(*pid).unwrap();
            let (session, output) =
                Session::start_sign(&format!("ecdsa-sign-{pid}"), params, &storage)
                    .expect("start_sign ecdsa");
            initial_messages.extend(output.messages);
            sessions.insert(pid.to_string(), (session, storage));
        }

        let results = route(initial_messages, &mut sessions);
        // Only the coordinator produces a result with signature.
        let sig_results: Vec<&SessionResult> = results.iter()
            .filter(|r| r.signature_r.is_some())
            .collect();
        assert!(!sig_results.is_empty(), "no signature result from coordinator");

        let r = sig_results[0].signature_r.as_ref().unwrap().clone();
        let s = sig_results[0].signature_z.as_ref().unwrap().clone();

        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        (r, s)
    }

    fn verify_ecdsa_signature(group_key: &[u8], msg_hash: &[u8], sig_r: &[u8], sig_s: &[u8]) {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        let r_bytes: [u8; 32] = sig_r.try_into().expect("r must be 32 bytes");
        let s_bytes: [u8; 32] = sig_s.try_into().expect("s must be 32 bytes");
        let sig = k256::ecdsa::Signature::from_scalars(r_bytes, s_bytes)
            .expect("invalid signature scalars");
        let pk = k256::PublicKey::from_sec1_bytes(group_key)
            .expect("invalid group key");
        let vk = k256::ecdsa::VerifyingKey::from(&pk);
        vk.verify_prehash(msg_hash, &sig)
            .expect("ECDSA signature verification failed");
    }

    #[test]
    fn test_ecdsa_keygen_and_sign_3_of_3() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_ecdsa_keygen(&mut owned);
        assert_eq!(group_key.len(), 33, "secp256k1 compressed key");

        let msg_hash = sha2::Sha256::digest(b"ecdsa threshold test message");
        let (sig_r, sig_s) = run_ecdsa_sign(&PARTIES, &msg_hash, &mut owned);

        assert_eq!(sig_r.len(), 32);
        assert_eq!(sig_s.len(), 32);

        verify_ecdsa_signature(&group_key, &msg_hash, &sig_r, &sig_s);
        println!("ECDSA 3-of-3 keygen + sign + verify: OK");
    }

    #[test]
    fn test_ecdsa_multiple_signs() {
        init_tracing();
        let mut owned = make_storages(&PARTIES);
        let group_key = run_ecdsa_keygen(&mut owned);

        for i in 0..5 {
            let msg = format!("ecdsa message {i}");
            let msg_hash = sha2::Sha256::digest(msg.as_bytes());
            let (sig_r, sig_s) = run_ecdsa_sign(&PARTIES, &msg_hash, &mut owned);
            verify_ecdsa_signature(&group_key, &msg_hash, &sig_r, &sig_s);
        }
        println!("ECDSA 5 sequential signs: OK");
    }

    #[test]
    fn test_ecdsa_5_of_5_sign() {
        // 5 parties, t=2, n=5=2t+1 (minimum for t=2).
        init_tracing();
        const PARTIES5: [&str; 5] = ["peer-A", "peer-B", "peer-C", "peer-D", "peer-E"];
        let mut owned = make_storages(&PARTIES5);

        // Keygen with all 5.
        let party_ids: Vec<String> = PARTIES5.iter().map(|s| s.to_string()).collect();
        let mut sessions: HashMap<String, (Session, Storage)> = HashMap::new();
        let mut initial_messages = Vec::new();
        for pid in &party_ids {
            let params = KeygenParams {
                group_id: GROUP_ID.to_string(),
                key_id: KEY_ID.to_string(),
                party_id: pid.clone(),
                party_ids: party_ids.clone(),
                threshold: 2,
                curve: Curve::EcdsaSecp256k1,
                scope: vec![],
            };
            let (storage, _) = owned.remove(pid).unwrap();
            let (session, output) =
                Session::start_keygen(&format!("keygen-{pid}"), params).expect("start_keygen");
            initial_messages.extend(output.messages);
            sessions.insert(pid.clone(), (session, storage));
        }
        let results = route(initial_messages, &mut sessions);
        assert_eq!(results.len(), 5);
        let group_key = results[0].group_key.clone().unwrap();
        for (pid, (_, storage)) in sessions {
            let dir = tempfile::tempdir().unwrap();
            owned.insert(pid, (storage, dir));
        }

        // Sign with all 5 (n=5 > 2t+1=5 for t=2, or n=5 > 2t+1=3 for t=1).
        let msg_hash = sha2::Sha256::digest(b"ecdsa 5-of-5 test");
        let (sig_r, sig_s) = run_ecdsa_sign(&PARTIES5, &msg_hash, &mut owned);
        verify_ecdsa_signature(&group_key, &msg_hash, &sig_r, &sig_s);
        println!("ECDSA 5-of-5 sign: OK");
    }
}
