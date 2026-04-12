// Coordination Protocol
// Based on: node/coord.go
//
// Models the barrier synchronization layer that precedes every TSS operation.
// An initiator broadcasts a coordMsg to all participants, each validates
// independently and responds ACK/NACK. The TSS protocol starts only after
// all participants ACK. Any NACK aborts the session.
//
// This spec models the coordination layer only, not the TSS rounds that
// follow. The boundary is: coord delivers ACK/NACK, initiator reaches
// AllAcked or Aborted.
//
// Abstraction choices:
//   - Auth validation abstracted to a boolean (not ZK proofs or cert internals)
//   - Nonce uniqueness and timestamp freshness modeled explicitly
//   - Network is reliable; no message loss or reordering
//   - PartyID modeled as str
//   - Initiator is a distinguished party (asymmetric protocol)
//   - TSS parameters (threshold, signers, message hash) omitted; they pass
//     through coordination transparently
module coord {

  // ============================================================
  // 1. TYPES
  // ============================================================

  type PartyID = str

  /// What kind of TSS operation this coordination is for
  type OpType =
    | Keygen
    | Sign

  /// Initiator-side protocol phase
  type InitiatorPhase =
    | Idle
    | Broadcasting    // coord msg sent, collecting responses
    | AllAcked        // all participants ACKed, TSS can start
    | Aborted         // at least one NACK or failure

  /// Participant-side protocol phase
  type ParticipantPhase =
    | PIdle           // not yet received coord message
    | Received        // coord message decoded
    | Validated       // auth + key checks passed
    | Acked           // ACK sent
    | Nacked          // NACK sent

  /// Response byte (0x01 = ACK, 0x00 = NACK)
  type Response =
    | ACK
    | NACK

  /// Abstract auth proof. The spec does not model ZK proofs or cert
  /// verification internals, just whether validation passes or fails.
  type AuthInfo = {
    present: bool,     // whether auth proof is attached
    valid: bool,       // will validation succeed? (abstract)
    nonce: str,        // replay-prevention nonce
    timestamp: int     // abstract timestamp (freshness)
  }

  /// The coordination message broadcast by initiator
  type CoordMsg = {
    opType: OpType,
    groupID: str,
    keyID: str,
    auth: AuthInfo,
    signNonce: str     // only used for Sign (empty for Keygen)
  }

  /// Payload wrappers for network messages (Quint sum types take one arg)
  type CoordPayload = {
    sender: PartyID,
    payload: CoordMsg
  }

  type ResponsePayload = {
    sender: PartyID,
    response: Response
  }

  /// Messages on the network
  type NetMsg =
    | CoordMessage(CoordPayload)
    | ResponseMessage(ResponsePayload)

  /// Per-participant local state
  type ParticipantState = {
    id: PartyID,
    phase: ParticipantPhase,
    receivedMsg: CoordMsg,
    response: Response
  }

  /// Initiator local state
  type InitiatorState = {
    id: PartyID,
    phase: InitiatorPhase,
    coordMsg: CoordMsg,
    acksReceived: Set[PartyID],
    nacksReceived: Set[PartyID]
  }

  // ============================================================
  // 2. CONSTANTS AND CONFIGURATION
  // ============================================================

  pure val P1: PartyID = "p1"  // initiator
  pure val P2: PartyID = "p2"  // participant
  pure val P3: PartyID = "p3"  // participant

  pure val PARTIES: Set[PartyID] = Set(P1, P2, P3)
  pure val PARTICIPANTS: Set[PartyID] = Set(P2, P3)

  pure val GROUP_ID = "group1"
  pure val KEY_ID = "key1"
  pure val SIGN_NONCE = "snonce1"

  /// Whether this group requires auth validation
  pure val HAS_AUTH_POLICY: bool = true

  /// Abstract current time and freshness window
  pure val NOW: int = 1000
  pure val TIMESTAMP_WINDOW: int = 30

  /// Sentinel values
  pure val EMPTY_AUTH: AuthInfo = {
    present: false, valid: false, nonce: "", timestamp: 0
  }
  pure val EMPTY_COORD_MSG: CoordMsg = {
    opType: Keygen, groupID: "", keyID: "", auth: EMPTY_AUTH, signNonce: ""
  }

  // ============================================================
  // 3. HELPER PURE FUNCTIONS
  // ============================================================

  /// Check if timestamp is within freshness window
  pure def isFresh(ts: int, now: int, window: int): bool =
    ts >= now - window and ts <= now + window

  /// Check if auth is required and present+valid
  pure def authOK(auth: AuthInfo, hasPolicy: bool): bool =
    if (not(hasPolicy)) true
    else auth.present and auth.valid

  /// Check if timestamp is fresh
  pure def timestampOK(auth: AuthInfo, hasPolicy: bool, now: int, window: int): bool =
    if (not(hasPolicy)) true
    else isFresh(auth.timestamp, now, window)

  /// Full validation check for a participant
  pure def validationPasses(
    msg: CoordMsg,
    hasPolicy: bool,
    keyExists: bool,
    nonces: Set[str],
    now: int,
    window: int
  ): bool = and {
    authOK(msg.auth, hasPolicy),
    timestampOK(msg.auth, hasPolicy, now, window),
    // Nonce uniqueness (only checked when auth policy exists)
    not(hasPolicy) or not(nonces.contains(msg.auth.nonce)),
    // Key constraints: keygen requires key NOT to exist, sign requires key to exist
    match msg.opType {
      | Keygen => not(keyExists)
      | Sign => keyExists
    }
  }

  /// Count response messages from a given sender
  pure def responseCountFor(p: PartyID, allMsgs: Set[NetMsg]): int =
    allMsgs.fold(0, (acc, m) => match m {
      | ResponseMessage(rp) => if (rp.sender == p) acc + 1 else acc
      | _ => acc
    })

  /// Create initial participant state
  pure def mkParticipantState(party: PartyID): ParticipantState = {
    id: party,
    phase: PIdle,
    receivedMsg: EMPTY_COORD_MSG,
    response: ACK  // sentinel, not meaningful until Acked/Nacked
  }

  /// Create initial initiator state
  pure def mkInitiatorState(party: PartyID): InitiatorState = {
    id: party,
    phase: Idle,
    coordMsg: EMPTY_COORD_MSG,
    acksReceived: Set(),
    nacksReceived: Set()
  }

  // ============================================================
  // 4. PROTOCOL TRANSITION FUNCTIONS (Pure)
  // ============================================================

  /// Initiator starts coordination: creates coordMsg, broadcasts
  pure def startCoordination(
    ist: InitiatorState,
    msg: CoordMsg
  ): { newState: InitiatorState, msgs: Set[NetMsg] } =
    if (ist.phase != Idle) { newState: ist, msgs: Set() }
    else {
      newState: { ...ist, phase: Broadcasting, coordMsg: msg },
      msgs: Set(CoordMessage({ sender: ist.id, payload: msg }))
    }

  /// Initiator receives ACK from a participant
  pure def receiveACKResponse(
    ist: InitiatorState,
    from: PartyID,
    allParticipants: Set[PartyID]
  ): { newState: InitiatorState } =
    if (ist.phase != Broadcasting) { newState: ist }
    else if (not(allParticipants.contains(from))) { newState: ist }
    else {
      val newAcks = ist.acksReceived.union(Set(from))
      val newPhase = if (newAcks == allParticipants) AllAcked else Broadcasting
      { newState: { ...ist, phase: newPhase, acksReceived: newAcks } }
    }

  /// Initiator receives NACK from a participant: immediate abort
  pure def receiveNACKResponse(
    ist: InitiatorState,
    from: PartyID,
    allParticipants: Set[PartyID]
  ): { newState: InitiatorState } =
    if (ist.phase != Broadcasting) { newState: ist }
    else if (not(allParticipants.contains(from))) { newState: ist }
    else {
      newState: {
        ...ist,
        phase: Aborted,
        nacksReceived: ist.nacksReceived.union(Set(from))
      }
    }

  /// Participant receives coord message
  pure def receiveCoordMsg(
    pst: ParticipantState,
    msg: CoordMsg
  ): ParticipantState =
    if (pst.phase != PIdle) pst
    else { ...pst, phase: Received, receivedMsg: msg }

  /// Participant validates auth, nonce, timestamp, key constraints.
  /// If validation fails, transitions directly to Nacked and emits NACK.
  /// If validation passes, transitions to Validated (ACK sent separately).
  pure def validateAndRespond(
    pst: ParticipantState,
    hasPolicy: bool,
    keyExists: bool,
    nonces: Set[str],
    now: int,
    window: int
  ): { newState: ParticipantState, msgs: Set[NetMsg], valid: bool } =
    if (pst.phase != Received) { newState: pst, msgs: Set(), valid: false }
    else {
      val passes = validationPasses(
        pst.receivedMsg, hasPolicy, keyExists, nonces, now, window
      )
      if (passes) {
        newState: { ...pst, phase: Validated },
        msgs: Set(),
        valid: true
      } else {
        newState: { ...pst, phase: Nacked, response: NACK },
        msgs: Set(ResponseMessage({ sender: pst.id, response: NACK })),
        valid: false
      }
    }

  /// Participant sends ACK after successful validation.
  /// In the Go code, the session network handler is registered between
  /// validation and ACK, ensuring the initiator cannot race ahead.
  pure def sendACK(
    pst: ParticipantState
  ): { newState: ParticipantState, msgs: Set[NetMsg] } =
    if (pst.phase != Validated) { newState: pst, msgs: Set() }
    else {
      newState: { ...pst, phase: Acked, response: ACK },
      msgs: Set(ResponseMessage({ sender: pst.id, response: ACK }))
    }

  // ============================================================
  // 5. STATE VARIABLES
  // ============================================================

  var initiator: InitiatorState
  var participants: PartyID -> ParticipantState
  var network: Set[NetMsg]
  var keyStore: Set[str]       // existing key IDs
  var seenNonces: Set[str]     // nonces already used (replay prevention)

  // ============================================================
  // 6. ACTIONS
  // ============================================================

  action unchanged_all = all {
    initiator' = initiator,
    participants' = participants,
    network' = network,
    keyStore' = keyStore,
    seenNonces' = seenNonces
  }

  /// Initialize: empty state, no keys, no nonces
  action init = all {
    initiator' = mkInitiatorState(P1),
    participants' = PARTICIPANTS.mapBy(p => mkParticipantState(p)),
    network' = Set(),
    keyStore' = Set(),
    seenNonces' = Set()
  }

  /// Initiator starts keygen coordination
  action startKeygenCoord(auth: AuthInfo): bool = {
    val msg: CoordMsg = {
      opType: Keygen,
      groupID: GROUP_ID,
      keyID: KEY_ID,
      auth: auth,
      signNonce: ""
    }
    val result = startCoordination(initiator, msg)
    if (result.msgs.size() > 0) all {
      initiator' = result.newState,
      network' = network.union(result.msgs),
      participants' = participants,
      keyStore' = keyStore,
      seenNonces' = seenNonces
    } else unchanged_all
  }

  /// Initiator starts sign coordination
  action startSignCoord(auth: AuthInfo): bool = {
    val msg: CoordMsg = {
      opType: Sign,
      groupID: GROUP_ID,
      keyID: KEY_ID,
      auth: auth,
      signNonce: SIGN_NONCE
    }
    val result = startCoordination(initiator, msg)
    if (result.msgs.size() > 0) all {
      initiator' = result.newState,
      network' = network.union(result.msgs),
      participants' = participants,
      keyStore' = keyStore,
      seenNonces' = seenNonces
    } else unchanged_all
  }

  /// Deliver coord message to a participant
  action deliverCoord(p: PartyID): bool = {
    val pst = participants.get(p)
    val coordMsgs = network.filter(m => match m {
      | CoordMessage(_) => true
      | _ => false
    })
    if (coordMsgs.size() == 0 or pst.phase != PIdle) unchanged_all
    else {
      nondet msg = coordMsgs.oneOf()
      match msg {
        | CoordMessage(cp) => {
          val newPst = receiveCoordMsg(pst, cp.payload)
          all {
            participants' = participants.set(p, newPst),
            initiator' = initiator,
            network' = network,
            keyStore' = keyStore,
            seenNonces' = seenNonces
          }
        }
        | _ => unchanged_all
      }
    }
  }

  /// Participant validates and transitions to Validated or Nacked
  action validateParticipant(p: PartyID): bool = {
    val pst = participants.get(p)
    val keyExists = keyStore.contains(pst.receivedMsg.keyID)
    val result = validateAndRespond(
      pst, HAS_AUTH_POLICY, keyExists, seenNonces, NOW, TIMESTAMP_WINDOW
    )
    if (pst.phase != Received) unchanged_all
    else if (result.valid) {
      all {
        participants' = participants.set(p, result.newState),
        network' = network.union(result.msgs),
        initiator' = initiator,
        keyStore' = keyStore,
        seenNonces' = seenNonces
      }
    } else {
      // Validation failed, NACK emitted
      all {
        participants' = participants.set(p, result.newState),
        network' = network.union(result.msgs),
        initiator' = initiator,
        keyStore' = keyStore,
        seenNonces' = seenNonces
      }
    }
  }

  /// Participant sends ACK (after validation passed)
  action ackParticipant(p: PartyID): bool = {
    val pst = participants.get(p)
    val result = sendACK(pst)
    if (result.msgs.size() > 0) all {
      participants' = participants.set(p, result.newState),
      network' = network.union(result.msgs),
      initiator' = initiator,
      keyStore' = keyStore,
      seenNonces' = seenNonces
    } else unchanged_all
  }

  /// Initiator collects a response from a participant
  action collectResponse(from: PartyID): bool = {
    val responseMsgs = network.filter(m => match m {
      | ResponseMessage(rp) => rp.sender == from
      | _ => false
    })
    if (responseMsgs.size() == 0) unchanged_all
    else {
      nondet msg = responseMsgs.oneOf()
      match msg {
        | ResponseMessage(rp) => match rp.response {
          | ACK => {
            val result = receiveACKResponse(initiator, rp.sender, PARTICIPANTS)
            all {
              initiator' = result.newState,
              participants' = participants,
              network' = network,
              keyStore' = keyStore,
              seenNonces' = seenNonces
            }
          }
          | NACK => {
            val result = receiveNACKResponse(initiator, rp.sender, PARTICIPANTS)
            all {
              initiator' = result.newState,
              participants' = participants,
              network' = network,
              keyStore' = keyStore,
              seenNonces' = seenNonces
            }
          }
        }
        | _ => unchanged_all
      }
    }
  }

  /// Nondeterministic step
  action step = any {
    val validAuth: AuthInfo = { present: true, valid: true, nonce: "n1", timestamp: NOW }
    startKeygenCoord(validAuth),

    val validAuth: AuthInfo = { present: true, valid: true, nonce: "n2", timestamp: NOW }
    startSignCoord(validAuth),

    nondet p = PARTICIPANTS.oneOf()
    deliverCoord(p),

    nondet p = PARTICIPANTS.oneOf()
    validateParticipant(p),

    nondet p = PARTICIPANTS.oneOf()
    ackParticipant(p),

    nondet from = PARTICIPANTS.oneOf()
    collectResponse(from)
  }

  // ============================================================
  // 7. INVARIANTS
  // ============================================================

  /// Safety: initiator reaches AllAcked only if all participants Acked
  val noProtocolWithoutAllACKs =
    (initiator.phase == AllAcked) implies
      PARTICIPANTS.forall(p => participants.get(p).phase == Acked)

  /// Safety: if any participant NACKed, initiator never reaches AllAcked
  val nackMeansAbort =
    PARTICIPANTS.exists(p => participants.get(p).phase == Nacked) implies
      initiator.phase != AllAcked

  /// Safety: responses only from valid participants
  val responseOnlyFromParticipants =
    network.forall(m => match m {
      | ResponseMessage(rp) => PARTICIPANTS.contains(rp.sender)
      | _ => true
    })

  /// Safety: each participant responds at most once
  val atMostOneResponsePerParticipant =
    PARTICIPANTS.forall(p => responseCountFor(p, network) <= 1)

  /// Safety: keygen participant cannot ACK if key already exists
  val keyExistsBlocksKeygen =
    PARTICIPANTS.forall(p => {
      val pst = participants.get(p)
      (pst.phase == Acked and pst.receivedMsg.opType == Keygen)
        implies not(keyStore.contains(pst.receivedMsg.keyID))
    })

  /// Safety: no participant ACKs without auth when policy requires it
  val authRequiredWhenPolicy =
    PARTICIPANTS.forall(p => {
      val pst = participants.get(p)
      (HAS_AUTH_POLICY and pst.phase == Acked)
        implies pst.receivedMsg.auth.present
    })

  /// Combined safety invariant
  val safety = and {
    noProtocolWithoutAllACKs,
    nackMeansAbort,
    responseOnlyFromParticipants,
    atMostOneResponsePerParticipant,
    keyExistsBlocksKeygen,
    authRequiredWhenPolicy
  }

  // ============================================================
  // 8. WITNESSES
  // ============================================================

  /// Witness: AllAcked is reachable (should be violated)
  val protocolNeverStarts =
    initiator.phase != AllAcked

  /// Witness: Aborted is reachable (should be violated)
  val neverAborted =
    initiator.phase != Aborted
}
