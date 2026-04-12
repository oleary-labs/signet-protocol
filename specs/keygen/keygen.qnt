// Keygen Protocol
// Based on: tss/keygen.go + docs/DESIGN-RESHARE.md (DKG context)
//
// Models the 3-round DKG (Distributed Key Generation) protocol on secp256k1.
// All parties are symmetric (no old/new role split). Uses Feldman VSS via
// bytemare/dkg, driven by tss.Run().
//
// Abstraction choices:
//   - DKG round data modeled as int (abstract algebraic values)
//   - Key shares, group key, public key shares modeled as int
//   - DKG Finalize() abstracted to constant lookup tables
//   - Network is reliable (messages eventually arrive); no Byzantine behavior
//   - PartyID modeled as str
//   - Self R1 broadcast stored locally in Finalize (no self-message on network)
//   - Self pub share pre-loaded in R2->R3 transition (no self-message on network)
//   - Chain key combination: integer sum (real: SHA256 over sorted contributions)
//   - RID: chainKey + 1 (real: SHA256(combinedChainKey))
module keygen {

  // ============================================================
  // 1. TYPES
  // ============================================================

  type PartyID = str

  type Phase =
    | Idle
    | Round1
    | Round2
    | Round3
    | Done

  /// Round 1 broadcast: DKG R1 data + chain key contribution
  type R1Msg = {
    sender: PartyID,
    r1Data: int,       // abstract DKG Round1Data
    chainKey: int      // random chain key contribution
  }

  /// Round 2 unicast: DKG R2 data (polynomial evaluation for receiver)
  type R2Msg = {
    sender: PartyID,
    receiver: PartyID,
    r2Data: int        // abstract DKG Round2Data
  }

  /// Round 3 broadcast: public key share
  type PubShareMsg = {
    sender: PartyID,
    publicKeyShare: int  // abstract compressed point
  }

  /// Messages on the network
  type Message =
    | R1Message(R1Msg)
    | R2Message(R2Msg)
    | PubShareMessage(PubShareMsg)

  /// Per-party local state
  type PartyState = {
    id: PartyID,
    phase: Phase,
    // Round 1 state
    chainKeyContrib: int,              // own chain key contribution (0 until R1)
    r1Data: int,                       // own DKG R1 data (0 until R1)
    receivedR1: PartyID -> R1Msg,      // collected R1 broadcasts
    // Round 2 state
    receivedR2: PartyID -> int,        // collected R2 unicast data (sender -> r2Data)
    // Round 2 output (from abstract DKG finalize)
    keyShare: int,                     // secret key share (0 until R2 complete)
    groupKey: int,                     // group verification key (0 until R2 complete)
    pubKeyShare: int,                  // own public key share (0 until R2 complete)
    // Round 3 state
    receivedPubShares: PartyID -> int, // collected pub shares
    // Final output (tss.Config fields)
    chainKey: int,                     // combined chain key (0 until done)
    rid: int,                          // round ID (0 until done)
    generation: int,                   // always 0 for keygen
    configBuilt: bool                  // true when Config assembled
  }

  // ============================================================
  // 2. CONSTANTS AND CONFIGURATION
  // ============================================================

  pure val P1: PartyID = "p1"
  pure val P2: PartyID = "p2"
  pure val P3: PartyID = "p3"

  // 3 parties, threshold 2
  pure val PARTIES: Set[PartyID] = Set(P1, P2, P3)
  pure val THRESHOLD = 2

  // Abstract DKG Round 1 data per party
  pure val R1_DATA: PartyID -> int = Map(P1 -> 11, P2 -> 22, P3 -> 33)

  // Abstract DKG Round 2 data: (sender, receiver) -> evaluation
  // No self-entries: bytemare/dkg Continue() produces data only for peers
  pure val R2_DATA: (PartyID, PartyID) -> int = Map(
    (P1, P2) -> 100, (P1, P3) -> 101,
    (P2, P1) -> 200, (P2, P3) -> 201,
    (P3, P1) -> 300, (P3, P2) -> 301
  )

  // Chain key contributions (random 32 bytes in real protocol)
  pure val CHAIN_KEYS: PartyID -> int = Map(P1 -> 1001, P2 -> 1002, P3 -> 1003)

  // Abstract group key (all parties derive the same key from DKG)
  pure val GROUP_KEY = 42

  // Abstract key shares (unique per party, non-zero)
  pure val KEY_SHARES: PartyID -> int = Map(P1 -> 500, P2 -> 600, P3 -> 700)

  // Abstract public key shares (unique per party, non-zero)
  pure val PUB_KEY_SHARES: PartyID -> int = Map(P1 -> 501, P2 -> 601, P3 -> 701)

  // ============================================================
  // 3. HELPER PURE FUNCTIONS
  // ============================================================

  /// Check if party has received all N R1 broadcasts
  pure def hasAllR1(ps: PartyState, allP: Set[PartyID]): bool =
    allP.forall(p => ps.receivedR1.keys().contains(p))

  /// Check if party has received all N-1 R2 unicasts (from all peers except self)
  pure def hasAllR2(ps: PartyState, allP: Set[PartyID]): bool =
    allP.filter(p => p != ps.id).forall(p => ps.receivedR2.keys().contains(p))

  /// Check if party has received all N pub shares
  pure def hasAllPubShares(ps: PartyState, allP: Set[PartyID]): bool =
    allP.forall(p => ps.receivedPubShares.keys().contains(p))

  /// Combine chain keys: abstract hash of all contributions
  /// Real: SHA256(ck_1 || ... || ck_N) in sorted party order
  pure def combineChainKeys(r1s: PartyID -> R1Msg, allP: Set[PartyID]): int =
    allP.fold(0, (acc, p) =>
      if (r1s.keys().contains(p)) acc + r1s.get(p).chainKey
      else acc
    )

  /// Count R1 messages from a given sender
  pure def r1CountFor(p: PartyID, allMsgs: Set[Message]): int =
    allMsgs.fold(0, (acc, m) => match m {
      | R1Message(r) => if (r.sender == p) acc + 1 else acc
      | _ => acc
    })

  /// Count pub share messages from a given sender
  pure def pubShareCountFor(p: PartyID, allMsgs: Set[Message]): int =
    allMsgs.fold(0, (acc, m) => match m {
      | PubShareMessage(ps) => if (ps.sender == p) acc + 1 else acc
      | _ => acc
    })

  /// Create initial party state
  pure def mkPartyState(party: PartyID): PartyState = {
    id: party,
    phase: Idle,
    chainKeyContrib: 0,
    r1Data: 0,
    receivedR1: Map(),
    receivedR2: Map(),
    keyShare: 0,
    groupKey: 0,
    pubKeyShare: 0,
    receivedPubShares: Map(),
    chainKey: 0,
    rid: 0,
    generation: 0,
    configBuilt: false
  }

  // ============================================================
  // 4. PROTOCOL TRANSITION FUNCTIONS (Pure)
  // ============================================================

  /// Round 1: Party prepares and broadcasts R1 data + chain key
  /// keygenRound1.Finalize: generates chain key, calls dkg.Start(),
  /// stores own R1 in r1Broadcasts[self], broadcasts to peers
  pure def prepareRound1(
    ps: PartyState
  ): { newState: PartyState, msgs: Set[Message] } =
    if (ps.phase != Idle) {
      newState: ps, msgs: Set()
    } else {
      val r1 = if (R1_DATA.keys().contains(ps.id)) R1_DATA.get(ps.id) else 0
      val ck = if (CHAIN_KEYS.keys().contains(ps.id)) CHAIN_KEYS.get(ps.id) else 0
      val r1Msg: R1Msg = { sender: ps.id, r1Data: r1, chainKey: ck }
      {
        newState: {
          ...ps,
          phase: Round1,
          r1Data: r1,
          chainKeyContrib: ck,
          // Store own R1 locally (keygenRound1.Finalize stores in r1Broadcasts[self])
          receivedR1: ps.receivedR1.put(ps.id, r1Msg)
        },
        msgs: Set(R1Message(r1Msg))
      }
    }

  /// Process a received R1 broadcast
  pure def receiveR1(ps: PartyState, msg: R1Msg): PartyState =
    { ...ps, receivedR1: ps.receivedR1.put(msg.sender, msg) }

  /// Round 1 -> Round 2 transition: party sends R2 unicast to each peer
  /// keygenRound1.Finalize: when all R1 received, calls dkg.Continue(allR1),
  /// sends R2Data to each peer (not self)
  pure def finishRound1(
    ps: PartyState
  ): { success: bool, newState: PartyState, msgs: Set[Message] } =
    if (not(hasAllR1(ps, PARTIES))) {
      success: false, newState: ps, msgs: Set()
    } else {
      val peers = PARTIES.filter(p => p != ps.id)
      val r2Msgs = peers.map(peer => {
        val r2 = if (R2_DATA.keys().contains((ps.id, peer)))
          R2_DATA.get((ps.id, peer))
        else 0
        R2Message({ sender: ps.id, receiver: peer, r2Data: r2 })
      })
      {
        success: true,
        newState: { ...ps, phase: Round2 },
        msgs: r2Msgs
      }
    }

  /// Process a received R2 unicast
  /// keygenRound2.Receive: validates msg.To == self, decodes, stores
  pure def receiveR2(ps: PartyState, msg: R2Msg): PartyState =
    if (msg.receiver == ps.id) {
      { ...ps, receivedR2: ps.receivedR2.put(msg.sender, msg.r2Data) }
    } else {
      ps // not addressed to us
    }

  /// Round 2 -> Round 3 transition: party derives key share, broadcasts pub share
  /// keygenRound2.Finalize: when all N-1 R2 received, calls dkg.Finalize()
  /// to get KeyShare, broadcasts own pub share, transitions to R3
  pure def finishRound2(
    ps: PartyState
  ): { success: bool, newState: PartyState, msgs: Set[Message] } =
    if (not(hasAllR2(ps, PARTIES))) {
      success: false, newState: ps, msgs: Set()
    } else {
      // Abstract DKG finalize: derive key share, group key, pub share
      val ks = if (KEY_SHARES.keys().contains(ps.id)) KEY_SHARES.get(ps.id) else 0
      val gk = GROUP_KEY
      val pks = if (PUB_KEY_SHARES.keys().contains(ps.id)) PUB_KEY_SHARES.get(ps.id) else 0
      val pubMsg: PubShareMsg = { sender: ps.id, publicKeyShare: pks }
      {
        success: true,
        newState: {
          ...ps,
          phase: Round3,
          keyShare: ks,
          groupKey: gk,
          pubKeyShare: pks,
          // Pre-load own pub share (keygenRound2.Finalize stores in pubShares[self])
          receivedPubShares: ps.receivedPubShares.put(ps.id, pks)
        },
        msgs: Set(PubShareMessage(pubMsg))
      }
    }

  /// Process a received pub share broadcast
  pure def receivePubShare(ps: PartyState, msg: PubShareMsg): PartyState =
    { ...ps, receivedPubShares: ps.receivedPubShares.put(msg.sender, msg.publicKeyShare) }

  /// Round 3 -> Done: party collects all pub shares, builds Config
  /// keygenRound3.Finalize: collects pub shares in party order, combines
  /// chain keys via SHA256(sorted), computes RID, builds tss.Config
  pure def finishRound3(
    ps: PartyState
  ): { success: bool, newState: PartyState } =
    if (not(hasAllPubShares(ps, PARTIES))) {
      { success: false, newState: ps }
    } else {
      val ck = combineChainKeys(ps.receivedR1, PARTIES)
      val r = ck + 1  // abstract: RID = SHA256(chainKey)
      {
        success: true,
        newState: {
          ...ps,
          phase: Done,
          chainKey: ck,
          rid: r,
          generation: 0,
          configBuilt: true
        }
      }
    }

  // ============================================================
  // 5. STATE VARIABLES
  // ============================================================

  var parties: PartyID -> PartyState
  var network: Set[Message]

  // ============================================================
  // 6. ACTIONS
  // ============================================================

  action unchanged_all = all {
    parties' = parties,
    network' = network
  }

  /// Initialize: all parties in Idle, empty network
  action init = all {
    parties' = PARTIES.mapBy(p => mkPartyState(p)),
    network' = Set()
  }

  /// A party starts Round 1 (broadcasts R1 data + chain key)
  action startRound1(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Idle) unchanged_all
    else {
      val result = prepareRound1(ps)
      all {
        parties' = parties.set(p, result.newState),
        network' = network.union(result.msgs)
      }
    }
  }

  /// A party receives an R1 broadcast from the network
  action deliverR1(p: PartyID, msg: R1Msg): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round1) unchanged_all
    else {
      val newPs = receiveR1(ps, msg)
      all {
        parties' = parties.set(p, newPs),
        network' = network
      }
    }
  }

  /// A party finishes Round 1 (sends R2 unicasts to peers)
  action completeRound1(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round1) unchanged_all
    else {
      val result = finishRound1(ps)
      if (result.success) all {
        parties' = parties.set(p, result.newState),
        network' = network.union(result.msgs)
      } else unchanged_all
    }
  }

  /// A party receives an R2 unicast from the network
  action deliverR2(p: PartyID, msg: R2Msg): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round2) unchanged_all
    else {
      val newPs = receiveR2(ps, msg)
      all {
        parties' = parties.set(p, newPs),
        network' = network
      }
    }
  }

  /// A party finishes Round 2 (derives key share, broadcasts pub share)
  action completeRound2(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round2) unchanged_all
    else {
      val result = finishRound2(ps)
      if (result.success) all {
        parties' = parties.set(p, result.newState),
        network' = network.union(result.msgs)
      } else unchanged_all
    }
  }

  /// A party receives a pub share broadcast from the network
  action deliverPubShare(p: PartyID, msg: PubShareMsg): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round3) unchanged_all
    else {
      val newPs = receivePubShare(ps, msg)
      all {
        parties' = parties.set(p, newPs),
        network' = network
      }
    }
  }

  /// A party finishes Round 3 (builds Config)
  action completeRound3(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round3) unchanged_all
    else {
      val result = finishRound3(ps)
      if (result.success) all {
        parties' = parties.set(p, result.newState),
        network' = network
      } else unchanged_all
    }
  }

  /// Nondeterministic step: pick a party and an enabled action
  action step = any {
    nondet p = PARTIES.oneOf()
    startRound1(p),

    nondet p = PARTIES.oneOf()
    nondet msg = network.filter(m => match m {
      | R1Message(_) => true
      | _ => false
    }).oneOf()
    match msg {
      | R1Message(r1) => deliverR1(p, r1)
      | _ => unchanged_all
    },

    nondet p = PARTIES.oneOf()
    completeRound1(p),

    nondet p = PARTIES.oneOf()
    nondet msg = network.filter(m => match m {
      | R2Message(_) => true
      | _ => false
    }).oneOf()
    match msg {
      | R2Message(r2) => deliverR2(p, r2)
      | _ => unchanged_all
    },

    nondet p = PARTIES.oneOf()
    completeRound2(p),

    nondet p = PARTIES.oneOf()
    nondet msg = network.filter(m => match m {
      | PubShareMessage(_) => true
      | _ => false
    }).oneOf()
    match msg {
      | PubShareMessage(ps) => deliverPubShare(p, ps)
      | _ => unchanged_all
    },

    nondet p = PARTIES.oneOf()
    completeRound3(p)
  }

  // ============================================================
  // 7. INVARIANTS
  // ============================================================

  /// Safety: all done parties agree on the group key
  val groupKeyConsistency =
    PARTIES.forall(p =>
      PARTIES.forall(q => {
        val ps = parties.get(p)
        val qs = parties.get(q)
        (ps.phase == Done and qs.phase == Done) implies
          ps.groupKey == qs.groupKey
      })
    )

  /// Safety: all done parties have generation == 0
  val generationZero =
    PARTIES.forall(p => {
      val ps = parties.get(p)
      ps.phase == Done implies ps.generation == 0
    })

  /// Safety: all done parties compute the same chain key
  val chainKeyConsistency =
    PARTIES.forall(p =>
      PARTIES.forall(q => {
        val ps = parties.get(p)
        val qs = parties.get(q)
        (ps.phase == Done and qs.phase == Done) implies
          ps.chainKey == qs.chainKey
      })
    )

  /// Safety: all done parties compute the same RID
  val ridConsistency =
    PARTIES.forall(p =>
      PARTIES.forall(q => {
        val ps = parties.get(p)
        val qs = parties.get(q)
        (ps.phase == Done and qs.phase == Done) implies
          ps.rid == qs.rid
      })
    )

  /// Safety: all done parties have non-zero key shares
  val allPartiesHaveShares =
    PARTIES.forall(p => {
      val ps = parties.get(p)
      ps.phase == Done implies ps.keyShare != 0
    })

  /// Safety: all done parties have configBuilt == true
  val allPartiesHaveConfig =
    PARTIES.forall(p => {
      val ps = parties.get(p)
      ps.phase == Done implies ps.configBuilt
    })

  /// Safety: R1 messages only from valid parties
  val r1OnlyFromParties =
    network.forall(m =>
      match m {
        | R1Message(r) => PARTIES.contains(r.sender)
        | _ => true
      }
    )

  /// Safety: R2 messages only addressed to valid parties
  val r2OnlyToParties =
    network.forall(m =>
      match m {
        | R2Message(r) => PARTIES.contains(r.receiver)
        | _ => true
      }
    )

  /// Safety: no party sends R2 to itself
  val r2NeverToSelf =
    network.forall(m =>
      match m {
        | R2Message(r) => r.sender != r.receiver
        | _ => true
      }
    )

  /// Safety: pub share messages only from valid parties
  val pubSharesOnlyFromParties =
    network.forall(m =>
      match m {
        | PubShareMessage(ps) => PARTIES.contains(ps.sender)
        | _ => true
      }
    )

  /// Safety: each party broadcasts R1 at most once
  val atMostOneR1PerParty =
    PARTIES.forall(p => r1CountFor(p, network) <= 1)

  /// Safety: each party broadcasts pub share at most once
  val atMostOnePubSharePerParty =
    PARTIES.forall(p => pubShareCountFor(p, network) <= 1)

  /// Combined safety invariant
  val safety = and {
    groupKeyConsistency,
    generationZero,
    chainKeyConsistency,
    ridConsistency,
    allPartiesHaveShares,
    allPartiesHaveConfig,
    r1OnlyFromParties,
    r2OnlyToParties,
    r2NeverToSelf,
    pubSharesOnlyFromParties,
    atMostOneR1PerParty,
    atMostOnePubSharePerParty
  }

  // ============================================================
  // 8. WITNESSES
  // ============================================================

  /// Witness: it is possible for all parties to reach Done
  /// (negate this; if the verifier finds a violation, the protocol can complete)
  val allPartiesNotDone =
    PARTIES.exists(p => parties.get(p).phase != Done)

  /// Witness: at least one party has built a config
  val noPartyHasConfig =
    PARTIES.forall(p => not(parties.get(p).configBuilt))
}
