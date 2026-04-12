// Reshare Protocol
// Based on: tss/reshare.go + docs/DESIGN-RESHARE.md
//
// Models the 3-round cryptographic reshare protocol where old committee members
// redistribute their key shares to a new committee using Lagrange-weighting
// and Feldman VSS, preserving the group public key.
//
// Code reference: tss/reshare.go implements reshareRound1, reshareRound2, reshareRound3
// as the Round interface consumed by tss.Run(). Each round has Receive() for incoming
// messages and Finalize() which drives the protocol forward.
//
// Abstraction choices:
//   - Scalars and group elements modeled as int (abstract algebraic values)
//   - Feldman commitments modeled as lists of int (commitment polynomials)
//   - VSS verification abstracted to a pure function (not full polynomial math)
//   - Network is reliable (messages eventually arrive); no Byzantine behavior
//   - PartyID modeled as str
//   - "Both" parties compute own sub-share locally (reshareRound2.Finalize calls
//     polynomial.Evaluate(myNewID) without a self-message)
//   - Duplicate message rejection modeled via map key overwrite (code uses explicit
//     dup checks in each Receive() method)
//   - RID = abstract(ChainKey) rather than SHA256(SHA256(ck1||...||ckN))
//   - Old-only sentinel Config has only {ID, Generation, GroupKey}
module reshare {

  // ============================================================
  // 1. TYPES
  // ============================================================

  type PartyID = str

  /// Role a party plays in the reshare, determined by membership
  type Role =
    | OldOnly      // in oldParties, not in newParties
    | NewOnly      // in newParties, not in oldParties
    | Both         // in both committees

  /// Protocol phase for each party
  type Phase =
    | Idle
    | Round1       // old parties broadcast commitments
    | Round2       // new parties receive + verify sub-shares
    | Round3       // new parties broadcast pub shares + build config
    | Done

  /// Round 1 broadcast: old party's Feldman commitments + metadata
  type CommitMsg = {
    sender: PartyID,
    commitments: List[int],   // Feldman commitment polynomial coefficients (as group elements)
    chainKey: int,            // random chain key contribution
    generation: int,          // current generation from old config
    groupKey: int             // group verification key (public)
  }

  /// Round 2 unicast: old party sends sub-share to a specific new party
  type EvalMsg = {
    sender: PartyID,
    receiver: PartyID,
    subShare: int             // f_i(x_j) evaluation
  }

  /// Round 3 broadcast: new party publishes its new public key share
  type PubShareMsg = {
    sender: PartyID,
    publicKeyShare: int       // newSecret_j * G (as abstract group element)
  }

  /// Messages on the network
  type Message =
    | CommitMessage(CommitMsg)
    | EvalMessage(EvalMsg)
    | PubShareMessage(PubShareMsg)

  /// Per-party local state
  type PartyState = {
    id: PartyID,
    role: Role,
    phase: Phase,
    // Old party state (Round 1)
    oldShare: int,                         // a_i (old secret share, 0 if new-only)
    lagrangeCoeff: int,                    // lambda_i (0 if new-only)
    weightedShare: int,                    // lambda_i * a_i (0 if new-only)
    polynomial: List[int],                 // VSS polynomial coefficients (empty if new-only)
    commitments: List[int],               // Feldman commitments (empty if new-only)
    chainKeyContrib: int,                  // random chain key contribution (0 if new-only)
    // Received data
    receivedCommits: PartyID -> CommitMsg, // collected Round 1 broadcasts
    receivedEvals: PartyID -> int,         // collected Round 2 sub-shares (sender -> value)
    receivedPubShares: PartyID -> int,     // collected Round 3 pub shares
    // New party output (Round 2-3)
    newSecret: int,                        // combined new secret share (0 until computed)
    newPubKeyShare: int,                   // newSecret * G (0 until computed)
    // Intermediate state (code: reshareRound2.Finalize builds combined VSS commitment)
    combinedVSSCommitment: List[int],      // element-wise sum of old commitments (empty until Round 2)
    // Final output (matches tss.Config fields)
    newGeneration: int,                    // generation + 1 (0 until done)
    newChainKey: int,                      // SHA256(ck_1 || ... || ck_N) (0 until done)
    newRID: int,                           // SHA256(chainKey) (0 until done)
    configBuilt: bool                      // true when final Config is assembled
  }

  /// Global protocol state
  type State = {
    parties: PartyID -> PartyState,
    network: Set[Message],
    groupKey: int,               // the group public key (must be preserved)
    oldGeneration: int,          // generation before reshare
    oldParties: Set[PartyID],
    newParties: Set[PartyID],
    allParties: Set[PartyID],
    oldThreshold: int,
    newThreshold: int
  }

  // ============================================================
  // 2. CONSTANTS AND CONFIGURATION
  // ============================================================

  // Abstract party identifiers
  pure val P1: PartyID = "p1"
  pure val P2: PartyID = "p2"
  pure val P3: PartyID = "p3"
  pure val P4: PartyID = "p4"

  // Old committee: {P1, P2, P3}, threshold 2
  // New committee: {P2, P3, P4}, threshold 2
  // P1 = old-only, P2/P3 = both, P4 = new-only
  pure val OLD_PARTIES: Set[PartyID] = Set(P1, P2, P3)
  pure val NEW_PARTIES: Set[PartyID] = Set(P2, P3, P4)
  pure val ALL_PARTIES: Set[PartyID] = OLD_PARTIES.union(NEW_PARTIES)
  pure val OLD_THRESHOLD = 2
  pure val NEW_THRESHOLD = 2

  // Abstract cryptographic values
  pure val GROUP_KEY = 42         // abstract group public key
  pure val GENERATION = 0         // starting generation

  // Abstract old shares (sum with Lagrange coefficients must reconstruct secret)
  // In real protocol: sum_i(lambda_i * a_i) = group_secret
  pure val OLD_SHARES: PartyID -> int = Map(P1 -> 10, P2 -> 20, P3 -> 30)
  pure val LAGRANGE_COEFFS: PartyID -> int = Map(P1 -> 3, P2 -> 5, P3 -> 7)

  // Abstract polynomial evaluations: polynomial_i(j) for each old party i, new party j
  // In reality these come from random polynomials with weighted shares as constant terms
  pure val POLY_EVALS: (PartyID, PartyID) -> int = Map(
    (P1, P2) -> 100, (P1, P3) -> 101, (P1, P4) -> 102,
    (P2, P2) -> 200, (P2, P3) -> 201, (P2, P4) -> 202,
    (P3, P2) -> 300, (P3, P3) -> 301, (P3, P4) -> 302
  )

  // Abstract commitments per old party (list of group elements)
  pure val COMMIT_VALS: PartyID -> List[int] = Map(
    P1 -> [30, 11],   // constant term = lambda_1 * a_1 * G
    P2 -> [100, 22],
    P3 -> [210, 33]
  )

  // Chain key contributions
  pure val CHAIN_KEYS: PartyID -> int = Map(P1 -> 1001, P2 -> 1002, P3 -> 1003)

  // ============================================================
  // 3. HELPER PURE FUNCTIONS
  // ============================================================

  /// Determine a party's role based on committee membership
  pure def determineRole(party: PartyID, oldP: Set[PartyID], newP: Set[PartyID]): Role =
    if (oldP.contains(party) and not(newP.contains(party))) OldOnly
    else if (not(oldP.contains(party)) and newP.contains(party)) NewOnly
    else Both

  /// Check if a party is an old party (can send commitments)
  pure def isOldParty(role: Role): bool =
    match role {
      | OldOnly => true
      | Both => true
      | NewOnly => false
    }

  /// Check if a party is a new party (receives sub-shares, builds config)
  pure def isNewParty(role: Role): bool =
    match role {
      | NewOnly => true
      | Both => true
      | OldOnly => false
    }

  /// Check if party has received all expected Round 1 commits
  pure def hasAllCommits(ps: PartyState, oldP: Set[PartyID]): bool =
    oldP.forall(p => ps.receivedCommits.keys().contains(p))

  /// Check if new party has received all sub-share evals from old parties
  pure def hasAllEvals(ps: PartyState, oldP: Set[PartyID]): bool =
    oldP.forall(p => ps.receivedEvals.keys().contains(p))

  /// Check if new party has received all Round 3 pub shares
  pure def hasAllPubShares(ps: PartyState, newP: Set[PartyID]): bool =
    newP.forall(p => ps.receivedPubShares.keys().contains(p))

  /// Verify group key preservation: sum of commitment constant terms == groupKey
  /// In real protocol: sum_i commits[i][0] == groupPubKey
  pure def verifyGroupKeyPreservation(commits: PartyID -> CommitMsg, oldP: Set[PartyID], gk: int): bool =
    // Abstract: all commits report the same group key
    oldP.forall(p =>
      if (commits.keys().contains(p)) commits.get(p).groupKey == gk
      else true
    )

  /// Abstract Feldman verification: verify sub-share against commitments
  /// In real protocol: secret_sharing.Verify(secp256k1, newID, subShare*G, commits)
  pure def verifyFeldman(subShare: int, _senderCommitments: List[int], _receiverID: PartyID): bool =
    // Abstract: non-zero sub-share passes verification
    subShare != 0

  /// Combine sub-shares: newSecret_j = sum_i f_i(x_j)
  pure def combineSubShares(evals: PartyID -> int, oldP: Set[PartyID]): int =
    oldP.fold(0, (acc, p) =>
      if (evals.keys().contains(p)) acc + evals.get(p)
      else acc
    )

  /// Compute combined chain key: abstract hash of all contributions
  pure def combineChainKeys(commits: PartyID -> CommitMsg, oldP: Set[PartyID]): int =
    oldP.fold(0, (acc, p) =>
      if (commits.keys().contains(p)) acc + commits.get(p).chainKey
      else acc
    )

  /// Create initial party state
  pure def mkPartyState(
    party: PartyID,
    role: Role,
    oldP: Set[PartyID],
    newP: Set[PartyID]
  ): PartyState = {
    id: party,
    role: role,
    phase: Idle,
    oldShare: if (isOldParty(role) and OLD_SHARES.keys().contains(party)) OLD_SHARES.get(party) else 0,
    lagrangeCoeff: if (isOldParty(role) and LAGRANGE_COEFFS.keys().contains(party)) LAGRANGE_COEFFS.get(party) else 0,
    weightedShare: 0,
    polynomial: [],
    commitments: [],
    chainKeyContrib: 0,
    receivedCommits: Map(),
    receivedEvals: Map(),
    receivedPubShares: Map(),
    newSecret: 0,
    newPubKeyShare: 0,
    combinedVSSCommitment: [],
    newGeneration: 0,
    newChainKey: 0,
    newRID: 0,
    configBuilt: false
  }

  // ============================================================
  // 4. PROTOCOL TRANSITION FUNCTIONS (Pure)
  // ============================================================

  /// Round 1: Old party prepares and broadcasts commitments
  /// Returns updated party state and the set of messages to send
  pure def prepareRound1(
    ps: PartyState
  ): { newState: PartyState, msgs: Set[Message] } =
    if (not(isOldParty(ps.role)) or ps.phase != Idle) {
      // New-only parties skip to receiving
      newState: { ...ps, phase: Round1 },
      msgs: Set()
    } else {
      val weighted = ps.lagrangeCoeff * ps.oldShare
      val commits = if (COMMIT_VALS.keys().contains(ps.id)) COMMIT_VALS.get(ps.id) else []
      val ck = if (CHAIN_KEYS.keys().contains(ps.id)) CHAIN_KEYS.get(ps.id) else 0
      val commitMsg: CommitMsg = {
        sender: ps.id,
        commitments: commits,
        chainKey: ck,
        generation: GENERATION,
        groupKey: GROUP_KEY
      }
      {
        newState: {
          ...ps,
          phase: Round1,
          weightedShare: weighted,
          commitments: commits,
          chainKeyContrib: ck
        },
        msgs: Set(CommitMessage(commitMsg))
      }
    }

  /// Process a received commit message
  pure def receiveCommit(ps: PartyState, msg: CommitMsg): PartyState =
    { ...ps, receivedCommits: ps.receivedCommits.put(msg.sender, msg) }

  /// Round 1 -> Round 2 transition: old parties send sub-share evals to new parties
  /// Called when all commits have been received and verified
  pure def finishRound1(
    ps: PartyState,
    oldP: Set[PartyID],
    newP: Set[PartyID],
    gk: int
  ): { success: bool, newState: PartyState, msgs: Set[Message] } =
    if (not(hasAllCommits(ps, oldP))) {
      success: false, newState: ps, msgs: Set()
    } else if (not(verifyGroupKeyPreservation(ps.receivedCommits, oldP, gk))) {
      // Group key invariant violated - abort
      success: false, newState: ps, msgs: Set()
    } else if (isOldParty(ps.role)) {
      // Old party: send sub-share evals to each new party.
      // Skips self — "Both" parties compute own sub-share locally in
      // reshareRound2.Finalize via polynomial.Evaluate(myNewID).
      val otherNewParties = newP.filter(np => np != ps.id)
      val evalMsgs = otherNewParties.map(newPartyID => {
        val eval = if (POLY_EVALS.keys().contains((ps.id, newPartyID)))
          POLY_EVALS.get((ps.id, newPartyID))
        else 0
        EvalMessage({ sender: ps.id, receiver: newPartyID, subShare: eval })
      })
      {
        success: true,
        newState: { ...ps, phase: Round2 },
        msgs: evalMsgs
      }
    } else {
      // New-only party: just advance phase
      { success: true, newState: { ...ps, phase: Round2 }, msgs: Set() }
    }

  /// Process a received eval message (Round 2 unicast)
  pure def receiveEval(ps: PartyState, msg: EvalMsg): PartyState =
    if (msg.receiver == ps.id) {
      // Verify Feldman commitment for this sub-share
      val senderCommits = if (ps.receivedCommits.keys().contains(msg.sender))
        ps.receivedCommits.get(msg.sender).commitments
      else []
      if (verifyFeldman(msg.subShare, senderCommits, ps.id)) {
        { ...ps, receivedEvals: ps.receivedEvals.put(msg.sender, msg.subShare) }
      } else {
        ps // Feldman verification failed; ignore (in real protocol: abort)
      }
    } else {
      ps // Not addressed to us
    }

  /// Round 2 -> Round 3 transition: new parties combine sub-shares, broadcast pub share
  /// Old-only parties exit here
  pure def finishRound2(
    ps: PartyState,
    oldP: Set[PartyID]
  ): { success: bool, newState: PartyState, msgs: Set[Message] } =
    match ps.role {
      | OldOnly =>
        // Old-only parties are done after Round 2
        // They produce a sentinel config (no key share, generation incremented)
        {
          success: true,
          newState: {
            ...ps,
            phase: Done,
            newGeneration: GENERATION + 1,
            configBuilt: true
          },
          msgs: Set()
        }
      | _ =>
        // New party (Both or NewOnly).
        // If also old party, compute own sub-share locally via
        // polynomial.Evaluate(myNewID) and insert into subShares map
        // before checking completeness.
        val evalsWithSelf = if (isOldParty(ps.role)) {
          // "Both" party: add own sub-share computed locally (no network message)
          val selfEval = if (POLY_EVALS.keys().contains((ps.id, ps.id)))
            POLY_EVALS.get((ps.id, ps.id))
          else 0
          ps.receivedEvals.put(ps.id, selfEval)
        } else {
          ps.receivedEvals
        }
        // Need sub-shares from all old parties
        if (not(oldP.forall(p => evalsWithSelf.keys().contains(p)))) {
          { success: false, newState: ps, msgs: Set() }
        } else {
          // Combine sub-shares: newSecret = sum_i f_i(j)
          val combined = oldP.fold(0, (acc, p) =>
            if (evalsWithSelf.keys().contains(p)) acc + evalsWithSelf.get(p)
            else acc
          )
          // Abstract: public key share = newSecret * G
          val pubShare = combined
          // Combined VSS commitment: element-wise sum of all old party commitments
          val pubMsg: PubShareMsg = { sender: ps.id, publicKeyShare: pubShare }
          {
            success: true,
            newState: {
              ...ps,
              phase: Round3,
              newSecret: combined,
              newPubKeyShare: pubShare,
              receivedEvals: evalsWithSelf,
              combinedVSSCommitment: [combined]  // abstract: just the sum
            },
            msgs: Set(PubShareMessage(pubMsg))
          }
        }
    }

  /// Process a received pub share message (Round 3 broadcast)
  pure def receivePubShare(ps: PartyState, msg: PubShareMsg): PartyState =
    { ...ps, receivedPubShares: ps.receivedPubShares.put(msg.sender, msg.publicKeyShare) }

  /// Round 3 -> Done: new parties collect all pub shares and build Config.
  /// reshareRound3.Finalize collects pub shares in party order, combines chain
  /// keys via SHA256(sorted), computes RID = SHA256(chainKey), builds final
  /// tss.Config.
  pure def finishRound3(
    ps: PartyState,
    newP: Set[PartyID],
    oldP: Set[PartyID]
  ): { success: bool, newState: PartyState } =
    // Own pub share is pre-seeded when entering Round 3. In the spec, we model
    // this by including own pub share via receivePubShare before calling
    // finishRound3. Check all new parties present.
    if (not(hasAllPubShares(ps, newP))) {
      { success: false, newState: ps }
    } else {
      // Chain key: SHA256(ck_1 || ... || ck_N) from old parties in sorted order
      val chainKey = combineChainKeys(ps.receivedCommits, oldP)
      // RID = SHA256(combinedChainKey)
      val rid = chainKey + 1  // abstract: distinct derived value
      {
        success: true,
        newState: {
          ...ps,
          phase: Done,
          newGeneration: GENERATION + 1,
          newChainKey: chainKey,
          newRID: rid,
          configBuilt: true
        }
      }
    }

  // ============================================================
  // 5. STATE VARIABLES
  // ============================================================

  var parties: PartyID -> PartyState
  var network: Set[Message]

  val currentState: State = {
    parties: parties,
    network: network,
    groupKey: GROUP_KEY,
    oldGeneration: GENERATION,
    oldParties: OLD_PARTIES,
    newParties: NEW_PARTIES,
    allParties: ALL_PARTIES,
    oldThreshold: OLD_THRESHOLD,
    newThreshold: NEW_THRESHOLD
  }

  // ============================================================
  // 6. ACTIONS
  // ============================================================

  action unchanged_all = all {
    parties' = parties,
    network' = network
  }

  /// Initialize: all parties in Idle, empty network
  action init = all {
    parties' = ALL_PARTIES.mapBy(p =>
      mkPartyState(p, determineRole(p, OLD_PARTIES, NEW_PARTIES), OLD_PARTIES, NEW_PARTIES)
    ),
    network' = Set()
  }

  /// A party starts Round 1 (broadcasts commitments if old party)
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

  /// A party receives a commit message from the network
  action deliverCommit(p: PartyID, msg: CommitMsg): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round1) unchanged_all
    else {
      val newPs = receiveCommit(ps, msg)
      all {
        parties' = parties.set(p, newPs),
        network' = network
      }
    }
  }

  /// A party finishes Round 1 (verifies group key, old parties send evals)
  action completeRound1(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round1) unchanged_all
    else {
      val result = finishRound1(ps, OLD_PARTIES, NEW_PARTIES, GROUP_KEY)
      if (result.success) all {
        parties' = parties.set(p, result.newState),
        network' = network.union(result.msgs)
      } else unchanged_all
    }
  }

  /// A party receives an eval message from the network
  action deliverEval(p: PartyID, msg: EvalMsg): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round2) unchanged_all
    else {
      val newPs = receiveEval(ps, msg)
      all {
        parties' = parties.set(p, newPs),
        network' = network
      }
    }
  }

  /// A party finishes Round 2 (new parties combine shares; old-only parties exit)
  action completeRound2(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round2) unchanged_all
    else {
      val result = finishRound2(ps, OLD_PARTIES)
      if (result.success) all {
        parties' = parties.set(p, result.newState),
        network' = network.union(result.msgs)
      } else unchanged_all
    }
  }

  /// A party receives a pub share message from the network
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

  /// A party finishes Round 3 (builds new Config)
  action completeRound3(p: PartyID): bool = {
    val ps = parties.get(p)
    if (ps.phase != Round3) unchanged_all
    else {
      val result = finishRound3(ps, NEW_PARTIES, OLD_PARTIES)
      if (result.success) all {
        parties' = parties.set(p, result.newState),
        network' = network
      } else unchanged_all
    }
  }

  /// Nondeterministic step: pick a party and an enabled action
  action step = any {
    nondet p = ALL_PARTIES.oneOf()
    startRound1(p),

    nondet p = ALL_PARTIES.oneOf()
    nondet msg = network.filter(m => match m {
      | CommitMessage(_) => true
      | _ => false
    }).oneOf()
    match msg {
      | CommitMessage(cm) => deliverCommit(p, cm)
      | _ => unchanged_all
    },

    nondet p = ALL_PARTIES.oneOf()
    completeRound1(p),

    nondet p = ALL_PARTIES.oneOf()
    nondet msg = network.filter(m => match m {
      | EvalMessage(_) => true
      | _ => false
    }).oneOf()
    match msg {
      | EvalMessage(em) => deliverEval(p, em)
      | _ => unchanged_all
    },

    nondet p = ALL_PARTIES.oneOf()
    completeRound2(p),

    nondet p = ALL_PARTIES.oneOf()
    nondet msg = network.filter(m => match m {
      | PubShareMessage(_) => true
      | _ => false
    }).oneOf()
    match msg {
      | PubShareMessage(pm) => deliverPubShare(p, pm)
      | _ => unchanged_all
    },

    nondet p = ALL_PARTIES.oneOf()
    completeRound3(p)
  }

  // ============================================================
  // 7. INVARIANTS
  // ============================================================

  /// Safety: Group key is never changed — all commit messages report the same group key
  val groupKeyPreserved =
    network.forall(m =>
      match m {
        | CommitMessage(cm) => cm.groupKey == GROUP_KEY
        | _ => true
      }
    )

  /// Safety: All done parties agree on the new generation
  val generationConsistency =
    ALL_PARTIES.forall(p =>
      ALL_PARTIES.forall(q => {
        val ps = parties.get(p)
        val qs = parties.get(q)
        (ps.phase == Done and qs.phase == Done) implies
          ps.newGeneration == qs.newGeneration
      })
    )

  /// Safety: New generation is exactly oldGeneration + 1
  val generationIncremented =
    ALL_PARTIES.forall(p => {
      val ps = parties.get(p)
      ps.phase == Done implies ps.newGeneration == GENERATION + 1
    })

  /// Safety: Old-only parties produce sentinel config (no new secret)
  val oldOnlySentinel =
    ALL_PARTIES.forall(p => {
      val ps = parties.get(p)
      (ps.phase == Done and ps.role == OldOnly) implies ps.newSecret == 0
    })

  /// Safety: New parties (Both, NewOnly) have a non-zero new secret when done
  val newPartiesHaveShares =
    ALL_PARTIES.forall(p => {
      val ps = parties.get(p)
      (ps.phase == Done and isNewParty(ps.role)) implies ps.newSecret != 0
    })

  /// Safety: Monotonic phase progression (parties never go backward)
  pure def phaseOrd(phase: Phase): int =
    match phase {
      | Idle => 0
      | Round1 => 1
      | Round2 => 2
      | Round3 => 3
      | Done => 4
    }

  /// Safety: Old-only parties skip Round 3 (go directly from Round2 to Done)
  val oldOnlySkipsRound3 =
    ALL_PARTIES.forall(p => {
      val ps = parties.get(p)
      (ps.role == OldOnly) implies ps.phase != Round3
    })

  /// Safety: Only new parties reach Round 3
  val onlyNewPartiesInRound3 =
    ALL_PARTIES.forall(p => {
      val ps = parties.get(p)
      ps.phase == Round3 implies isNewParty(ps.role)
    })

  /// Safety: Eval messages are only addressed to new parties
  val evalsOnlyToNewParties =
    network.forall(m =>
      match m {
        | EvalMessage(em) => NEW_PARTIES.contains(em.receiver)
        | _ => true
      }
    )

  /// Safety: Commit messages only from old parties
  val commitsOnlyFromOldParties =
    network.forall(m =>
      match m {
        | CommitMessage(cm) => OLD_PARTIES.contains(cm.sender)
        | _ => true
      }
    )

  /// Safety: Pub share messages only from new parties
  val pubSharesOnlyFromNewParties =
    network.forall(m =>
      match m {
        | PubShareMessage(pm) => NEW_PARTIES.contains(pm.sender)
        | _ => true
      }
    )

  /// All new parties that finish compute the same chain key
  val chainKeyConsistency =
    NEW_PARTIES.forall(p =>
      NEW_PARTIES.forall(q => {
        val ps = parties.get(p)
        val qs = parties.get(q)
        (ps.phase == Done and qs.phase == Done and
         isNewParty(ps.role) and isNewParty(qs.role))
          implies ps.newChainKey == qs.newChainKey
      })
    )

  /// All new parties that finish compute the same RID
  /// (RID is deterministic from chain keys)
  val ridConsistency =
    NEW_PARTIES.forall(p =>
      NEW_PARTIES.forall(q => {
        val ps = parties.get(p)
        val qs = parties.get(q)
        (ps.phase == Done and qs.phase == Done and
         isNewParty(ps.role) and isNewParty(qs.role))
          implies ps.newRID == qs.newRID
      })
    )

  /// "Both" parties must have their own sub-share in receivedEvals when done
  /// (reshareRound2.Finalize computes local self-evaluation)
  val bothPartiesSelfEval =
    ALL_PARTIES.forall(p => {
      val ps = parties.get(p)
      (ps.role == Both and ps.phase == Done) implies
        ps.receivedEvals.keys().contains(ps.id)
    })

  /// Combined safety invariant
  val safety = and {
    groupKeyPreserved,
    generationConsistency,
    generationIncremented,
    oldOnlySentinel,
    oldOnlySkipsRound3,
    onlyNewPartiesInRound3,
    evalsOnlyToNewParties,
    commitsOnlyFromOldParties,
    pubSharesOnlyFromNewParties,
    chainKeyConsistency,
    ridConsistency,
    bothPartiesSelfEval
  }

  // ============================================================
  // 8. WITNESSES (liveness / reachability)
  // ============================================================

  /// Witness: it is possible for all parties to reach Done
  /// (negate this — if the verifier finds a counterexample, the protocol can complete)
  val allPartiesNotDone =
    ALL_PARTIES.exists(p => parties.get(p).phase != Done)

  /// Witness: at least one new party has built a config with a valid new secret
  val noNewPartyHasConfig =
    NEW_PARTIES.forall(p => not(parties.get(p).configBuilt))

  /// Witness: old-only party has exited (reached Done before new parties)
  val noOldOnlyExited =
    ALL_PARTIES.filter(p =>
      determineRole(p, OLD_PARTIES, NEW_PARTIES) == OldOnly
    ).forall(p => parties.get(p).phase != Done)

}
