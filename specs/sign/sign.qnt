// FROST Threshold Signing Protocol (RFC 9591) -- Quint Specification
//
// Models the 2-round FROST signing protocol at the orchestration level.
// Cryptographic operations are abstracted; the spec verifies message
// delivery patterns, quorum logic, and agreement properties.
//
// Reference implementation: tss/sign.go (Go), kms-frost/src/session.rs (Rust)

module sign {
  // --- Constants ---

  /// All nodes eligible to participate in signing.
  const PARTICIPANTS: Set[str]

  /// Minimum number of signers required to produce a valid signature.
  const THRESHOLD: int

  /// The chosen coalition for this signing session.
  /// Must satisfy: SIGNERS.size() >= THRESHOLD and SIGNERS.subseteq(PARTICIPANTS).
  const SIGNERS: Set[str]

  // --- Types ---

  type Phase = Idle | Committed | SignShareSent | Done

  type Commitment = {
    from: str,
    nonce_commit: int,  // abstract: represents (hiding_commit, binding_commit)
  }

  type SignShare = {
    from: str,
    sig_share: int,  // abstract: represents z_i = d_i + e_i*rho_i + c*sk_i*lambda_i
  }

  type Signature = {
    group_commit: int,  // abstract R = sum of per-signer R_i
    z: int,             // aggregate z = sum of z_i
  }

  type Msg =
    | CommitMsg(Commitment)
    | ShareMsg(SignShare)

  // Result is either a signature or nothing. Quint has no built-in Option,
  // so we use a sum type.
  type Result =
    | Completed(Signature)
    | Pending

  type LocalState = {
    phase: Phase,
    nonce: int,
    result: Result,
  }

  // --- State ---

  /// Per-signer local state.
  var state: str -> LocalState

  /// Global message soup. Monotonically growing; messages are never removed.
  /// Models the SessionNetwork broadcast (unicast to each peer).
  var msgs: Set[Msg]

  // --- Helpers ---

  /// Extract all commitments from the message soup sent by signers other than p.
  pure def commitmentsFor(p: str, allMsgs: Set[Msg], signers: Set[str]): Set[Commitment] =
    allMsgs.fold(Set(), (acc, m) => match m {
      | CommitMsg(c) => if (c.from != p and signers.contains(c.from))
                          acc.union(Set(c))
                        else acc
      | _ => acc
    })

  /// Extract all signature shares from the message soup sent by any signer.
  pure def sharesFrom(allMsgs: Set[Msg], signers: Set[str]): Set[SignShare] =
    allMsgs.fold(Set(), (acc, m) => match m {
      | ShareMsg(s) => if (signers.contains(s.from))
                         acc.union(Set(s))
                       else acc
      | _ => acc
    })

  /// Count commitments for a given sender in the message soup.
  pure def commitCountFor(p: str, allMsgs: Set[Msg]): int =
    allMsgs.fold(0, (acc, m) => match m {
      | CommitMsg(c) => if (c.from == p) acc + 1 else acc
      | _ => acc
    })

  /// Count shares for a given sender in the message soup.
  pure def shareCountFor(p: str, allMsgs: Set[Msg]): int =
    allMsgs.fold(0, (acc, m) => match m {
      | ShareMsg(s) => if (s.from == p) acc + 1 else acc
      | _ => acc
    })

  /// Abstract partial signature computation.
  /// In reality: z_i = d_i + e_i * rho_i + challenge * sk_i * lambda_i
  /// We abstract to just the nonce, ensuring deterministic unique shares.
  pure def computeShare(p: str, nonce: int): int =
    nonce

  /// Abstract group commitment: sum of all nonce commitments.
  pure def computeGroupCommit(commits: Set[Commitment]): int =
    commits.fold(0, (acc, c) => acc + c.nonce_commit)

  /// Abstract signature aggregation: sum of all partial signatures.
  pure def aggregateShares(shares: Set[SignShare]): int =
    shares.fold(0, (acc, s) => acc + s.sig_share)

  /// Check if a result is Completed.
  pure def isCompleted(r: Result): bool = match r {
    | Completed(_) => true
    | Pending => false
  }

  /// Extract signature from result (only call when isCompleted is true).
  pure def getSig(r: Result): Signature = match r {
    | Completed(s) => s
    | Pending => { group_commit: -1, z: -1 }  // should never happen
  }

  // --- Initialization ---

  action init = all {
    state' = SIGNERS.mapBy(_ => {
      phase: Idle,
      nonce: 0,
      result: Pending,
    }),
    msgs' = Set(),
  }

  // --- Actions ---

  /// Round 1: Signer p generates a nonce commitment and broadcasts it.
  /// Models signCommitRound.Finalize() in tss/sign.go.
  action commit(p: str): bool = all {
    SIGNERS.contains(p),
    state.get(p).phase == Idle,
    nondet nonce = 1.to(100).oneOf()
    all {
      state' = state.set(p, {
        ...state.get(p),
        phase: Committed,
        nonce: nonce,
      }),
      msgs' = msgs.union(Set(CommitMsg({
        from: p,
        nonce_commit: nonce,
      }))),
    }
  }

  /// Round 1 -> Round 2 transition: Signer p has received commitments from
  /// ALL other signers. Produces a partial signature share and broadcasts it.
  /// Models the transition from signCommitRound to signAggregateRound.
  action produceShare(p: str): bool = all {
    SIGNERS.contains(p),
    state.get(p).phase == Committed,
    // Must have commitments from all other signers (FROST requires all, not just threshold)
    commitmentsFor(p, msgs, SIGNERS).size() >= SIGNERS.size() - 1,
    state' = state.set(p, {
      ...state.get(p),
      phase: SignShareSent,
    }),
    msgs' = msgs.union(Set(ShareMsg({
      from: p,
      sig_share: computeShare(p, state.get(p).nonce),
    }))),
  }

  /// Round 2 completion: Signer p has received enough shares to aggregate.
  /// Models signAggregateRound.Finalize() producing the final Signature.
  action aggregate(p: str): bool = all {
    SIGNERS.contains(p),
    state.get(p).phase == SignShareSent,
    // Need shares from all signers (in FROST, aggregation uses all coalition shares)
    sharesFrom(msgs, SIGNERS).size() >= SIGNERS.size(),
    state' = state.set(p, {
      ...state.get(p),
      phase: Done,
      result: Completed({
        group_commit: computeGroupCommit(
          msgs.fold(Set(), (acc, m) => match m {
            | CommitMsg(c) => if (SIGNERS.contains(c.from)) acc.union(Set(c)) else acc
            | _ => acc
          })
        ),
        z: aggregateShares(sharesFrom(msgs, SIGNERS)),
      }),
    }),
    msgs' = msgs,
  }

  /// Non-deterministic step: pick a signer, pick an action.
  action step = {
    nondet p = SIGNERS.oneOf()
    any {
      commit(p),
      produceShare(p),
      aggregate(p),
    }
  }

  // --- Safety Properties ---

  /// Agreement: all signers that complete produce the same signature.
  val agreement = SIGNERS.forall(p1 =>
    SIGNERS.forall(p2 =>
      (isCompleted(state.get(p1).result) and isCompleted(state.get(p2).result))
        implies (getSig(state.get(p1).result) == getSig(state.get(p2).result))
    )
  )

  /// Quorum required: no signer reaches Done unless enough shares exist.
  val quorumRequired = SIGNERS.forall(p =>
    (state.get(p).phase == Done) implies
      sharesFrom(msgs, SIGNERS).size() >= SIGNERS.size()
  )

  /// No phantom shares: every share in msgs was sent by a coalition member.
  val noPhantomShares = msgs.forall(m => match m {
    | ShareMsg(s) => SIGNERS.contains(s.from)
    | _ => true
  })

  /// No phantom commitments: every commitment was sent by a coalition member.
  val noPhantomCommitments = msgs.forall(m => match m {
    | CommitMsg(c) => SIGNERS.contains(c.from)
    | _ => true
  })

  /// Commitment completeness: no signer produces a share without having seen
  /// commitments from all other signers first.
  val commitmentCompleteness = msgs.forall(m => match m {
    | ShareMsg(s) => commitmentsFor(s.from, msgs, SIGNERS).size() >= SIGNERS.size() - 1
    | _ => true
  })

  /// At most one commitment per signer.
  val atMostOneCommitPerSigner = SIGNERS.forall(p =>
    commitCountFor(p, msgs) <= 1
  )

  /// At most one share per signer.
  val atMostOneSharePerSigner = SIGNERS.forall(p =>
    shareCountFor(p, msgs) <= 1
  )

  /// Witness: this SHOULD be violatable. If quint run finds a violation,
  /// it confirms the spec can reach a state where signing completes.
  val nobodyDone = SIGNERS.forall(p => state.get(p).phase != Done)
}

// --- Concrete instance for model checking ---

module sign_3of3 {
  import sign(
    PARTICIPANTS = Set("p1", "p2", "p3"),
    THRESHOLD = 2,
    SIGNERS = Set("p1", "p2", "p3"),
  ).*
}
