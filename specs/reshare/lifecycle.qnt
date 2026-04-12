// Group Reshare Lifecycle
// Based on: docs/DESIGN-RESHARE.md sections 4-8 + node/chain.go, node/node.go
//
// Models the per-group ACTIVE -> RESHARING -> ACTIVE state machine that
// manages key reshare jobs triggered by on-chain membership changes.
// This is the node-level orchestration layer above the KeyManager interface
// (node/keymanager.go). The actual cryptographic reshare protocol is modeled
// separately in reshare.qnt.
//
// Architecture boundary:
//   This spec lives in the node/ layer. It calls the KeyManager to reshare
//   a key and gets back success/failure. It does NOT care whether the
//   KeyManager is:
//     - LocalKeyManager (in-process Go tss, tss/reshare.go)
//     - RemoteKeyManager (gRPC to Rust KMS, kms-frost/)
//   The KeyManager interface (node/keymanager.go) does not yet have a
//   Reshare method — it will be added alongside this orchestration code.
//   The lifecycle spec is intentionally backend-agnostic: the same state
//   machine applies regardless of which KeyManager implementation runs
//   the FROST rounds.
//
// NOT YET IMPLEMENTED in code — this spec is ahead of the implementation.
// The design is fully specified in DESIGN-RESHARE.md; the chain client
// (node/chain.go) detects NodeJoined/NodeRemoved events but does not
// yet create ReshareJobs or trigger reshare coordination.
//
// Scope:
//   - Per-group state (ACTIVE/RESHARING), not per-node
//   - Models a single node's view of one group (local state machine)
//   - Key staleness tracking (keysTotal vs keysDone)
//   - Deferred membership events
//   - Coordinator vs on-demand reshare paths
//   - Sign-handler blocking on stale keys
//   - Abstracts away the cryptographic protocol behind the KeyManager
//     interface (just "key in-flight -> key done")
module lifecycle {

  // ============================================================
  // 1. TYPES
  // ============================================================

  type GroupID = str
  type KeyID = str
  type PartyID = str

  /// Per-group reshare state
  type GroupPhase =
    | Active       // normal operation, all keys fresh
    | Resharing    // one or more keys stale, reshare in progress or pending

  /// Membership event types from the chain
  type EventType =
    | NodeAdded(PartyID)
    | NodeRemoved(PartyID)

  /// A deferred membership event that arrived while resharing
  /// (design doc section 5.1: DeferredMembershipEvent)
  type DeferredEvent = {
    event: EventType
  }

  /// The reshare job for a group (design doc section 5.1: ReshareJob)
  /// Created when a membership event is detected while the group is ACTIVE.
  /// One job per group at a time — additional events are deferred.
  type ReshareJob = {
    oldParties: Set[PartyID],
    newParties: Set[PartyID],
    oldThreshold: int,
    newThreshold: int,
    keysTotal: Set[KeyID],         // snapshot of all key IDs at job creation
    deferredEvents: List[DeferredEvent]
  }

  /// Coordinator status for this node
  type CoordStatus =
    | NotCoordinator
    | Coordinating(int)   // concurrency level

  /// Per-key reshare status
  type KeyReshareStatus =
    | Fresh            // not part of current reshare, or already reshared
    | Stale            // needs reshare, not yet started
    | InFlight         // reshare session running for this key
    | Done             // reshare completed for this key in current job

  /// Result of a sign attempt
  type SignResult =
    | SignOK
    | SignBlocked(KeyID)     // key is stale, sign must wait
    | SignError              // key not found or other error

  /// The full state of the reshare lifecycle for a single group on a single node
  type State = {
    groupId: GroupID,
    phase: GroupPhase,
    members: Set[PartyID],      // current on-chain membership
    threshold: int,
    keys: Set[KeyID],           // all keys held for this group
    job: ReshareJob,            // active reshare job (meaningful only in Resharing)
    keysDone: Set[KeyID],       // keys completed in current reshare
    keysInFlight: Set[KeyID],   // keys with active reshare sessions
    coordStatus: CoordStatus,
    selfID: PartyID
  }

  // ============================================================
  // 2. CONSTANTS AND CONFIGURATION
  // ============================================================

  pure val SELF: PartyID = "node1"
  pure val GROUP: GroupID = "group1"

  // Initial membership
  pure val N1: PartyID = "node1"
  pure val N2: PartyID = "node2"
  pure val N3: PartyID = "node3"
  pure val N4: PartyID = "node4"  // will be added later
  pure val INITIAL_MEMBERS: Set[PartyID] = Set(N1, N2, N3)
  pure val INITIAL_THRESHOLD = 2

  // Initial keys
  pure val K1: KeyID = "key1"
  pure val K2: KeyID = "key2"
  pure val K3: KeyID = "key3"
  pure val INITIAL_KEYS: Set[KeyID] = Set(K1, K2, K3)

  // Empty job sentinel
  pure val EMPTY_JOB: ReshareJob = {
    oldParties: Set(),
    newParties: Set(),
    oldThreshold: 0,
    newThreshold: 0,
    keysTotal: Set(),
    deferredEvents: []
  }

  // ============================================================
  // 3. PURE FUNCTIONS
  // ============================================================

  /// Check if a key is stale in the current reshare job
  /// (design doc section 5.3: stale iff job exists AND key in keysTotal AND not in done)
  pure def isKeyStale(st: State, keyId: KeyID): bool =
    st.phase == Resharing and
    st.job.keysTotal.contains(keyId) and
    not(st.keysDone.contains(keyId))

  /// Get all stale keys for the current job
  pure def staleKeys(st: State): Set[KeyID] =
    if (st.phase != Resharing) Set()
    else st.job.keysTotal.exclude(st.keysDone)

  /// Check if all keys in the job are done
  pure def allKeysDone(st: State): bool =
    st.phase == Resharing and
    st.job.keysTotal.subseteq(st.keysDone)

  /// Apply a membership event to get new members
  pure def applyEvent(members: Set[PartyID], event: EventType): Set[PartyID] =
    match event {
      | NodeAdded(p) => members.union(Set(p))
      | NodeRemoved(p) => members.exclude(Set(p))
    }

  /// Create a reshare job from a membership event
  /// (design doc section 8.1: chain client creates ReshareJob)
  pure def createJob(
    st: State,
    event: EventType
  ): ReshareJob = {
    oldParties: st.members,
    newParties: applyEvent(st.members, event),
    oldThreshold: st.threshold,
    newThreshold: st.threshold,  // threshold unchanged by default
    keysTotal: st.keys,          // snapshot of all current keys
    deferredEvents: []
  }

  /// Append a deferred event to the current job
  /// (design doc section 8.1 step 2: if RESHARING, append to DeferredEvents)
  pure def deferEvent(job: ReshareJob, event: EventType): ReshareJob =
    { ...job, deferredEvents: job.deferredEvents.append({ event: event }) }

  /// Process a membership event: either create a new job or defer
  /// Returns (newState, jobCreated)
  pure def onMembershipEvent(
    st: State,
    event: EventType
  ): { newState: State, jobCreated: bool } =
    if (st.phase == Active) {
      // Create new reshare job, transition to Resharing
      {
        newState: {
          ...st,
          phase: Resharing,
          members: applyEvent(st.members, event),
          job: createJob(st, event),
          keysDone: Set(),
          keysInFlight: Set()
        },
        jobCreated: true
      }
    } else {
      // Already resharing: defer this event
      {
        newState: {
          ...st,
          job: deferEvent(st.job, event),
          members: applyEvent(st.members, event)
        },
        jobCreated: false
      }
    }

  /// Start coordinator for this group
  /// (design doc section 8.3: POST /v1/reshare handler)
  pure def startCoordinator(
    st: State,
    concurrency: int
  ): { success: bool, newState: State } =
    if (st.phase == Active) {
      // 404: no pending job
      { success: false, newState: st }
    } else {
      // Resharing
      match st.coordStatus {
        | Coordinating(_) =>
          // 409: already coordinating
          { success: false, newState: st }
        | NotCoordinator =>
          { success: true, newState: { ...st, coordStatus: Coordinating(concurrency) } }
      }
    }

  /// Coordinator picks a stale key to reshare
  /// (design doc section 8.3: coordinatorLoop iterates staleKeys)
  pure def coordinatorPickKey(
    st: State,
    keyId: KeyID
  ): { success: bool, newState: State } =
    if (st.phase != Resharing) { success: false, newState: st }
    else if (not(isKeyStale(st, keyId))) { success: false, newState: st }
    else if (st.keysInFlight.contains(keyId)) { success: false, newState: st }
    else {
      success: true,
      newState: { ...st, keysInFlight: st.keysInFlight.union(Set(keyId)) }
    }

  /// A key's reshare completes (coordinator or on-demand)
  /// (design doc section 8.3: writeReshareKeyRecord, invalidateConfigCache)
  pure def completeKeyReshare(
    st: State,
    keyId: KeyID
  ): State = {
    ...st,
    keysDone: st.keysDone.union(Set(keyId)),
    keysInFlight: st.keysInFlight.exclude(Set(keyId))
  }

  /// On-demand reshare: sign handler triggers reshare for a specific stale key
  /// (design doc section 8.4: waitForReshare -> on-demand reshare)
  pure def onDemandReshare(
    st: State,
    keyId: KeyID
  ): { success: bool, newState: State } =
    if (not(isKeyStale(st, keyId))) { success: false, newState: st }
    else if (st.keysInFlight.contains(keyId)) {
      // Already in flight (coordinator or another on-demand): wait, don't start new
      { success: false, newState: st }
    } else {
      success: true,
      newState: { ...st, keysInFlight: st.keysInFlight.union(Set(keyId)) }
    }

  /// Attempt to sign with a key
  /// (design doc section 8.2: handleSign checks isStale before proceeding)
  pure def trySigning(st: State, keyId: KeyID): SignResult =
    if (not(st.keys.contains(keyId))) SignError
    else if (isKeyStale(st, keyId)) SignBlocked(keyId)
    else SignOK

  /// Complete the current reshare job: transition back to ACTIVE or process deferred
  /// (design doc section 8.3: coordinatorLoop "when all keys done" block)
  pure def completeJob(st: State): { newState: State, deferredProcessed: bool } =
    if (not(allKeysDone(st))) {
      // Not all keys done yet
      newState: st, deferredProcessed: false
    } else if (st.job.deferredEvents.length() > 0) {
      // Process first deferred event: create new job
      // (design doc section 10.4: new OldParties = previous NewParties)
      val nextEvent = st.job.deferredEvents[0]
      val remainingDeferred = st.job.deferredEvents.slice(1, st.job.deferredEvents.length())
      val baseState = {
        ...st,
        phase: Active,
        job: EMPTY_JOB,
        keysDone: Set(),
        keysInFlight: Set(),
        coordStatus: NotCoordinator
      }
      val result = onMembershipEvent(baseState, nextEvent.event)
      // Carry over remaining deferred events to the new job
      val stateWithDeferred = {
        ...result.newState,
        job: { ...result.newState.job,
               deferredEvents: remainingDeferred }
      }
      { newState: stateWithDeferred, deferredProcessed: true }
    } else {
      // No deferred events: go back to ACTIVE
      // (design doc: delete reshare_jobs, clear reshare_done, set ACTIVE)
      newState: {
        ...st,
        phase: Active,
        job: EMPTY_JOB,
        keysDone: Set(),
        keysInFlight: Set(),
        coordStatus: NotCoordinator
      },
      deferredProcessed: false
    }

  // ============================================================
  // 4. STATE VARIABLES
  // ============================================================

  var state: State

  // ============================================================
  // 5. ACTIONS
  // ============================================================

  action unchanged = state' = state

  /// Initialize: group in ACTIVE state with initial membership and keys
  action init = state' = {
    groupId: GROUP,
    phase: Active,
    members: INITIAL_MEMBERS,
    threshold: INITIAL_THRESHOLD,
    keys: INITIAL_KEYS,
    job: EMPTY_JOB,
    keysDone: Set(),
    keysInFlight: Set(),
    coordStatus: NotCoordinator,
    selfID: SELF
  }

  /// Chain event: a node is added to the group
  action chainNodeAdded(p: PartyID): bool = {
    if (state.members.contains(p)) unchanged
    else {
      val result = onMembershipEvent(state, NodeAdded(p))
      state' = result.newState
    }
  }

  /// Chain event: a node is removed from the group
  action chainNodeRemoved(p: PartyID): bool = {
    if (not(state.members.contains(p))) unchanged
    else {
      val result = onMembershipEvent(state, NodeRemoved(p))
      state' = result.newState
    }
  }

  /// Operator calls POST /v1/reshare to start coordinator
  action apiStartReshare(concurrency: int): bool = {
    val result = startCoordinator(state, concurrency)
    if (result.success) state' = result.newState
    else unchanged
  }

  /// Coordinator picks and starts resharing a stale key
  action coordReshareKey(keyId: KeyID): bool = {
    val result = coordinatorPickKey(state, keyId)
    if (result.success) state' = result.newState
    else unchanged
  }

  /// A key's reshare session completes successfully
  action keyReshareComplete(keyId: KeyID): bool = {
    if (not(state.keysInFlight.contains(keyId))) unchanged
    else state' = completeKeyReshare(state, keyId)
  }

  /// Sign handler encounters a stale key, triggers on-demand reshare
  action signTriggersOnDemand(keyId: KeyID): bool = {
    val result = onDemandReshare(state, keyId)
    if (result.success) state' = result.newState
    else unchanged
  }

  /// All keys done: complete job and possibly process deferred event
  action finishJob: bool = {
    val result = completeJob(state)
    if (result.newState != state) state' = result.newState
    else unchanged
  }

  /// A new key is created (keygen) while reshare is in progress
  /// (design doc: "keys created after reshare starts are born into new committee")
  action keygenDuringReshare(keyId: KeyID): bool = {
    if (state.keys.contains(keyId)) unchanged
    else state' = { ...state, keys: state.keys.union(Set(keyId)) }
    // Note: new key is NOT added to job.keysTotal — it doesn't need resharing
  }

  /// Nondeterministic step
  action step = any {
    // Chain events
    nondet p = Set(N1, N2, N3, N4).oneOf()
    chainNodeAdded(p),

    nondet p = Set(N1, N2, N3, N4).oneOf()
    chainNodeRemoved(p),

    // Operator triggers
    nondet c = Set(1, 5).oneOf()
    apiStartReshare(c),

    // Coordinator picks a key
    nondet k = INITIAL_KEYS.oneOf()
    coordReshareKey(k),

    // Key reshare completes
    nondet k = INITIAL_KEYS.oneOf()
    keyReshareComplete(k),

    // Sign triggers on-demand
    nondet k = INITIAL_KEYS.oneOf()
    signTriggersOnDemand(k),

    // Job completion
    finishJob,

    // Keygen during reshare
    nondet k = Set("key4", "key5").oneOf()
    keygenDuringReshare(k)
  }

  // ============================================================
  // 6. INVARIANTS
  // ============================================================

  /// The group is ACTIVE iff there is no active reshare job
  val phaseJobConsistency =
    if (state.phase == Active) state.job == EMPTY_JOB
    else state.job.keysTotal.size() > 0

  /// keysDone is always a subset of keysTotal
  val keysDoneSubset =
    state.keysDone.subseteq(state.job.keysTotal)

  /// keysInFlight is always a subset of stale keys (keysTotal - keysDone)
  val keysInFlightSubset =
    state.keysInFlight.subseteq(state.job.keysTotal.exclude(state.keysDone))

  /// No keys are in flight when group is ACTIVE
  val activeNoInFlight =
    state.phase == Active implies state.keysInFlight == Set()

  /// No keys are done when group is ACTIVE
  val activeNoDone =
    state.phase == Active implies state.keysDone == Set()

  /// Coordinator status is NotCoordinator when ACTIVE
  val activeNotCoordinating =
    state.phase == Active implies state.coordStatus == NotCoordinator

  /// Signing a non-stale key always succeeds (returns SignOK)
  val freshKeysSignable =
    state.keys.forall(k =>
      not(isKeyStale(state, k)) implies trySigning(state, k) == SignOK
    )

  /// Stale keys block signing
  val staleKeysBlock =
    state.keys.forall(k =>
      isKeyStale(state, k) implies trySigning(state, k) == SignBlocked(k)
    )

  /// Keys created during reshare are not stale
  /// (they're born into the new committee — not in job.keysTotal)
  val newKeysNotStale =
    state.keys.forall(k =>
      not(state.job.keysTotal.contains(k)) implies not(isKeyStale(state, k))
    )

  /// The job's keysTotal is a subset of the group's keys at creation time
  /// (it's a snapshot — keys added later are not included)
  val keysTotalSnapshot =
    state.phase == Resharing implies
      state.job.keysTotal.subseteq(state.keys)

  /// Members always include at least the threshold (group is functional)
  val membershipAboveThreshold =
    state.members.size() >= state.threshold

  /// Combined safety invariant
  val safety = and {
    phaseJobConsistency,
    keysDoneSubset,
    keysInFlightSubset,
    activeNoInFlight,
    activeNoDone,
    activeNotCoordinating,
    freshKeysSignable,
    staleKeysBlock,
    newKeysNotStale,
    keysTotalSnapshot
  }

  // ============================================================
  // 7. WITNESSES
  // ============================================================

  /// Witness: group can enter RESHARING state
  val neverResharing = state.phase != Resharing

  /// Witness: all keys can be reshared and group returns to ACTIVE
  val neverReturnsToActive =
    not(state.phase == Active and state.keysDone == Set() and
        state.job == EMPTY_JOB and state.keys.size() > INITIAL_KEYS.size())

  /// Witness: deferred events can be processed
  val neverProcessesDeferred =
    state.phase != Resharing or state.job.deferredEvents.length() == 0

  /// Witness: on-demand reshare can be triggered
  val neverOnDemand =
    state.keysInFlight == Set() or
    state.coordStatus != NotCoordinator

}
