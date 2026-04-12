// Reshare Protocol -- Deterministic Tests
//
// Usage: quint test specs/reshare/test.qnt --main=reshare_test
//        quint test specs/reshare/test.qnt --main=lifecycle_test

module reshare_test {
  import reshare from "./reshare"
  import reshare.*

  /// Test: Full reshare completes for a simple scenario
  /// P1 (old-only), P2 (both), P3 (both), P4 (new-only)
  run fullReshareTest =
    // Initialize
    init
    // All parties start Round 1
    .then(startRound1(P1))
    .then(startRound1(P2))
    .then(startRound1(P3))
    .then(startRound1(P4))
    // Deliver commit messages to all parties
    .then(all {
      val cm1: CommitMsg = { sender: P1, commitments: [30, 11], chainKey: 1001, generation: 0, groupKey: 42 }
      parties' = ALL_PARTIES.mapBy(p => receiveCommit(parties.get(p), cm1)),
      network' = network
    })
    .then(all {
      val cm2: CommitMsg = { sender: P2, commitments: [100, 22], chainKey: 1002, generation: 0, groupKey: 42 }
      parties' = ALL_PARTIES.mapBy(p => receiveCommit(parties.get(p), cm2)),
      network' = network
    })
    .then(all {
      val cm3: CommitMsg = { sender: P3, commitments: [210, 33], chainKey: 1003, generation: 0, groupKey: 42 }
      parties' = ALL_PARTIES.mapBy(p => receiveCommit(parties.get(p), cm3)),
      network' = network
    })
    // All parties complete Round 1
    .then(completeRound1(P1))
    .then(completeRound1(P2))
    .then(completeRound1(P3))
    .then(completeRound1(P4))
    // Deliver eval messages to new parties
    .then(all {
      // Deliver evals from all old parties to P2
      val newP2 = parties.get(P2)
        .receiveEval({ sender: P1, receiver: P2, subShare: 100 })
        .receiveEval({ sender: P2, receiver: P2, subShare: 200 })
        .receiveEval({ sender: P3, receiver: P2, subShare: 300 })
      // Deliver evals from all old parties to P3
      val newP3 = parties.get(P3)
        .receiveEval({ sender: P1, receiver: P3, subShare: 101 })
        .receiveEval({ sender: P2, receiver: P3, subShare: 201 })
        .receiveEval({ sender: P3, receiver: P3, subShare: 301 })
      // Deliver evals from all old parties to P4
      val newP4 = parties.get(P4)
        .receiveEval({ sender: P1, receiver: P4, subShare: 102 })
        .receiveEval({ sender: P2, receiver: P4, subShare: 202 })
        .receiveEval({ sender: P3, receiver: P4, subShare: 302 })
      parties' = parties.set(P2, newP2).set(P3, newP3).set(P4, newP4),
      network' = network
    })
    // Complete Round 2 for all parties
    .then(completeRound2(P1))  // old-only: exits with sentinel
    .then(completeRound2(P2))  // both: combines, broadcasts pub share
    .then(completeRound2(P3))
    .then(completeRound2(P4))
    // Verify: P1 (old-only) is Done
    .then(all {
      assert(parties.get(P1).phase == Done),
      assert(parties.get(P1).newSecret == 0),          // sentinel: no new key share
      assert(parties.get(P1).newGeneration == 1),
      unchanged_all
    })
    // Deliver pub share messages to all new parties
    .then(all {
      val ps2 = parties.get(P2)
      val ps3 = parties.get(P3)
      val ps4 = parties.get(P4)
      val newP2 = ps2
        .receivePubShare({ sender: P2, publicKeyShare: ps2.newPubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.newPubKeyShare })
        .receivePubShare({ sender: P4, publicKeyShare: ps4.newPubKeyShare })
      val newP3 = ps3
        .receivePubShare({ sender: P2, publicKeyShare: ps2.newPubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.newPubKeyShare })
        .receivePubShare({ sender: P4, publicKeyShare: ps4.newPubKeyShare })
      val newP4 = ps4
        .receivePubShare({ sender: P2, publicKeyShare: ps2.newPubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.newPubKeyShare })
        .receivePubShare({ sender: P4, publicKeyShare: ps4.newPubKeyShare })
      parties' = parties.set(P2, newP2).set(P3, newP3).set(P4, newP4),
      network' = network
    })
    // Complete Round 3
    .then(completeRound3(P2))
    .then(completeRound3(P3))
    .then(completeRound3(P4))
    // Final verification
    .then(all {
      // All parties are Done
      assert(ALL_PARTIES.forall(p => parties.get(p).phase == Done)),
      // All have generation = 1
      assert(ALL_PARTIES.forall(p => parties.get(p).newGeneration == 1)),
      // New parties have non-zero secrets
      assert(NEW_PARTIES.forall(p => parties.get(p).newSecret != 0)),
      // New parties agree on chain key
      assert(parties.get(P2).newChainKey == parties.get(P3).newChainKey),
      assert(parties.get(P3).newChainKey == parties.get(P4).newChainKey),
      // New parties built configs
      assert(NEW_PARTIES.forall(p => parties.get(p).configBuilt)),
      unchanged_all
    })

  /// Test: Old-only party exits after Round 2 (does not reach Round 3)
  run oldOnlyExitsEarlyTest =
    init
    .then(startRound1(P1))
    .then(startRound1(P2))
    .then(startRound1(P3))
    .then(startRound1(P4))
    .then(all {
      val cm1: CommitMsg = { sender: P1, commitments: [30, 11], chainKey: 1001, generation: 0, groupKey: 42 }
      val cm2: CommitMsg = { sender: P2, commitments: [100, 22], chainKey: 1002, generation: 0, groupKey: 42 }
      val cm3: CommitMsg = { sender: P3, commitments: [210, 33], chainKey: 1003, generation: 0, groupKey: 42 }
      parties' = ALL_PARTIES.mapBy(p =>
        parties.get(p).receiveCommit(cm1).receiveCommit(cm2).receiveCommit(cm3)
      ),
      network' = network
    })
    .then(completeRound1(P1))
    .then(completeRound1(P2))
    .then(completeRound1(P3))
    .then(completeRound1(P4))
    .then(completeRound2(P1))
    .then(all {
      // P1 (old-only) is Done with sentinel config
      assert(parties.get(P1).phase == Done),
      assert(parties.get(P1).role == OldOnly),
      assert(parties.get(P1).newSecret == 0),
      assert(parties.get(P1).configBuilt),
      // Other parties are still in Round 2 (haven't received evals yet)
      assert(parties.get(P2).phase == Round2),
      assert(parties.get(P3).phase == Round2),
      assert(parties.get(P4).phase == Round2),
      unchanged_all
    })
}

module lifecycle_test {
  import lifecycle from "./lifecycle"
  import lifecycle.*

  /// Test: Normal reshare lifecycle -- node added, reshare all keys, return to ACTIVE
  run normalLifecycleTest =
    init
    // Chain event: N4 joins the group
    .then(chainNodeAdded(N4))
    .then(all {
      assert(state.phase == Resharing),
      assert(state.job.oldParties == Set(N1, N2, N3)),
      assert(state.job.newParties == Set(N1, N2, N3, N4)),
      assert(state.job.keysTotal == Set(K1, K2, K3)),
      assert(state.members == Set(N1, N2, N3, N4)),
      unchanged
    })
    // Operator starts coordinator
    .then(apiStartReshare(5))
    .then(all {
      assert(state.coordStatus == Coordinating(5)),
      unchanged
    })
    // Coordinator reshares keys one by one
    .then(coordReshareKey(K1))
    .then(keyReshareComplete(K1))
    .then(all {
      assert(state.keysDone == Set(K1)),
      assert(not(isKeyStale(state, K1))),
      // K1 is now signable
      assert(trySigning(state, K1) == SignOK),
      // K2, K3 still stale
      assert(trySigning(state, K2) == SignBlocked(K2)),
      unchanged
    })
    .then(coordReshareKey(K2))
    .then(keyReshareComplete(K2))
    .then(coordReshareKey(K3))
    .then(keyReshareComplete(K3))
    // All done -- finish job
    .then(all {
      assert(allKeysDone(state)),
      unchanged
    })
    .then(finishJob)
    .then(all {
      assert(state.phase == Active),
      assert(state.job == EMPTY_JOB),
      assert(state.coordStatus == NotCoordinator),
      assert(state.keysDone == Set()),
      assert(state.keysInFlight == Set()),
      // All keys signable again
      assert(INITIAL_KEYS.forall(k => trySigning(state, k) == SignOK)),
      unchanged
    })

  /// Test: Deferred events -- second membership change during reshare
  run deferredEventTest =
    init
    // N4 added -> triggers reshare
    .then(chainNodeAdded(N4))
    .then(all {
      assert(state.phase == Resharing),
      assert(state.job.deferredEvents.length() == 0),
      unchanged
    })
    // N2 removed while resharing -> deferred
    .then(chainNodeRemoved(N2))
    .then(all {
      assert(state.phase == Resharing),
      assert(state.job.deferredEvents.length() == 1),
      // Members updated immediately (chain view)
      assert(state.members == Set(N1, N3, N4)),
      // But job still uses old/new from first event
      assert(state.job.oldParties == Set(N1, N2, N3)),
      assert(state.job.newParties == Set(N1, N2, N3, N4)),
      unchanged
    })
    // Complete all keys for the first reshare
    .then(apiStartReshare(1))
    .then(coordReshareKey(K1))
    .then(keyReshareComplete(K1))
    .then(coordReshareKey(K2))
    .then(keyReshareComplete(K2))
    .then(coordReshareKey(K3))
    .then(keyReshareComplete(K3))
    // Finish job -- should process deferred event
    .then(finishJob)
    .then(all {
      // Should be RESHARING again with new job for N2 removal
      assert(state.phase == Resharing),
      assert(state.job.keysTotal == Set(K1, K2, K3)),
      // New job's old = previous new (N1, N2, N3, N4), new = that minus N2
      assert(state.job.newParties == Set(N1, N3, N4)),
      assert(state.job.deferredEvents.length() == 0),
      unchanged
    })

  /// Test: On-demand reshare -- sign handler triggers reshare for stale key
  run onDemandReshareTest =
    init
    .then(chainNodeAdded(N4))
    .then(all {
      // All keys are stale
      assert(trySigning(state, K1) == SignBlocked(K1)),
      unchanged
    })
    // Sign for K2 triggers on-demand (no coordinator started)
    .then(signTriggersOnDemand(K2))
    .then(all {
      assert(state.keysInFlight == Set(K2)),
      assert(state.coordStatus == NotCoordinator),
      unchanged
    })
    // On-demand reshare completes
    .then(keyReshareComplete(K2))
    .then(all {
      assert(state.keysDone == Set(K2)),
      assert(trySigning(state, K2) == SignOK),
      // K1, K3 still stale
      assert(trySigning(state, K1) == SignBlocked(K1)),
      unchanged
    })

  /// Test: Keygen during reshare -- new key is born into new committee
  run keygenDuringReshareTest =
    init
    .then(chainNodeAdded(N4))
    .then(all {
      assert(state.phase == Resharing),
      unchanged
    })
    // New key created during reshare
    .then(keygenDuringReshare("key4"))
    .then(all {
      assert(state.keys.contains("key4")),
      // New key is NOT in job.keysTotal -- it doesn't need resharing
      assert(not(state.job.keysTotal.contains("key4"))),
      assert(not(isKeyStale(state, "key4"))),
      // New key is immediately signable
      assert(trySigning(state, "key4") == SignOK),
      unchanged
    })

  /// Test: Duplicate coordinator start returns 409
  run duplicateCoordinatorTest =
    init
    .then(chainNodeAdded(N4))
    .then(apiStartReshare(5))
    .then(all {
      assert(state.coordStatus == Coordinating(5)),
      unchanged
    })
    // Second start attempt fails (409)
    .then(all {
      val result = startCoordinator(state, 1)
      assert(not(result.success)),
      unchanged
    })
}
