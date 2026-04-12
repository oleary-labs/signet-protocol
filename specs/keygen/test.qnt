// Keygen Protocol -- Deterministic Tests
//
// Usage: quint test specs/keygen/test.qnt --main=keygen_test

module keygen_test {
  import keygen from "./keygen"
  import keygen.*

  // --- Happy path: all parties complete keygen in order ---

  run happyPathTest = {
    init
    // All parties start Round 1
    .then(startRound1(P1))
    .then(startRound1(P2))
    .then(startRound1(P3))
    // Deliver R1 broadcasts to all parties
    .then(all {
      val r1_p1: R1Msg = { sender: P1, r1Data: 11, chainKey: 1001 }
      parties' = PARTIES.mapBy(p => receiveR1(parties.get(p), r1_p1)),
      network' = network
    })
    .then(all {
      val r1_p2: R1Msg = { sender: P2, r1Data: 22, chainKey: 1002 }
      parties' = PARTIES.mapBy(p => receiveR1(parties.get(p), r1_p2)),
      network' = network
    })
    .then(all {
      val r1_p3: R1Msg = { sender: P3, r1Data: 33, chainKey: 1003 }
      parties' = PARTIES.mapBy(p => receiveR1(parties.get(p), r1_p3)),
      network' = network
    })
    // All parties complete Round 1 (send R2 unicasts)
    .then(completeRound1(P1))
    .then(completeRound1(P2))
    .then(completeRound1(P3))
    // Deliver R2 unicasts to each party
    .then(all {
      val newP1 = parties.get(P1)
        .receiveR2({ sender: P2, receiver: P1, r2Data: 200 })
        .receiveR2({ sender: P3, receiver: P1, r2Data: 300 })
      val newP2 = parties.get(P2)
        .receiveR2({ sender: P1, receiver: P2, r2Data: 100 })
        .receiveR2({ sender: P3, receiver: P2, r2Data: 301 })
      val newP3 = parties.get(P3)
        .receiveR2({ sender: P1, receiver: P3, r2Data: 101 })
        .receiveR2({ sender: P2, receiver: P3, r2Data: 201 })
      parties' = parties.set(P1, newP1).set(P2, newP2).set(P3, newP3),
      network' = network
    })
    // All parties complete Round 2 (derive key share, broadcast pub share)
    .then(completeRound2(P1))
    .then(completeRound2(P2))
    .then(completeRound2(P3))
    // Verify Round 2 output
    .then(all {
      assert(parties.get(P1).phase == Round3),
      assert(parties.get(P1).keyShare != 0),
      assert(parties.get(P1).groupKey == 42),
      assert(parties.get(P1).pubKeyShare != 0),
      unchanged_all
    })
    // Deliver pub shares to all parties
    .then(all {
      val ps1 = parties.get(P1)
      val ps2 = parties.get(P2)
      val ps3 = parties.get(P3)
      val newP1 = ps1
        .receivePubShare({ sender: P2, publicKeyShare: ps2.pubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.pubKeyShare })
      val newP2 = ps2
        .receivePubShare({ sender: P1, publicKeyShare: ps1.pubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.pubKeyShare })
      val newP3 = ps3
        .receivePubShare({ sender: P1, publicKeyShare: ps1.pubKeyShare })
        .receivePubShare({ sender: P2, publicKeyShare: ps2.pubKeyShare })
      parties' = parties.set(P1, newP1).set(P2, newP2).set(P3, newP3),
      network' = network
    })
    // All parties complete Round 3 (build Config)
    .then(completeRound3(P1))
    .then(completeRound3(P2))
    .then(completeRound3(P3))
    // Final verification
    .then(all {
      // All parties are Done
      assert(PARTIES.forall(p => parties.get(p).phase == Done)),
      // All have generation = 0
      assert(PARTIES.forall(p => parties.get(p).generation == 0)),
      // All have non-zero key shares
      assert(PARTIES.forall(p => parties.get(p).keyShare != 0)),
      // All built configs
      assert(PARTIES.forall(p => parties.get(p).configBuilt)),
      // All agree on group key
      assert(parties.get(P1).groupKey == parties.get(P2).groupKey),
      assert(parties.get(P2).groupKey == parties.get(P3).groupKey),
      // All agree on chain key
      assert(parties.get(P1).chainKey == parties.get(P2).chainKey),
      assert(parties.get(P2).chainKey == parties.get(P3).chainKey),
      // All agree on RID
      assert(parties.get(P1).rid == parties.get(P2).rid),
      assert(parties.get(P2).rid == parties.get(P3).rid),
      // Safety invariants hold
      assert(safety),
      unchanged_all
    })
  }

  // --- Interleaved order: P3 starts first, then P1, then P2 ---

  run interleavedOrderTest = {
    init
    .then(startRound1(P3))
    .then(startRound1(P1))
    .then(startRound1(P2))
    // Deliver R1 broadcasts (all at once)
    .then(all {
      val r1_p1: R1Msg = { sender: P1, r1Data: 11, chainKey: 1001 }
      val r1_p2: R1Msg = { sender: P2, r1Data: 22, chainKey: 1002 }
      val r1_p3: R1Msg = { sender: P3, r1Data: 33, chainKey: 1003 }
      parties' = PARTIES.mapBy(p =>
        parties.get(p).receiveR1(r1_p1).receiveR1(r1_p2).receiveR1(r1_p3)
      ),
      network' = network
    })
    // Complete R1 in different order
    .then(completeRound1(P3))
    .then(completeRound1(P1))
    .then(completeRound1(P2))
    // Deliver R2 unicasts
    .then(all {
      val newP1 = parties.get(P1)
        .receiveR2({ sender: P2, receiver: P1, r2Data: 200 })
        .receiveR2({ sender: P3, receiver: P1, r2Data: 300 })
      val newP2 = parties.get(P2)
        .receiveR2({ sender: P1, receiver: P2, r2Data: 100 })
        .receiveR2({ sender: P3, receiver: P2, r2Data: 301 })
      val newP3 = parties.get(P3)
        .receiveR2({ sender: P1, receiver: P3, r2Data: 101 })
        .receiveR2({ sender: P2, receiver: P3, r2Data: 201 })
      parties' = parties.set(P1, newP1).set(P2, newP2).set(P3, newP3),
      network' = network
    })
    // Complete R2 in different order
    .then(completeRound2(P2))
    .then(completeRound2(P3))
    .then(completeRound2(P1))
    // Deliver pub shares
    .then(all {
      val ps1 = parties.get(P1)
      val ps2 = parties.get(P2)
      val ps3 = parties.get(P3)
      val newP1 = ps1
        .receivePubShare({ sender: P2, publicKeyShare: ps2.pubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.pubKeyShare })
      val newP2 = ps2
        .receivePubShare({ sender: P1, publicKeyShare: ps1.pubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.pubKeyShare })
      val newP3 = ps3
        .receivePubShare({ sender: P1, publicKeyShare: ps1.pubKeyShare })
        .receivePubShare({ sender: P2, publicKeyShare: ps2.pubKeyShare })
      parties' = parties.set(P1, newP1).set(P2, newP2).set(P3, newP3),
      network' = network
    })
    // Complete R3 in different order
    .then(completeRound3(P3))
    .then(completeRound3(P1))
    .then(completeRound3(P2))
    // Same result regardless of ordering
    .then(all {
      assert(PARTIES.forall(p => parties.get(p).phase == Done)),
      assert(PARTIES.forall(p => parties.get(p).configBuilt)),
      assert(parties.get(P1).groupKey == parties.get(P3).groupKey),
      assert(parties.get(P1).chainKey == parties.get(P3).chainKey),
      assert(parties.get(P1).rid == parties.get(P3).rid),
      unchanged_all
    })
  }

  // --- Agreement: focused pairwise equality checks ---

  run agreementTest = {
    init
    .then(startRound1(P1))
    .then(startRound1(P2))
    .then(startRound1(P3))
    .then(all {
      val r1_p1: R1Msg = { sender: P1, r1Data: 11, chainKey: 1001 }
      val r1_p2: R1Msg = { sender: P2, r1Data: 22, chainKey: 1002 }
      val r1_p3: R1Msg = { sender: P3, r1Data: 33, chainKey: 1003 }
      parties' = PARTIES.mapBy(p =>
        parties.get(p).receiveR1(r1_p1).receiveR1(r1_p2).receiveR1(r1_p3)
      ),
      network' = network
    })
    .then(completeRound1(P1))
    .then(completeRound1(P2))
    .then(completeRound1(P3))
    .then(all {
      val newP1 = parties.get(P1)
        .receiveR2({ sender: P2, receiver: P1, r2Data: 200 })
        .receiveR2({ sender: P3, receiver: P1, r2Data: 300 })
      val newP2 = parties.get(P2)
        .receiveR2({ sender: P1, receiver: P2, r2Data: 100 })
        .receiveR2({ sender: P3, receiver: P2, r2Data: 301 })
      val newP3 = parties.get(P3)
        .receiveR2({ sender: P1, receiver: P3, r2Data: 101 })
        .receiveR2({ sender: P2, receiver: P3, r2Data: 201 })
      parties' = parties.set(P1, newP1).set(P2, newP2).set(P3, newP3),
      network' = network
    })
    .then(completeRound2(P1))
    .then(completeRound2(P2))
    .then(completeRound2(P3))
    .then(all {
      val ps1 = parties.get(P1)
      val ps2 = parties.get(P2)
      val ps3 = parties.get(P3)
      val newP1 = ps1
        .receivePubShare({ sender: P2, publicKeyShare: ps2.pubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.pubKeyShare })
      val newP2 = ps2
        .receivePubShare({ sender: P1, publicKeyShare: ps1.pubKeyShare })
        .receivePubShare({ sender: P3, publicKeyShare: ps3.pubKeyShare })
      val newP3 = ps3
        .receivePubShare({ sender: P1, publicKeyShare: ps1.pubKeyShare })
        .receivePubShare({ sender: P2, publicKeyShare: ps2.pubKeyShare })
      parties' = parties.set(P1, newP1).set(P2, newP2).set(P3, newP3),
      network' = network
    })
    .then(completeRound3(P1))
    .then(completeRound3(P2))
    .then(completeRound3(P3))
    // Pairwise agreement on all derived values
    .then(all {
      // Group key: all three agree
      assert(parties.get(P1).groupKey == parties.get(P2).groupKey),
      assert(parties.get(P2).groupKey == parties.get(P3).groupKey),
      assert(parties.get(P1).groupKey == GROUP_KEY),
      // Chain key: all three agree
      assert(parties.get(P1).chainKey == parties.get(P2).chainKey),
      assert(parties.get(P2).chainKey == parties.get(P3).chainKey),
      // RID: all three agree
      assert(parties.get(P1).rid == parties.get(P2).rid),
      assert(parties.get(P2).rid == parties.get(P3).rid),
      // RID is derived from chain key
      assert(parties.get(P1).rid == parties.get(P1).chainKey + 1),
      // Generation: all zero
      assert(parties.get(P1).generation == 0),
      assert(parties.get(P2).generation == 0),
      assert(parties.get(P3).generation == 0),
      // Key shares: unique per party
      assert(parties.get(P1).keyShare != parties.get(P2).keyShare),
      assert(parties.get(P2).keyShare != parties.get(P3).keyShare),
      // Public key shares: unique per party
      assert(parties.get(P1).pubKeyShare != parties.get(P2).pubKeyShare),
      assert(parties.get(P2).pubKeyShare != parties.get(P3).pubKeyShare),
      unchanged_all
    })
  }
}
