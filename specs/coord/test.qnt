// Coordination Protocol -- Deterministic Tests
//
// Usage: quint test specs/coord/test.qnt --main=coord_test

module coord_test {
  import coord from "./coord"
  import coord.*

  // --- Valid auth used across tests ---

  pure val VALID_AUTH: AuthInfo = {
    present: true, valid: true, nonce: "n1", timestamp: NOW
  }

  pure val INVALID_AUTH: AuthInfo = {
    present: true, valid: false, nonce: "n2", timestamp: NOW
  }

  pure val MISSING_AUTH: AuthInfo = {
    present: false, valid: false, nonce: "", timestamp: 0
  }

  // --- Happy path keygen: both participants validate + ACK, initiator AllAcked ---

  run happyPathKeygenTest = {
    init
    .then(startKeygenCoord(VALID_AUTH))
    .then(all {
      assert(initiator.phase == Broadcasting),
      unchanged_all
    })
    // Deliver coord to both participants
    .then(deliverCoord(P2))
    .then(deliverCoord(P3))
    .then(all {
      assert(participants.get(P2).phase == Received),
      assert(participants.get(P3).phase == Received),
      unchanged_all
    })
    // Both validate (passes: no key exists, auth valid)
    .then(validateParticipant(P2))
    .then(validateParticipant(P3))
    .then(all {
      assert(participants.get(P2).phase == Validated),
      assert(participants.get(P3).phase == Validated),
      unchanged_all
    })
    // Both send ACK
    .then(ackParticipant(P2))
    .then(ackParticipant(P3))
    .then(all {
      assert(participants.get(P2).phase == Acked),
      assert(participants.get(P3).phase == Acked),
      unchanged_all
    })
    // Initiator collects responses
    .then(collectResponse(P2))
    .then(all {
      // One ACK in, still Broadcasting
      assert(initiator.phase == Broadcasting),
      assert(initiator.acksReceived == Set(P2)),
      unchanged_all
    })
    .then(collectResponse(P3))
    .then(all {
      // Both ACKs in, AllAcked
      assert(initiator.phase == AllAcked),
      assert(initiator.acksReceived == Set(P2, P3)),
      assert(initiator.nacksReceived == Set()),
      assert(safety),
      unchanged_all
    })
  }

  // --- Key exists: keygen participant NACKs, initiator aborts ---

  run keyExistsNACKTest = {
    init
    // Pre-populate key store
    .then(all {
      initiator' = initiator,
      participants' = participants,
      network' = network,
      keyStore' = Set(KEY_ID),
      seenNonces' = seenNonces
    })
    .then(startKeygenCoord(VALID_AUTH))
    .then(deliverCoord(P2))
    .then(deliverCoord(P3))
    // P2 validates: key exists + opType==Keygen => NACK
    .then(validateParticipant(P2))
    .then(all {
      assert(participants.get(P2).phase == Nacked),
      assert(participants.get(P2).response == NACK),
      unchanged_all
    })
    // Initiator collects NACK from P2
    .then(collectResponse(P2))
    .then(all {
      assert(initiator.phase == Aborted),
      assert(initiator.nacksReceived == Set(P2)),
      assert(nackMeansAbort),
      unchanged_all
    })
  }

  // --- Auth failure: invalid auth causes NACK ---

  run authFailureNACKTest = {
    init
    .then(startKeygenCoord(INVALID_AUTH))
    .then(deliverCoord(P2))
    // P2 validates: auth.valid == false => NACK
    .then(validateParticipant(P2))
    .then(all {
      assert(participants.get(P2).phase == Nacked),
      assert(participants.get(P2).response == NACK),
      unchanged_all
    })
    .then(collectResponse(P2))
    .then(all {
      assert(initiator.phase == Aborted),
      assert(safety),
      unchanged_all
    })
  }

  // --- Happy path sign: key exists, both ACK ---

  run happyPathSignTest = {
    init
    // Pre-populate key store for signing
    .then(all {
      initiator' = initiator,
      participants' = participants,
      network' = network,
      keyStore' = Set(KEY_ID),
      seenNonces' = seenNonces
    })
    .then(startSignCoord(VALID_AUTH))
    .then(all {
      assert(initiator.phase == Broadcasting),
      assert(initiator.coordMsg.opType == Sign),
      unchanged_all
    })
    .then(deliverCoord(P2))
    .then(deliverCoord(P3))
    .then(validateParticipant(P2))
    .then(validateParticipant(P3))
    .then(all {
      // Sign + key exists => validation passes
      assert(participants.get(P2).phase == Validated),
      assert(participants.get(P3).phase == Validated),
      unchanged_all
    })
    .then(ackParticipant(P2))
    .then(ackParticipant(P3))
    .then(collectResponse(P2))
    .then(collectResponse(P3))
    .then(all {
      assert(initiator.phase == AllAcked),
      assert(initiator.acksReceived == Set(P2, P3)),
      assert(safety),
      unchanged_all
    })
  }

  // --- Missing auth with policy: NACK ---

  run missingAuthNACKTest = {
    init
    .then(startKeygenCoord(MISSING_AUTH))
    .then(deliverCoord(P2))
    .then(validateParticipant(P2))
    .then(all {
      // HAS_AUTH_POLICY is true, auth not present => NACK
      assert(participants.get(P2).phase == Nacked),
      assert(authRequiredWhenPolicy),
      unchanged_all
    })
  }

  // --- Sign without key: NACK ---

  run signWithoutKeyNACKTest = {
    init
    // keyStore is empty, but we try to sign
    .then(startSignCoord(VALID_AUTH))
    .then(deliverCoord(P2))
    .then(validateParticipant(P2))
    .then(all {
      // Sign + key does NOT exist => NACK
      assert(participants.get(P2).phase == Nacked),
      unchanged_all
    })
  }
}
