// Sign Protocol -- Deterministic Tests
//
// Usage: quint test specs/sign/test.qnt --main=sign_test
//        quint test specs/sign/test.qnt --main=sign_threshold_test

module sign_test {
  import sign from "./sign"
  import sign(
    PARTICIPANTS = Set("p1", "p2", "p3"),
    THRESHOLD = 2,
    SIGNERS = Set("p1", "p2", "p3"),
  ).*

  // --- Happy path: all signers commit, produce shares, aggregate in order ---

  run happyPathTest = {
    init
      .then(commit("p1"))
      .then(commit("p2"))
      .then(commit("p3"))
      .then(produceShare("p1"))
      .then(produceShare("p2"))
      .then(produceShare("p3"))
      .then(aggregate("p1"))
      .then(all {
        assert(state.get("p1").phase == Done),
        assert(isCompleted(state.get("p1").result)),
        assert(state.get("p2").phase == SignShareSent),
        assert(state.get("p3").phase == SignShareSent),
        assert(agreement),
        assert(noPhantomShares),
        assert(quorumRequired),
        state' = state,
        msgs' = msgs,
      })
  }

  // --- All signers complete: verify agreement ---

  run allCompleteTest = {
    init
      .then(commit("p1"))
      .then(commit("p2"))
      .then(commit("p3"))
      .then(produceShare("p1"))
      .then(produceShare("p2"))
      .then(produceShare("p3"))
      .then(aggregate("p1"))
      .then(aggregate("p2"))
      .then(aggregate("p3"))
      .then(all {
        assert(state.get("p1").phase == Done),
        assert(state.get("p2").phase == Done),
        assert(state.get("p3").phase == Done),
        assert(state.get("p1").result == state.get("p2").result),
        assert(state.get("p2").result == state.get("p3").result),
        assert(agreement),
        state' = state,
        msgs' = msgs,
      })
  }

  // --- Interleaved commit order: p1 commits, p3 commits, p2 commits last ---

  run interleavedCommitTest = {
    init
      .then(commit("p1"))
      .then(commit("p3"))
      .then(commit("p2"))
      .then(produceShare("p3"))
      .then(produceShare("p1"))
      .then(produceShare("p2"))
      .then(aggregate("p1"))
      .then(all {
        assert(state.get("p1").phase == Done),
        assert(agreement),
        state' = state,
        msgs' = msgs,
      })
  }

  // --- Commitment completeness: share requires all commitments ---

  run commitmentCompletenessInvariantTest = {
    init
      .then(commit("p1"))
      .then(commit("p2"))
      // p1 has only p2's commitment, missing p3
      .then(all {
        assert(commitmentsFor("p1", msgs, SIGNERS).size() == 1),
        assert(commitmentCompleteness),
        state' = state,
        msgs' = msgs,
      })
  }

  // --- Message counts: verify exactly one commit and one share per signer ---

  run messageCountTest = {
    init
      .then(commit("p1"))
      .then(commit("p2"))
      .then(commit("p3"))
      .then(all {
        assert(atMostOneCommitPerSigner),
        state' = state,
        msgs' = msgs,
      })
      .then(produceShare("p1"))
      .then(produceShare("p2"))
      .then(produceShare("p3"))
      .then(all {
        assert(atMostOneSharePerSigner),
        assert(msgs.size() == 6),  // 3 commits + 3 shares
        state' = state,
        msgs' = msgs,
      })
  }
}

// --- 2-of-3 threshold test: only 2 signers participate ---

module sign_threshold_test {
  import sign from "./sign"
  import sign(
    PARTICIPANTS = Set("p1", "p2", "p3"),
    THRESHOLD = 2,
    SIGNERS = Set("p1", "p2"),
  ).*

  run thresholdSubsetTest = {
    init
      .then(commit("p1"))
      .then(commit("p2"))
      .then(produceShare("p1"))
      .then(produceShare("p2"))
      .then(aggregate("p1"))
      .then(aggregate("p2"))
      .then(all {
        assert(state.get("p1").phase == Done),
        assert(state.get("p2").phase == Done),
        assert(state.get("p1").result == state.get("p2").result),
        assert(agreement),
        assert(quorumRequired),
        state' = state,
        msgs' = msgs,
      })
  }
}
