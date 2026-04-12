# Formal Specifications

Executable formal models of Signet's core protocols, written in [Quint](https://github.com/informalsystems/quint).

The threshold signing protocols in this project involve multi-party message passing with strict round ordering, quorum requirements, and agreement properties. Bugs in this layer (wrong delivery order, missing quorum checks, split-brain on derived values) are hard to find with unit tests because they emerge from specific interleavings of concurrent events.

These specs model the protocol orchestration layer, not the underlying cryptography. Scalars, commitments, and signatures are abstract values. The cryptographic correctness is the responsibility of the libraries (bytemare/frost, bytemare/dkg); the specs verify that the message-passing structure preserves safety under arbitrary interleaving.

Each spec defines safety invariants (properties that must hold in every reachable state) and witness properties (states the protocol should be able to reach). Quint can typecheck the models, run deterministic scenario tests, and explore random execution traces while checking invariants.

## Protocols

| Directory | Protocol | Specs | Tests |
|-----------|----------|-------|-------|
| [sign/](sign/) | Threshold signing (2-round) | `sign.qnt` | `test.qnt` |
| [keygen/](keygen/) | Key generation (3-round DKG) | `keygen.qnt` | `test.qnt` |
| [reshare/](reshare/) | Key reshare (3-round protocol + node lifecycle) | `reshare.qnt`, `lifecycle.qnt` | `test.qnt` |
| [coord/](coord/) | Session coordination (barrier sync + auth) | `coord.qnt` | `test.qnt` |

## Setup

```bash
npm install -g @informalsystems/quint
brew install apalache-mc  # optional, for quint verify
```

## How to read results

### `quint test` -- Deterministic scenarios

Runs hand-written execution traces with explicit assertions. Each `run` block is a fixed sequence of actions (no randomness).

```
ok happyPathTest passed 1 test(s)        # test passed
ok interleavedOrderTest passed 1 test(s)  # test passed
```

A failure means an `assert(...)` in the trace evaluated to false. The output shows the failing state, which tells you exactly where the invariant broke.

### `quint run` -- Random simulation

Explores random execution traces by repeatedly picking a party and an enabled action via the nondeterministic `step` definition.

```
[ok] No violation found (762ms at 656 traces/second).
```

This means the invariant held across all explored traces. It is not a proof (the state space is too large to exhaust), but it provides confidence proportional to the number of samples.

```
[violation] Found an issue (423ms).
```

For a safety invariant, a violation means a bug: there exists a reachable state where the property fails. The output includes the full execution trace leading to the violating state.

For a witness property, a violation is expected and desirable. Witnesses are negations of liveness goals (e.g., "no party has completed"). Finding a violation confirms the protocol can actually reach that state. If `quint run` cannot find a violation for a witness, it usually means the random walk did not explore enough of the state space within the step limit, not that the state is unreachable. The deterministic tests cover reachability directly.

### `quint verify` -- Exhaustive model checking

Explores all reachable states symbolically via the [Apalache](https://apalache-mc.org/) model checker. Unlike `quint run`, this is a proof: if it reports no violation, the invariant holds in every reachable state, not just the states that happened to be sampled.

```bash
quint verify keygen.qnt --invariant=safety
```

```
[ok] No violation found.   # invariant holds in ALL reachable states (proof)
[violation] Found an issue. # counterexample with full trace
```

Requires a separate install (`apalache-mc`). The specs in this project are written to be compatible with both `run` and `verify`, but we primarily use `test` and `run` for day-to-day development. Use `verify` when you need a guarantee, not just confidence.
