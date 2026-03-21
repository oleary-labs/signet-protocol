# Project Context: signet

## Overview
Research project implementing a threshold signing network. Uses a custom LSS (Linear Secret Sharing) MPC protocol (`signet/lss`) for keygen, signing, and reshare, with `libp2p` for P2P transport.

## Tech Stack
- **Language**: Go 1.24+
- **Threshold crypto**: `signet/lss` (internal — secp256k1 LSS keygen/sign/reshare via `github.com/decred/dcrd/dcrec/secp256k1/v4`)
- **P2P networking**: `github.com/libp2p/go-libp2p` + Kademlia DHT + GossipSub
- **Testing**: `github.com/stretchr/testify`

## Project Structure
```
signet/
├── lss/               # LSS protocol implementation
│   ├── keygen.go      # 3-round keygen
│   ├── sign.go        # 3-round signing + Signature type
│   ├── reshare.go     # 3-round reshare
│   ├── session.go     # Round interface + Run() loop
│   ├── config.go      # Config (party share + public key map)
│   ├── party.go       # PartyID, PartyIDSlice, Lagrange
│   ├── polynomial.go  # Shamir polynomial
│   ├── curve.go       # Scalar/Point wrappers
│   └── message.go     # Message wire type + Network interface
├── network/
│   ├── host.go        # libp2p host setup
│   ├── session.go     # SessionNetwork — implements lss.Network
│   ├── discovery.go   # Kademlia DHT peer discovery
│   └── identity.go    # EthereumAddress from libp2p pubkey
├── node/              # HTTP API + coordination + chain client
├── contracts/         # Solidity (Foundry)
├── circuits/          # Noir ZK circuit
├── network_test.go    # Integration tests
├── go.mod
└── CLAUDE.md
```

## Development Commands
```bash
go test ./...           # Run all tests
go test -run TestBasic  # Run specific test
go test -v ./...        # Verbose output
go build ./...          # Compile check
go vet ./...            # Static analysis
```

## Conventions
- Error handling: explicit `if err != nil { return err }`
- Context: pass `context.Context` as first arg for cancellation
- Logging: use `go.uber.org/zap`
- No global state — pass dependencies explicitly
