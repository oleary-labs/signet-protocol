// verify-ed25519 verifies a FROST-produced Ed25519 signature using Go's
// crypto/ed25519 standard library. This proves the threshold signature is
// indistinguishable from a single-signer Ed25519 signature.
//
// Usage:
//
//	go run ./cmd/verify-ed25519 \
//	  --pubkey 0x<32-byte-hex> \
//	  --message 0x<message-hex> \
//	  --signature 0x<64-byte-hex>
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	pubkeyHex := flag.String("pubkey", "", "Ed25519 public key (32 bytes, hex)")
	messageHex := flag.String("message", "", "message that was signed (hex)")
	signatureHex := flag.String("signature", "", "Ed25519 signature (64 bytes, hex)")
	flag.Parse()

	if *pubkeyHex == "" || *messageHex == "" || *signatureHex == "" {
		fmt.Fprintln(os.Stderr, "usage: verify-ed25519 --pubkey=0x... --message=0x... --signature=0x...")
		os.Exit(1)
	}

	pubkey, err := decodeHex(*pubkeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pubkey: %v\n", err)
		os.Exit(1)
	}
	if len(pubkey) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "pubkey must be %d bytes, got %d\n", ed25519.PublicKeySize, len(pubkey))
		os.Exit(1)
	}

	message, err := decodeHex(*messageHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid message: %v\n", err)
		os.Exit(1)
	}

	signature, err := decodeHex(*signatureHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid signature: %v\n", err)
		os.Exit(1)
	}
	if len(signature) != ed25519.SignatureSize {
		fmt.Fprintf(os.Stderr, "signature must be %d bytes, got %d\n", ed25519.SignatureSize, len(signature))
		os.Exit(1)
	}

	if ed25519.Verify(pubkey, message, signature) {
		fmt.Println("OK: Ed25519 signature is valid")
	} else {
		fmt.Println("FAIL: Ed25519 signature is invalid")
		os.Exit(1)
	}
}

func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	return hex.DecodeString(s)
}
