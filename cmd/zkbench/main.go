// Command zkbench generates a test JWT, writes Noir circuit inputs (Prover.toml),
// and benchmarks the full ZK proof pipeline: compile -> execute -> prove -> verify.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const circuitDir = "circuits/jwt_auth"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// 1. Generate RSA-2048 key pair.
	fmt.Println("=== Generating RSA-2048 key pair ===")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate RSA key: %w", err)
	}

	// 2. Build JWT with test claims.
	claims := map[string]interface{}{
		"iss": "https://accounts.example.com",
		"sub": "user-abc-123",
		"aud": "signet-app.example.com",
		"azp": "client-id-456",
		"exp": 1893456000, // 2030-01-01
		"iat": 1709900000,
	}

	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(claims)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	// Sign with RSA-SHA256.
	hash := sha256.Sum256([]byte(signingInput))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return fmt.Errorf("sign JWT: %w", err)
	}

	jwt := signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes)
	fmt.Printf("JWT length: %d bytes\n", len(jwt))
	fmt.Printf("Signed data length: %d bytes\n", len(signingInput))

	// 3. Compute circuit inputs.
	modulus := privKey.PublicKey.N
	redcParam := new(big.Int).Lsh(big.NewInt(1), 2*2048+4)
	redcParam.Div(redcParam, modulus)
	sigBigInt := new(big.Int).SetBytes(sigBytes)

	modulusLimbs := splitBigIntToLimbs(modulus, 120, 18)
	redcLimbs := splitBigIntToLimbs(redcParam, 120, 18)
	sigLimbs := splitBigIntToLimbs(sigBigInt, 120, 18)

	// base64_decode_offset = header length + 1 (for the '.')
	base64DecodeOffset := len(headerB64) + 1

	// Pad signed data to MAX_DATA_LENGTH (1024).
	dataBytes := []byte(signingInput)
	dataStorage := make([]int, 1024)
	for i, b := range dataBytes {
		dataStorage[i] = int(b)
	}

	// Session pub — 33 bytes (dummy compressed secp256k1 key for benchmarking).
	sessionPub := make([]int, 33)
	sessionPub[0] = 0x02
	for i := 1; i < 33; i++ {
		sessionPub[i] = i
	}

	// 4. Write Prover.toml.
	proverPath := filepath.Join(circuitDir, "Prover.toml")
	fmt.Printf("Writing %s\n", proverPath)
	if err := writeProverToml(proverPath, proverData{
		DataStorage:        dataStorage,
		DataLen:            len(dataBytes),
		Base64DecodeOffset: base64DecodeOffset,
		ModulusLimbs:       modulusLimbs,
		RedcLimbs:          redcLimbs,
		SigLimbs:           sigLimbs,
		Iss:                claims["iss"].(string),
		Sub:                claims["sub"].(string),
		Exp:                uint64(claims["exp"].(int)),
		Aud:                claims["aud"].(string),
		Azp:                claims["azp"].(string),
		SessionPub:         sessionPub,
	}); err != nil {
		return fmt.Errorf("write Prover.toml: %w", err)
	}

	// 5. Run the benchmark pipeline.
	fmt.Println("\n=== Circuit Compilation ===")
	compileTime, err := timeCmd(circuitDir, "nargo", "compile", "--force")
	if err != nil {
		return fmt.Errorf("nargo compile: %w", err)
	}
	fmt.Printf("Compile time: %s\n", compileTime)

	fmt.Println("\n=== Witness Generation ===")
	execTime, err := timeCmd(circuitDir, "nargo", "execute", "bench_witness")
	if err != nil {
		return fmt.Errorf("nargo execute: %w", err)
	}
	fmt.Printf("Witness generation: %s\n", execTime)

	// bb prove with --write_vk (generates proof + VK in one step)
	fmt.Println("\n=== Proof Generation (UltraHonk) ===")
	proveTime, err := timeCmd(circuitDir, "bb", "prove",
		"-b", "target/jwt_auth.json",
		"-w", "target/bench_witness.gz",
		"-o", "target/proof",
		"--write_vk")
	if err != nil {
		return fmt.Errorf("bb prove: %w", err)
	}
	fmt.Printf("Proof generation: %s\n", proveTime)

	// bb verify -k target/proof/vk -p target/proof/proof -i target/proof/public_inputs
	fmt.Println("\n=== Proof Verification ===")
	verifyTime, err := timeCmd(circuitDir, "bb", "verify",
		"-k", "target/proof/vk",
		"-p", "target/proof/proof",
		"-i", "target/proof/public_inputs")
	if err != nil {
		return fmt.Errorf("bb verify: %w", err)
	}
	fmt.Printf("Verification: %s\n", verifyTime)

	// Check proof size.
	proofInfo, err := os.Stat(filepath.Join(circuitDir, "target", "proof", "proof"))
	if err == nil {
		fmt.Printf("\nProof size: %d bytes (%.1f KB)\n", proofInfo.Size(), float64(proofInfo.Size())/1024)
	}
	vkInfo, _ := os.Stat(filepath.Join(circuitDir, "target", "proof", "vk"))
	if vkInfo != nil {
		fmt.Printf("VK size: %d bytes (%.1f KB)\n", vkInfo.Size(), float64(vkInfo.Size())/1024)
	}

	// 6. Get circuit info.
	fmt.Println("\n=== Circuit Info ===")
	infoCmd := exec.Command("nargo", "info")
	infoCmd.Dir = circuitDir
	infoCmd.Stdout = os.Stdout
	infoCmd.Stderr = os.Stderr
	infoCmd.Run()

	// Print summary.
	fmt.Println("\n=== Summary ===")
	fmt.Printf("Compile:     %s\n", compileTime)
	fmt.Printf("Witness:     %s\n", execTime)
	fmt.Printf("Prove:       %s\n", proveTime)
	fmt.Printf("Verify:      %s\n", verifyTime)
	if proofInfo != nil {
		fmt.Printf("Proof size:  %d bytes\n", proofInfo.Size())
	}

	return nil
}

type proverData struct {
	DataStorage        []int
	DataLen            int
	Base64DecodeOffset int
	ModulusLimbs       []string
	RedcLimbs          []string
	SigLimbs           []string
	Iss                string
	Sub                string
	Exp                uint64
	Aud                string
	Azp                string
	SessionPub         []int
}

func writeProverToml(path string, d proverData) error {
	var b strings.Builder

	// Bare keys MUST come before any [table] sections in TOML,
	// otherwise they get captured inside the preceding table.
	b.WriteString(fmt.Sprintf("base64_decode_offset = %d\n", d.Base64DecodeOffset))
	b.WriteString(fmt.Sprintf("expected_exp = %d\n", d.Exp))
	b.WriteString(fmt.Sprintf("redc_params_limbs = [%s]\n", joinQuoted(d.RedcLimbs)))
	b.WriteString(fmt.Sprintf("signature_limbs = [%s]\n", joinQuoted(d.SigLimbs)))
	b.WriteString(fmt.Sprintf("pubkey_modulus_limbs = [%s]\n", joinQuoted(d.ModulusLimbs)))
	b.WriteString(fmt.Sprintf("session_pub = [%s]\n\n", joinInts(d.SessionPub)))

	// Table sections for BoundedVec types.
	b.WriteString("[data]\n")
	b.WriteString(fmt.Sprintf("storage = [%s]\n", joinInts(d.DataStorage)))
	b.WriteString(fmt.Sprintf("len = %d\n\n", d.DataLen))
	writeBoundedVec(&b, "expected_iss", d.Iss, 128)
	writeBoundedVec(&b, "expected_sub", d.Sub, 128)
	writeBoundedVec(&b, "expected_aud", d.Aud, 128)
	writeBoundedVec(&b, "expected_azp", d.Azp, 128)

	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeBoundedVec(b *strings.Builder, name, value string, maxLen int) {
	storage := make([]int, maxLen)
	for i, c := range []byte(value) {
		storage[i] = int(c)
	}
	b.WriteString(fmt.Sprintf("[%s]\n", name))
	b.WriteString(fmt.Sprintf("storage = [%s]\n", joinInts(storage)))
	b.WriteString(fmt.Sprintf("len = %d\n\n", len(value)))
}

func splitBigIntToLimbs(n *big.Int, chunkBits, numChunks int) []string {
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), uint(chunkBits)), big.NewInt(1))
	limbs := make([]string, numChunks)
	tmp := new(big.Int).Set(n)
	for i := 0; i < numChunks; i++ {
		limb := new(big.Int).And(tmp, mask)
		limbs[i] = limb.Text(10) // decimal — matching noir-jwt JS helper
		tmp.Rsh(tmp, uint(chunkBits))
	}
	return limbs
}

func joinInts(vals []int) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, ", ")
}

func joinQuoted(vals []string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = fmt.Sprintf("\"%s\"", v)
	}
	return strings.Join(parts, ", ")
}

func timeCmd(dir, name string, args ...string) (time.Duration, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	start := time.Now()
	err := cmd.Run()
	return time.Since(start), err
}
