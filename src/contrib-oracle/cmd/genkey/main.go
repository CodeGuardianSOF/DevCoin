package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	var (
		outDir  string
		prefix  string
		format  string
		seedStr string
	)
	flag.StringVar(&outDir, "outdir", "./secrets", "directory to write key files")
	flag.StringVar(&prefix, "prefix", "oracle", "filename prefix for key files")
	flag.StringVar(&format, "format", "base64", "output format: base64 or hex")
	flag.StringVar(&seedStr, "seed", "", "optional existing private seed or key (base64 or hex) to derive keys")
	flag.Parse()

	var priv ed25519.PrivateKey
	if seedStr == "" {
		// generate random 32-byte seed
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			panic(err)
		}
		priv = ed25519.NewKeyFromSeed(seed)
	} else {
		// accept base64 or hex; 32-byte seed or 64-byte private key
		dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(seedStr))
		if err != nil {
			if db, err2 := hex.DecodeString(strings.TrimSpace(seedStr)); err2 == nil {
				dec = db
			} else {
				panic(fmt.Errorf("failed to decode seed: %v", err))
			}
		}
		switch len(dec) {
		case ed25519.SeedSize:
			priv = ed25519.NewKeyFromSeed(dec)
		case ed25519.PrivateKeySize:
			priv = ed25519.PrivateKey(dec)
		default:
			panic(fmt.Errorf("unexpected seed/private key length: %d", len(dec)))
		}
	}

	pub := priv.Public().(ed25519.PublicKey)
	seed := priv.Seed()

	enc := func(b []byte) string {
		switch strings.ToLower(format) {
		case "hex":
			return hex.EncodeToString(b)
		default:
			return base64.StdEncoding.EncodeToString(b)
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	privPath := filepath.Join(outDir, prefix+".key")
	pubPath := filepath.Join(outDir, prefix+".pub")
	seedPath := filepath.Join(outDir, prefix+".seed")

	// Write files (private key as full 64-byte key, plus seed for convenience)
	if err := os.WriteFile(privPath, []byte(enc(priv)), 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(seedPath, []byte(enc(seed)), 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(pubPath, []byte(enc(pub)), 0o644); err != nil {
		panic(err)
	}

	fmt.Printf("Written:\n  %s (private key, %s)\n  %s (seed, %s)\n  %s (public key, %s)\n\n", privPath, format, seedPath, format, pubPath, format)
	fmt.Printf("Values:\n  PRIVKEY=%s\n  SEED=%s\n  PUBKEY=%s\n", enc(priv), enc(seed), enc(pub))
}
