package main

import (
	"log"
	"os"
	"strings"

	"github.com/CodeGuardianSOF/DevCoin/src/contrib-oracle/internal/server"
)

func main() {
	addr := getEnv("ORACLE_ADDR", ":8090")
	secret := mustEnv("GITHUB_WEBHOOK_SECRET")
	api := getEnv("BLOCKCHAIN_API", "http://127.0.0.1:8080")
	repos := getEnv("REPO_WHITELIST", "")

	s, err := server.New(addr, secret, api, parseList(repos))
	if err != nil {
		log.Fatal(err)
	}
	if err := s.Start(); err != nil {
		log.Fatal(err)
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("missing required env: %s", key)
	}
	return v
}

func parseList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
