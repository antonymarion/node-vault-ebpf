package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/agent"
)

func main() {
	socket := flag.String("socket", envOr("NVE_SOCKET", "/var/run/node-vault-ebpf.sock"), "Unix socket path")
	vaultAddr := flag.String("vault-addr", envOr("VAULT_ADDR", "http://127.0.0.1:8200"), "Vault address")
	vaultToken := flag.String("vault-token", os.Getenv("VAULT_TOKEN"), "Vault token (prefer env)")
	noEbpf := flag.Bool("no-ebpf", envOr("NVE_NO_EBPF", "") == "1", "Disable eBPF attach (scrub+proxy only)")
	pid := flag.Int("pid", 0, "Node PID to watch (0 = learn from client bootstrap)")
	flag.Parse()

	cfg := agent.Config{
		SocketPath: *socket,
		VaultAddr:  *vaultAddr,
		VaultToken: *vaultToken,
		NoEBPF:     *noEbpf,
		WatchPID:   *pid,
	}

	a, err := agent.New(cfg)
	if err != nil {
		log.Fatalf("agent init: %v", err)
	}
	defer a.Close()

	go func() {
		if err := a.Serve(); err != nil {
			log.Fatalf("serve: %v", err)
		}
	}()

	log.Printf("node-vault-ebpf agent listening on %s (ebpf=%v)", cfg.SocketPath, !cfg.NoEBPF)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	log.Printf("shutting down")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
