package dnsseed

import (
	"context"
	"net"
	"time"

	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/ebpfmaps"
)

// Seed resolves hostnames and pushes A records into the eBPF dns_ip_map.
// This complements in-kernel DNS capture for Docker/host environments where
// udp_recvmsg visibility is limited.
func Seed(ctx context.Context, m *ebpfmaps.Manager, hosts []string) error {
	resolver := net.DefaultResolver
	for _, host := range hosts {
		if host == "" || host == "*" {
			continue
		}
		ips, err := resolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			continue
		}
		if err := m.PutDNS(host, ips); err != nil {
			return err
		}
	}
	return nil
}

// StartPeriodic refreshes DNS mappings until ctx is cancelled.
func StartPeriodic(ctx context.Context, m *ebpfmaps.Manager, hostsFn func() []string, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	go func() {
		defer t.Stop()
		for {
			_ = Seed(ctx, m, hostsFn())
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}
