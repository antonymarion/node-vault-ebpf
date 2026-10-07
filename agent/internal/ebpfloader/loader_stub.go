//go:build !linux || nve_no_ebpf

package ebpfloader

import (
	"fmt"
	"net"

	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/ebpfmaps"
)

// New returns a stub loader when not on Linux or when built with nve_no_ebpf.
func New(_ string) (ebpfmaps.Loader, error) {
	return stub{}, nil
}

type stub struct{}

func (stub) Available() bool                          { return false }
func (stub) PutSecret(_, _, _ string, _ uint16) error { return nil }
func (stub) PutDNS(net.IP, string) error              { return nil }
func (stub) WatchPID(uint32) error                    { return nil }
func (stub) AttachNode(int) error {
	return fmt.Errorf("eBPF loader not available on this build/platform")
}
func (stub) Counters() (map[string]uint64, error) { return map[string]uint64{}, nil }
func (stub) Close() error                         { return nil }
