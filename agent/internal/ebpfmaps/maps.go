package ebpfmaps

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/scrub"
)

const MaxSecretLen = 256
const MaxHostLen = 128

// Manager syncs secret/DNS/PID state. When the real eBPF collection is unavailable,
// it keeps an in-memory mirror used by tests and --no-ebpf mode.
type Manager struct {
	mu      sync.RWMutex
	secrets map[string]scrub.Entry
	dns     map[uint32]string
	pids    map[uint32]struct{}
	loader  Loader
}

// Loader is implemented by the real eBPF collection.
type Loader interface {
	Available() bool
	PutSecret(placeholder, secret, host string, port uint16) error
	PutDNS(ip net.IP, host string) error
	WatchPID(pid uint32) error
	AttachNode(pid int) error
	Counters() (map[string]uint64, error)
	Close() error
}

type noopLoader struct{}

func (noopLoader) Available() bool                                    { return false }
func (noopLoader) PutSecret(_, _, _ string, _ uint16) error           { return nil }
func (noopLoader) PutDNS(net.IP, string) error                        { return nil }
func (noopLoader) WatchPID(uint32) error                              { return nil }
func (noopLoader) AttachNode(int) error                               { return fmt.Errorf("ebpf disabled") }
func (noopLoader) Counters() (map[string]uint64, error)               { return map[string]uint64{}, nil }
func (noopLoader) Close() error                                       { return nil }

func New(loader Loader) *Manager {
	if loader == nil {
		loader = noopLoader{}
	}
	return &Manager{
		secrets: make(map[string]scrub.Entry),
		dns:     make(map[uint32]string),
		pids:    make(map[uint32]struct{}),
		loader:  loader,
	}
}

func (m *Manager) EBPFEnabled() bool {
	return m.loader.Available()
}

func (m *Manager) SyncEntries(entries []scrub.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range entries {
		if len(e.Placeholder) > MaxSecretLen || len(e.Secret) > MaxSecretLen {
			return fmt.Errorf("secret/placeholder exceeds %d bytes", MaxSecretLen)
		}
		if len(e.Placeholder) != len(e.Secret) {
			return fmt.Errorf("length mismatch placeholder=%d secret=%d", len(e.Placeholder), len(e.Secret))
		}
		m.secrets[e.Placeholder] = e
		if err := m.loader.PutSecret(e.Placeholder, e.Secret, e.AllowedHost, e.Port); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) PutDNS(host string, ips []net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		key := binary.BigEndian.Uint32(v4)
		m.dns[key] = host
		if err := m.loader.PutDNS(v4, host); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) WatchPID(pid uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pids[pid] = struct{}{}
	return m.loader.WatchPID(pid)
}

func (m *Manager) AttachNode(pid int) error {
	return m.loader.AttachNode(pid)
}

func (m *Manager) Counters() (map[string]uint64, error) {
	return m.loader.Counters()
}

func (m *Manager) Close() error {
	return m.loader.Close()
}

// LookupSecret is for tests / diagnostics (never expose to Node client).
func (m *Manager) LookupSecret(placeholder string) (scrub.Entry, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.secrets[placeholder]
	return e, ok
}
