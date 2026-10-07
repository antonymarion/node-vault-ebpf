//go:build linux && !nve_no_ebpf

package ebpfloader

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/ebpfmaps"
)

const (
	maxSecretLen = 256
	maxHostLen   = 128
)

type placeholderKey struct {
	Data [maxSecretLen]byte
}

type secretEntry struct {
	SecretLen uint32
	HostLen   uint32
	Port      uint16
	_         uint16
	Secret    [maxSecretLen]byte
	Host      [maxHostLen]byte
}

type linuxLoader struct {
	mu       sync.Mutex
	coll     *ebpf.Collection
	links    []link.Link
	objPath  string
	secret   *ebpf.Map
	dns      *ebpf.Map
	pids     *ebpf.Map
	counters *ebpf.Map
}

func New(objectPath string) (ebpfmaps.Loader, error) {
	_ = rlimit.RemoveMemlock()

	l := &linuxLoader{objPath: objectPath}
	if objectPath == "" {
		objectPath = defaultObjectPath()
		l.objPath = objectPath
	}
	if _, err := os.Stat(objectPath); err != nil {
		return l.initStandaloneMaps()
	}
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	l.coll = coll
	l.secret = coll.Maps["secret_map"]
	l.dns = coll.Maps["dns_ip_map"]
	l.pids = coll.Maps["watched_pids"]
	l.counters = coll.Maps["counters"]
	if l.secret == nil || l.dns == nil || l.pids == nil {
		coll.Close()
		return nil, fmt.Errorf("missing required maps in %s", objectPath)
	}
	if prog := coll.Programs["handle_connect_enter"]; prog != nil {
		lnk, err := link.Tracepoint("syscalls", "sys_enter_connect", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: connect tracepoint: %v\n", err)
		} else {
			l.links = append(l.links, lnk)
		}
	}
	if prog := coll.Programs["handle_udp_recvmsg"]; prog != nil {
		lnk, err := link.Kprobe("udp_recvmsg", prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: udp_recvmsg kprobe: %v\n", err)
		} else {
			l.links = append(l.links, lnk)
		}
	}
	return l, nil
}

func (l *linuxLoader) initStandaloneMaps() (ebpfmaps.Loader, error) {
	var err error
	l.secret, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(binary.Size(placeholderKey{})),
		ValueSize:  uint32(binary.Size(secretEntry{})),
		MaxEntries: 4096,
	})
	if err != nil {
		return nil, err
	}
	l.dns, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  maxHostLen,
		MaxEntries: 8192,
	})
	if err != nil {
		return nil, err
	}
	l.pids, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  1,
		MaxEntries: 1024,
	})
	if err != nil {
		return nil, err
	}
	l.counters, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 8,
	})
	if err != nil {
		return nil, err
	}
	return l, nil
}

func defaultObjectPath() string {
	if p := os.Getenv("NVE_BPF_OBJECT"); p != "" {
		return p
	}
	candidates := []string{
		"/opt/node-vault-ebpf/rewrite.bpf.o",
		filepath.Join("bpf", "rewrite.bpf.o"),
		filepath.Join("..", "bpf", "rewrite.bpf.o"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return candidates[0]
}

func (l *linuxLoader) Available() bool { return l.secret != nil }

func (l *linuxLoader) PutSecret(placeholder, secret, host string, port uint16) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(placeholder) != len(secret) || len(placeholder) > maxSecretLen {
		return fmt.Errorf("invalid placeholder/secret length")
	}
	var key placeholderKey
	copy(key.Data[:], placeholder)
	var val secretEntry
	val.SecretLen = uint32(len(secret))
	val.HostLen = uint32(len(host))
	val.Port = port
	copy(val.Secret[:], secret)
	copy(val.Host[:], host)
	return l.secret.Put(key, val)
}

func (l *linuxLoader) PutDNS(ip net.IP, host string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	key := binary.BigEndian.Uint32(v4)
	var val struct{ Data [maxHostLen]byte }
	copy(val.Data[:], host)
	return l.dns.Put(key, val)
}

func (l *linuxLoader) WatchPID(pid uint32) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var one uint8 = 1
	return l.pids.Put(pid, one)
}

func (l *linuxLoader) AttachNode(pid int) error {
	if err := l.WatchPID(uint32(pid)); err != nil {
		return err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.coll == nil {
		return fmt.Errorf("no eBPF object loaded (build/load rewrite.bpf.o); maps-only mode active")
	}
	exe := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exe)
	if err != nil {
		return fmt.Errorf("readlink %s: %w", exe, err)
	}
	target = strings.Split(target, " ")[0]
	ex, err := link.OpenExecutable(target)
	if err != nil {
		return err
	}
	attached := 0
	for _, sym := range []string{"SSL_write", "SSL_write_ex"} {
		progName := "handle_ssl_write"
		if sym == "SSL_write_ex" {
			progName = "handle_ssl_write_ex"
		}
		prog := l.coll.Programs[progName]
		if prog == nil {
			continue
		}
		lnk, err := ex.Uprobe(sym, prog, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warn: uprobe %s on %s: %v\n", sym, target, err)
			continue
		}
		l.links = append(l.links, lnk)
		attached++
		fmt.Fprintf(os.Stderr, "attached %s on %s (pid=%d)\n", sym, target, pid)
	}
	if attached == 0 {
		return fmt.Errorf("failed to attach any SSL_write uprobe on %s", target)
	}
	return nil
}

func (l *linuxLoader) Counters() (map[string]uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	names := []string{"ssl_enter", "rewrite", "host_mismatch", "dns_hit", "no_secret"}
	out := map[string]uint64{}
	if l.counters == nil {
		return out, nil
	}
	for i, name := range names {
		var v uint64
		key := uint32(i)
		if err := l.counters.Lookup(&key, &v); err != nil {
			continue
		}
		out[name] = v
	}
	return out, nil
}

func (l *linuxLoader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, lnk := range l.links {
		_ = lnk.Close()
	}
	l.links = nil
	if l.coll != nil {
		l.coll.Close()
		l.coll = nil
		return nil
	}
	if l.secret != nil {
		l.secret.Close()
	}
	if l.dns != nil {
		l.dns.Close()
	}
	if l.pids != nil {
		l.pids.Close()
	}
	if l.counters != nil {
		l.counters.Close()
	}
	return nil
}
