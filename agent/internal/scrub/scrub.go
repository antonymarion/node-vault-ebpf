package scrub

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"strings"
)

const Prefix = "nve:"

// Entry is stored in the eBPF secret map / agent registry.
type Entry struct {
	Placeholder string
	Secret      string
	AllowedHost string
	Port        uint16
}

// Registry maps placeholders to secrets for eBPF sync.
type Registry struct {
	entries map[string]Entry
}

func NewRegistry() *Registry {
	return &Registry{entries: make(map[string]Entry)}
}

func (r *Registry) All() []Entry {
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}

func (r *Registry) Put(e Entry) {
	r.entries[e.Placeholder] = e
}

// ScrubJSON replaces string leaf values with length-matched placeholders.
// Returns scrubbed JSON bytes and new entries.
func ScrubJSON(raw []byte, allowedHost string, port uint16, reg *Registry) ([]byte, []Entry, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, nil, err
	}
	var created []Entry
	scrubbed := walk(v, allowedHost, port, reg, &created)
	out, err := json.Marshal(scrubbed)
	return out, created, err
}

func walk(v any, host string, port uint16, reg *Registry, created *[]Entry) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			// Preserve metadata objects that are not secret payloads.
			if k == "metadata" || k == "request_id" || k == "lease_id" || k == "warnings" {
				out[k] = child
				continue
			}
			out[k] = walk(child, host, port, reg, created)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = walk(child, host, port, reg, created)
		}
		return out
	case string:
		if t == "" || strings.HasPrefix(t, Prefix) {
			return t
		}
		ph, err := PlaceholderFor(t)
		if err != nil {
			return t
		}
		e := Entry{Placeholder: ph, Secret: t, AllowedHost: host, Port: port}
		reg.Put(e)
		*created = append(*created, e)
		return ph
	default:
		return v
	}
}

// PlaceholderFor returns a placeholder with exactly len(secret) bytes.
func PlaceholderFor(secret string) (string, error) {
	n := len(secret)
	if n < len(Prefix)+1 {
		return "", fmt.Errorf("secret too short for placeholder prefix")
	}
	need := n - len(Prefix)
	// base32 without padding, lowercase-ish using std encoding then trim
	buf := make([]byte, need+8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	enc := strings.TrimRight(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), "=")
	enc = strings.ToUpper(enc)
	if len(enc) < need {
		enc = enc + strings.Repeat("0", need-len(enc))
	}
	return Prefix + enc[:need], nil
}
