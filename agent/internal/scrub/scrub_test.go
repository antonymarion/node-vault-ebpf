package scrub

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlaceholderLengthMatch(t *testing.T) {
	secret := "super-secret-bearer-token-12345"
	ph, err := PlaceholderFor(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(ph) != len(secret) {
		t.Fatalf("len placeholder=%d secret=%d ph=%q", len(ph), len(secret), ph)
	}
	if !strings.HasPrefix(ph, Prefix) {
		t.Fatalf("prefix: %q", ph)
	}
}

func TestScrubKVv2Shape(t *testing.T) {
	raw := []byte(`{
		"request_id":"abc",
		"lease_id":"",
		"renewable":false,
		"lease_duration":0,
		"data":{
			"data":{"token":"super-secret-bearer-token-12345"},
			"metadata":{"version":1,"destroyed":false}
		}
	}`)
	reg := NewRegistry()
	out, created, err := ScrubJSON(raw, "httpbin.org", 443, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("created=%d", len(created))
	}
	var body map[string]any
	if err := json.Unmarshal(out, &body); err != nil {
		t.Fatal(err)
	}
	data := body["data"].(map[string]any)
	inner := data["data"].(map[string]any)
	token := inner["token"].(string)
	if token != created[0].Placeholder {
		t.Fatalf("token=%q placeholder=%q", token, created[0].Placeholder)
	}
	if len(token) != len("super-secret-bearer-token-12345") {
		t.Fatalf("length mismatch")
	}
	meta := data["metadata"].(map[string]any)
	if meta["version"].(float64) != 1 {
		t.Fatalf("metadata altered")
	}
	if strings.Contains(string(out), "super-secret") {
		t.Fatalf("secret leaked into scrubbed JSON")
	}
}

func TestScrubKVv1Shape(t *testing.T) {
	raw := []byte(`{"data":{"password":"hunter2xx"},"lease_duration":100}`)
	reg := NewRegistry()
	out, created, err := ScrubJSON(raw, "", 0, reg)
	if err != nil {
		t.Fatal(err)
	}
	if len(created) != 1 {
		t.Fatalf("created=%d", len(created))
	}
	if strings.Contains(string(out), "hunter2xx") {
		t.Fatal("secret present")
	}
}
