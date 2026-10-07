package agent

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/scrub"
)

func TestPlaceholderRoundTripLength(t *testing.T) {
	secret := "super-secret-bearer-token-12345"
	ph, err := scrub.PlaceholderFor(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(ph) != len(secret) {
		t.Fatalf("len %d != %d", len(ph), len(secret))
	}
}

func TestHealthDispatch(t *testing.T) {
	a, err := New(Config{
		SocketPath: "",
		VaultAddr:  "http://127.0.0.1:8200",
		NoEBPF:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	res := a.dispatch(envelope{ID: "1", Method: "health", Params: map[string]any{}})
	if !res.OK {
		t.Fatalf("health not ok: %+v", res)
	}
	raw, _ := json.Marshal(res.Result)
	if string(raw) == "" {
		t.Fatal("empty result")
	}
}

func TestServeTCPBootstrap(t *testing.T) {
	// Use a temp unix-like path that works as TCP via custom serve helper — skip on platforms
	// without unix sockets by using a short dial test against health only through dispatch.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	a, err := New(Config{NoEBPF: true, VaultAddr: "http://127.0.0.1:8200"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		a.handleConn(conn)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)
	if err := enc.Encode(envelope{ID: "h1", Method: "health"}); err != nil {
		t.Fatal(err)
	}
	var res response
	if err := dec.Decode(&res); err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("not ok: %+v", res)
	}
	_ = conn.Close()
	<-done
}
