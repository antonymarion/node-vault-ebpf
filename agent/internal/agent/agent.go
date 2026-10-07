package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/dnsseed"
	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/ebpfloader"
	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/ebpfmaps"
	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/scrub"
	"github.com/node-vault-ebpf/node-vault-ebpf/agent/internal/vaultclient"
)

type Config struct {
	SocketPath string
	VaultAddr  string
	VaultToken string
	NoEBPF     bool
	WatchPID   int
	BPFObject  string
}

type Agent struct {
	cfg      Config
	vault    *vaultclient.Client
	reg      *scrub.Registry
	maps     *ebpfmaps.Manager
	ln       net.Listener
	mu       sync.Mutex
	hosts    map[string]struct{}
	passthru bool
	ctx      context.Context
	cancel   context.CancelFunc
}

type envelope struct {
	ID     string         `json:"id"`
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

type response struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  *struct {
		Message    string `json:"message"`
		StatusCode int    `json:"statusCode,omitempty"`
		Body       any    `json:"body,omitempty"`
	} `json:"error,omitempty"`
}

func New(cfg Config) (*Agent, error) {
	var loader ebpfmaps.Loader
	if cfg.NoEBPF {
		loader = ebpfmapsNoop{}
	} else {
		l, err := ebpfloader.New(cfg.BPFObject)
		if err != nil {
			log.Printf("ebpf loader warning: %v (continuing with best-effort)", err)
			loader = ebpfmapsNoop{}
		} else {
			loader = l
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	a := &Agent{
		cfg:   cfg,
		vault: vaultclient.New(vaultclient.Config{Endpoint: cfg.VaultAddr, Token: cfg.VaultToken}),
		reg:   scrub.NewRegistry(),
		maps:  ebpfmaps.New(loader),
		hosts: map[string]struct{}{},
		ctx:   ctx,
		cancel: cancel,
	}

	dnsseed.StartPeriodic(ctx, a.maps, a.listHosts, 30*time.Second)

	if cfg.WatchPID > 0 {
		_ = a.maps.WatchPID(uint32(cfg.WatchPID))
		if !cfg.NoEBPF {
			if err := a.maps.AttachNode(cfg.WatchPID); err != nil {
				log.Printf("initial attach pid=%d: %v", cfg.WatchPID, err)
			}
		}
	}
	return a, nil
}

type ebpfmapsNoop struct{}

func (ebpfmapsNoop) Available() bool                          { return false }
func (ebpfmapsNoop) PutSecret(_, _, _ string, _ uint16) error { return nil }
func (ebpfmapsNoop) PutDNS(net.IP, string) error              { return nil }
func (ebpfmapsNoop) WatchPID(uint32) error                    { return nil }
func (ebpfmapsNoop) AttachNode(int) error                     { return fmt.Errorf("ebpf disabled") }
func (ebpfmapsNoop) Counters() (map[string]uint64, error)     { return map[string]uint64{}, nil }
func (ebpfmapsNoop) Close() error                             { return nil }

func (a *Agent) listHosts() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.hosts))
	for h := range a.hosts {
		out = append(out, h)
	}
	return out
}

func (a *Agent) Serve() error {
	_ = os.Remove(a.cfg.SocketPath)
	ln, err := net.Listen("unix", a.cfg.SocketPath)
	if err != nil {
		return err
	}
	if err := os.Chmod(a.cfg.SocketPath, 0o660); err != nil {
		log.Printf("chmod socket: %v", err)
	}
	a.ln = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-a.ctx.Done():
				return nil
			default:
				return err
			}
		}
		go a.handleConn(conn)
	}
}

func (a *Agent) Close() error {
	a.cancel()
	if a.ln != nil {
		_ = a.ln.Close()
	}
	_ = os.Remove(a.cfg.SocketPath)
	return a.maps.Close()
}

func (a *Agent) handleConn(conn net.Conn) {
	defer conn.Close()
	dec := json.NewDecoder(conn)
	for {
		var env envelope
		if err := dec.Decode(&env); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("decode: %v", err)
			}
			return
		}
		res := a.dispatch(env)
		enc := json.NewEncoder(conn)
		if err := enc.Encode(res); err != nil {
			return
		}
	}
}

func (a *Agent) dispatch(env envelope) response {
	respondErr := func(msg string, status int, body any) response {
		r := response{ID: env.ID, OK: false}
		r.Error = &struct {
			Message    string `json:"message"`
			StatusCode int    `json:"statusCode,omitempty"`
			Body       any    `json:"body,omitempty"`
		}{Message: msg, StatusCode: status, Body: body}
		return r
	}

	switch env.Method {
	case "health":
		ctrs, _ := a.maps.Counters()
		return response{ID: env.ID, OK: true, Result: map[string]any{
			"ok":          true,
			"ebpf":        a.maps.EBPFEnabled() && !a.cfg.NoEBPF,
			"passthrough": a.passthru,
			"counters":    ctrs,
		}}
	case "bootstrap":
		return a.handleBootstrap(env)
	case "vault.request":
		return a.handleVaultRequest(env)
	case "vault.approleLogin":
		roleID, _ := env.Params["role_id"].(string)
		secretID, _ := env.Params["secret_id"].(string)
		mount, _ := env.Params["mount_point"].(string)
		raw, err := a.vault.AppRoleLogin(roleID, secretID, mount)
		if err != nil {
			return vaultErr(env.ID, err)
		}
		return response{ID: env.ID, OK: true, Result: jsonRaw(raw)}
	case "vault.kubernetesLogin":
		role, _ := env.Params["role"].(string)
		jwt, _ := env.Params["jwt"].(string)
		mount, _ := env.Params["mount_point"].(string)
		raw, err := a.vault.KubernetesLogin(role, jwt, mount)
		if err != nil {
			return vaultErr(env.ID, err)
		}
		return response{ID: env.ID, OK: true, Result: jsonRaw(raw)}
	case "dns.seed":
		host, _ := env.Params["host"].(string)
		a.rememberHost(host)
		_ = dnsseed.Seed(a.ctx, a.maps, []string{host})
		return response{ID: env.ID, OK: true, Result: map[string]any{"ok": true}}
	default:
		return respondErr("unknown method: "+env.Method, 0, nil)
	}
}

func (a *Agent) handleBootstrap(env envelope) response {
	endpoint, _ := env.Params["endpoint"].(string)
	token, _ := env.Params["token"].(string)
	ns, _ := env.Params["namespace"].(string)
	prefix, _ := env.Params["pathPrefix"].(string)
	api, _ := env.Params["apiVersion"].(string)
	passthru, _ := env.Params["passthrough"].(bool)
	a.passthru = passthru
	a.vault.Configure(vaultclient.Config{
		Endpoint:   endpoint,
		Token:      token,
		Namespace:  ns,
		PathPrefix: prefix,
		APIVersion: api,
	})
	if hosts, ok := env.Params["allowedHosts"].([]any); ok {
		for _, h := range hosts {
			if s, ok := h.(string); ok {
				a.rememberHost(s)
			}
		}
	}
	if pidF, ok := env.Params["pid"].(float64); ok && int(pidF) > 0 {
		pid := int(pidF)
		_ = a.maps.WatchPID(uint32(pid))
		if !a.cfg.NoEBPF && !passthru {
			if err := a.maps.AttachNode(pid); err != nil {
				log.Printf("attach node pid=%d: %v", pid, err)
			}
		}
	}
	_ = dnsseed.Seed(a.ctx, a.maps, a.listHosts())
	return response{ID: env.ID, OK: true, Result: map[string]any{"ok": true}}
}

func (a *Agent) handleVaultRequest(env envelope) response {
	method, _ := env.Params["method"].(string)
	path, _ := env.Params["path"].(string)
	if method == "" {
		method = "GET"
	}
	var jsonBody any
	if v, ok := env.Params["json"]; ok {
		jsonBody = v
	}
	qs := map[string]any{}
	if raw, ok := env.Params["qs"].(map[string]any); ok {
		qs = raw
	}
	headers := map[string]string{}
	if raw, ok := env.Params["headers"].(map[string]any); ok {
		for k, v := range raw {
			headers[k] = fmt.Sprint(v)
		}
	}
	host := a.firstHost(env.Params)
	raw, err := a.vault.Request(method, path, jsonBody, qs, headers)
	if err != nil {
		return vaultErr(env.ID, err)
	}

	scrubbing := strings.EqualFold(method, "GET") || strings.EqualFold(method, "LIST")
	if scrubFlag, ok := env.Params["scrub"].(bool); ok {
		scrubbing = scrubFlag
	}
	if a.passthru {
		scrubbing = false
	}
	if !scrubbing {
		return response{ID: env.ID, OK: true, Result: jsonRaw(raw)}
	}

	out, created, err := scrub.ScrubJSON(raw, host, 443, a.reg)
	if err != nil {
		return response{ID: env.ID, OK: false, Error: &struct {
			Message    string `json:"message"`
			StatusCode int    `json:"statusCode,omitempty"`
			Body       any    `json:"body,omitempty"`
		}{Message: err.Error()}}
	}
	if host != "" {
		a.rememberHost(host)
		_ = dnsseed.Seed(a.ctx, a.maps, []string{host})
	}
	if err := a.maps.SyncEntries(created); err != nil {
		log.Printf("sync eBPF secrets: %v", err)
	}
	return response{ID: env.ID, OK: true, Result: jsonRaw(out)}
}

func (a *Agent) firstHost(params map[string]any) string {
	if hosts, ok := params["allowedHosts"].([]any); ok && len(hosts) > 0 {
		if s, ok := hosts[0].(string); ok {
			return s
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for h := range a.hosts {
		return h
	}
	return ""
}

func (a *Agent) rememberHost(host string) {
	if host == "" {
		return
	}
	a.mu.Lock()
	a.hosts[host] = struct{}{}
	a.mu.Unlock()
}

func vaultErr(id string, err error) response {
	r := response{ID: id, OK: false}
	r.Error = &struct {
		Message    string `json:"message"`
		StatusCode int    `json:"statusCode,omitempty"`
		Body       any    `json:"body,omitempty"`
	}{Message: err.Error()}
	var api *vaultclient.APIError
	if errors.As(err, &api) {
		r.Error.StatusCode = api.StatusCode
		var body any
		_ = json.Unmarshal(api.Body, &body)
		r.Error.Body = body
		r.Error.Message = api.Message
	}
	return r
}

func jsonRaw(raw json.RawMessage) any {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return map[string]any{}
	}
	return v
}
