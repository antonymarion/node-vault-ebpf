# Architecture

## Components

1. **npm client (`node-vault-ebpf`)** — factory API compatible with `node-vault`. Speaks newline-delimited JSON over a Unix socket.
2. **Agent (`node-vault-ebpf-agent`)** — Go process holding Vault credentials, scrubbing responses, syncing eBPF maps, attaching uprobes to Node PIDs.
3. **eBPF programs (`bpf/rewrite.bpf.c`)** — `SSL_write` rewrite, `sys_enter_connect` tracking, optional `udp_recvmsg` hook; userspace DNS seeding fills `dns_ip_map`.

## IPC methods

| Method | Purpose |
|--------|---------|
| `bootstrap` | Endpoint/token/namespace handoff, watch PID, allowed hosts |
| `vault.request` | Generic Vault HTTP; GET/LIST scrubbed by default |
| `vault.approleLogin` / `vault.kubernetesLogin` | Auth; token retained in agent only |
| `health` | Liveness + eBPF counters |
| `dns.seed` | Force-resolve a hostname into `dns_ip_map` |

## Placeholder format

- Prefix: `nve:`
- Total length equals the original secret length (required for in-place `bpf_probe_write_user`).
- Mapped in `secret_map` with optional `allowed_host` + port.

## Host filter chain

1. Agent resolves `allowedHosts` and writes `dns_ip_map`.
2. `sys_enter_connect` records `pid → last destination`.
3. On `SSL_write`, if buffer contains a known placeholder and last destination IP maps to the allowed host, rewrite; else leave placeholder.

## Related: platformatic/node-epbf (`node-ebpf`)

Evaluated [platformatic/node-epbf](https://github.com/platformatic/node-epbf) (npm: `node-ebpf`, Apache-2.0): Node native bindings for libbpf (load object, maps, kprobe/tracepoint/XDP, ringbuf).

**Not adopted for v1:**

- Loading eBPF from the **app** Node process would require `CAP_BPF` on the untrusted workload — breaks the threat model.
- Documented attach API has **no uprobe** support (`attachKprobe` / `attachTracepoint` / `attachXdp` / `attachRawTracepoint` only). Our TLS rewrite needs `SSL_write` uprobes on the Node binary.
- `npm install` runs `node-gyp rebuild` — we keep eBPF out of the published client tarball on purpose.

It could later back a **Node-written privileged agent** (instead of Go) for map sync + non-uprobe hooks, if uprobe attach lands upstream. Until then the Go + cilium/ebpf loader remains the control plane.
