# Threat model

## Goals

- After compromise of a Node.js application process (RCE, dependency malware, prompt-injected agent), the attacker must not find usable Vault secret values in process memory, environment, or files the app can read.
- Secrets may only be emitted on the wire toward explicitly allowed TLS destinations.

## Trust boundaries

| Component | Trust |
|-----------|--------|
| Node app + npm client | **Untrusted** after RCE |
| Unix socket to agent | Trusted local IPC; mode `0600`/`0660`, same host |
| Agent process | **Trusted** (root / CAP_BPF) |
| Kernel eBPF maps | **Trusted** |
| Vault server | Trusted IdP / secret store |

## In scope (v1)

- Scrubbing string leaves in Vault JSON responses (`read` / `LIST`).
- Length-matched `nve:` placeholders.
- eBPF uprobe rewrite on Node BoringSSL `SSL_write` / `SSL_write_ex`.
- Destination host filtering via DNS seeding + `connect` tracking.

## Out of scope (v1)

- Compromised agent/root/kernel.
- Secrets used outside outbound TLS (local crypto, non-TLS protocols, logging side channels once rewritten on the wire).
- Kubernetes admission webhooks / shadow Secrets.
- Preventing the app from sending placeholders to unallowed hosts (they arrive as useless placeholders — by design).

## Weaker drop-in mode

If the app constructs the client with `token:` / `VAULT_TOKEN`, the token exists briefly in Node before bootstrap handoff and wipe. Prefer configuring Vault credentials **only** on the agent.

## Supply chain

The npm package ships **JavaScript only**. The agent and BPF object are distributed as a separate binary/image. There is no install-time script that loads eBPF into the host kernel.
