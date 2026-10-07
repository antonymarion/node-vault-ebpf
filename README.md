<p align="center">
  <img src="docs/logo.jpg" width="128" height="128" alt="node-vault-ebpf">
</p>

# node-vault-ebpf

Drop-in [`node-vault`](https://github.com/nodevault/node-vault) client + privileged Linux eBPF agent so **Node.js processes never hold real Vault secrets in memory**.

Inspired by the Kloak model (placeholders in userspace, real values injected in-kernel at TLS write time). This is an **independent MIT implementation** — not a fork of Kloak (AGPL).

## How it works

1. Your app calls `vault.read()` through `node-vault-ebpf`.
2. The privileged **agent** fetches the secret from HashiCorp Vault.
3. The agent returns a **length-matched** placeholder (`nve:...`) and stores the real value in an eBPF map.
4. When the app sends HTTPS traffic containing the placeholder, an uprobe on Node’s BoringSSL `SSL_write` rewrites it to the real secret — **only** if the destination host is allowed.

```
Node app  --IPC-->  agent (Vault + eBPF maps)  --uprobe-->  TLS rewrite
   ^                                                         |
   +---- sees only nve: placeholders ------------------------+
```

## Requirements

- Linux amd64/arm64 (eBPF). Windows/macOS: develop via Docker.
- Privileges for the agent: `CAP_BPF` / `CAP_PERFMON` / `CAP_SYS_ADMIN`, or `--privileged` in Docker.
- Node.js ≥ 18 for the npm client.

## Quick start (Docker Compose)

```bash
docker compose -f docker/docker-compose.yml up --build
```

The demo app logs the placeholder, then calls `httpbin.org` (allowed) and `postman-echo.com` (blocked).

## Install client

[![npm](https://img.shields.io/npm/v/node-vault-ebpf.svg)](https://www.npmjs.com/package/node-vault-ebpf)

```bash
npm install node-vault-ebpf
```

Install/run the agent separately (release binary or container). **Never** load eBPF from an npm `postinstall` script.

```js
const vault = require('node-vault-ebpf')({
  agentSocket: '/var/run/node-vault-ebpf.sock',
  allowedHosts: ['api.example.com'],
  // Prefer VAULT_TOKEN on the agent. Passing token here is weaker drop-in mode.
});

const res = await vault.read('secret/data/demo');
// res.data.data.* contains nve: placeholders only
```

## Repository layout

| Path | Role |
|------|------|
| `packages/node-vault-ebpf` | npm publishable client |
| `agent/` | Go privileged agent |
| `bpf/` | eBPF CO-RE programs |
| `docker/` | Agent image + compose PoC |
| `examples/basic-httpbin` | End-to-end demo |
| `docs/` | Threat model & architecture |

## Security

See [docs/threat-model.md](docs/threat-model.md). Summary:

- Protects against **RCE inside the Node process** exfiltrating Vault secrets from memory/env.
- Does **not** protect against a compromised root/agent or kernel.
- Host allowlisting is required to stop sending rewritten secrets to attacker-controlled HTTPS endpoints.

## Links

- GitHub: https://github.com/antonymarion/node-vault-ebpf
- npm: [node-vault-ebpf](https://www.npmjs.com/package/node-vault-ebpf)
- Cornerstone: [corner-stone.ai](https://corner-stone.ai/#open-source)

## License

MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
