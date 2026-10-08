<p align="center">
  <img src="./logo.png" width="128" height="128" alt="node-vault-ebpf">
</p>

# node-vault-ebpf

Drop-in [node-vault](https://github.com/nodevault/node-vault)-compatible client that keeps HashiCorp Vault secrets **out of Node.js process memory**.

Real secret values live in kernel eBPF maps managed by a privileged Linux agent. The Node process only sees length-matched placeholders (`nve:...`). When the app sends those placeholders over TLS, an uprobe on Node's BoringSSL `SSL_write` rewrites them to the real values — only for allowed destination hosts.

## Install

```bash
npm install node-vault-ebpf
```

You also need the privileged agent (Linux only). See the [root README](../../README.md) for Docker / binary install.

## Usage

```js
const vault = require('node-vault-ebpf')({
  endpoint: 'http://127.0.0.1:8200',
  // Prefer configuring VAULT_TOKEN on the agent. Passing token here is the weaker drop-in mode.
  agentSocket: '/var/run/node-vault-ebpf.sock',
  allowedHosts: ['httpbin.org'],
});

const secret = await vault.read('secret/data/demo');
// secret.data.data.token === 'nve:....' (placeholder, same length as real value)
```

## Security notes

- Prefer agent-side `VAULT_ADDR` / `VAULT_TOKEN` (or AppRole). Avoid putting the Vault token in the Node process when possible.
- Placeholders are only rewritten on outbound TLS for hosts listed in `allowedHosts` (or per-request options).
- This is not a substitute for patching RCE; it limits secret blast radius after compromise of the app process.

## License

MIT
