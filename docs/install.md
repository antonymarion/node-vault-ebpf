# Install

## Agent (Linux)

### Docker

```bash
docker build -f docker/Dockerfile.agent -t node-vault-ebpf-agent .
docker run --privileged --pid=host \
  -e VAULT_ADDR=http://vault:8200 \
  -e VAULT_TOKEN=s.xxx \
  -v /var/run/node-vault-ebpf:/var/run \
  node-vault-ebpf-agent
```

### Binary

Build on Linux:

```bash
# BPF object
clang -O2 -g -target bpf -I bpf/headers -I/usr/include \
  -c bpf/rewrite.bpf.c -o bpf/rewrite.bpf.o

cd agent && go build -o node-vault-ebpf-agent ./cmd/node-vault-ebpf-agent
sudo NVE_BPF_OBJECT=../bpf/rewrite.bpf.o ./node-vault-ebpf-agent
```

Flags:

- `-socket` — Unix socket (default `/var/run/node-vault-ebpf.sock`)
- `-vault-addr` / `-vault-token` — or use env
- `-no-ebpf` — scrub + proxy only (tests)
- `-pid` — pre-attach a Node PID

## npm client

```bash
npm install node-vault-ebpf
```

Point `agentSocket` at the agent socket. See package README.
