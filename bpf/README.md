# eBPF programs

`rewrite.bpf.c` attaches to Node.js BoringSSL `SSL_write` / `SSL_write_ex`, rewrites length-matched `nve:` placeholders, and tracks TCP destinations for host allowlisting.

## Build

```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include -I/usr/include/x86_64-linux-gnu \
  -c rewrite.bpf.c -o rewrite.bpf.o
```

Or build via `docker/Dockerfile.agent`, which compiles the object and embeds it at `/opt/node-vault-ebpf/rewrite.bpf.o`.

## Maps

| Map | Purpose |
|-----|---------|
| `secret_map` | placeholder → secret + allowed host |
| `dns_ip_map` | IPv4 → hostname |
| `conn_fd_map` | pid/fd → destination |
| `pid_last_conn` | last connect() destination per pid |
| `watched_pids` | PIDs subject to rewrite |
| `counters` | debug counters |
