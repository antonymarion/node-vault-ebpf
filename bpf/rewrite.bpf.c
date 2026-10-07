// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SECRET_LEN 256
#define MAX_HOST_LEN 128
#define MAX_SCAN 256
#define PREFIX_LEN 4
#define AF_INET 2

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct placeholder_key {
	__u8 data[MAX_SECRET_LEN];
};

struct secret_entry {
	__u32 secret_len;
	__u32 host_len;
	__u16 port;
	__u16 pad;
	__u8 secret[MAX_SECRET_LEN];
	__u8 host[MAX_HOST_LEN];
};

struct conn_info {
	__u32 daddr;
	__u16 dport;
	__u16 pad;
};

struct host_name {
	__u8 data[MAX_HOST_LEN];
};

struct sockaddr_in_min {
	__u16 sin_family;
	__be16 sin_port;
	__be32 sin_addr;
	__u8 sin_zero[8];
};

/* Large buffers live here — BPF stack is limited to 512 bytes. */
struct scratch {
	char local[MAX_SCAN];
	struct placeholder_key key;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct placeholder_key);
	__type(value, struct secret_entry);
} secret_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct host_name);
} dns_ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);
	__type(value, struct conn_info);
} conn_fd_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u8);
} watched_pids SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct conn_info);
} pid_last_conn SEC(".maps");

enum {
	CNT_SSL_ENTER = 0,
	CNT_REWRITE = 1,
	CNT_HOST_MISMATCH = 2,
	CNT_DNS_HIT = 3,
	CNT_NO_SECRET = 4,
	CNT_MAX = 8,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

static __always_inline int host_allowed(struct secret_entry *ent, __u32 daddr)
{
	struct host_name *hn;
	int i;

	if (ent->host_len == 0)
		return 1;
	if (daddr == 0)
		return 0;
	hn = bpf_map_lookup_elem(&dns_ip_map, &daddr);
	if (!hn)
		return 0;
	bump(CNT_DNS_HIT);
#pragma unroll
	for (i = 0; i < MAX_HOST_LEN; i++) {
		if ((__u32)i >= ent->host_len)
			return 1;
		if (hn->data[i] != ent->host[i])
			return 0;
		if (hn->data[i] == 0)
			return 1;
	}
	return 1;
}

static __always_inline int try_rewrite(char *buf, __u32 buflen, __u32 pid)
{
	__u32 zero = 0;
	struct scratch *sc;
	struct conn_info *last;
	__u32 daddr = 0;
	int off;

	sc = bpf_map_lookup_elem(&heap, &zero);
	if (!sc)
		return 0;
	if (buflen < PREFIX_LEN + 8)
		return 0;
	if (buflen > MAX_SCAN)
		buflen = MAX_SCAN;
	__builtin_memset(sc->local, 0, sizeof(sc->local));
	if (bpf_probe_read_user(sc->local, buflen, buf) < 0)
		return 0;
	last = bpf_map_lookup_elem(&pid_last_conn, &pid);
	if (last)
		daddr = last->daddr;

#pragma unroll
	for (off = 0; off < MAX_SCAN - PREFIX_LEN; off++) {
		struct secret_entry *ent;
		__u32 rem;
		__u32 plen = 0;
		int i;

		if ((__u32)off + PREFIX_LEN > buflen)
			break;
		if (sc->local[off] != 'n' || sc->local[off + 1] != 'v' ||
		    sc->local[off + 2] != 'e' || sc->local[off + 3] != ':')
			continue;
		__builtin_memset(&sc->key, 0, sizeof(sc->key));
		rem = buflen - (__u32)off;
		if (rem > MAX_SECRET_LEN)
			rem = MAX_SECRET_LEN;
#pragma unroll
		for (i = 0; i < MAX_SECRET_LEN; i++) {
			char c;

			if ((__u32)i >= rem)
				break;
			c = sc->local[off + i];
			if (c == 0 || c == ' ' || c == '\r' || c == '\n' ||
			    c == '"' || c == '\'' || c == '&')
				break;
			sc->key.data[i] = (__u8)c;
			plen = (__u32)i + 1;
		}
		if (plen < PREFIX_LEN + 4)
			continue;
		ent = bpf_map_lookup_elem(&secret_map, &sc->key);
		if (!ent) {
			bump(CNT_NO_SECRET);
			continue;
		}
		if (ent->secret_len != plen)
			continue;
		if (!host_allowed(ent, daddr)) {
			bump(CNT_HOST_MISMATCH);
			continue;
		}
		if (bpf_probe_write_user(buf + off, ent->secret, ent->secret_len) == 0)
			bump(CNT_REWRITE);
		return 1;
	}
	return 0;
}

/* x86_64 userspace pt_regs (uprobe context). */
struct uregs {
	unsigned long r15, r14, r13, r12, bp, bx;
	unsigned long r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di;
	unsigned long orig_ax, ip, cs, flags, sp, ss;
};

SEC("uprobe/SSL_write")
int handle_ssl_write(struct uregs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	char *buf;
	int num;

	if (!bpf_map_lookup_elem(&watched_pids, &pid))
		return 0;
	bump(CNT_SSL_ENTER);
	buf = (char *)ctx->si;
	num = (int)ctx->dx;
	if (num <= 0 || !buf)
		return 0;
	try_rewrite(buf, (__u32)num, pid);
	return 0;
}

SEC("uprobe/SSL_write_ex")
int handle_ssl_write_ex(struct uregs *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	char *buf;
	__u64 num;

	if (!bpf_map_lookup_elem(&watched_pids, &pid))
		return 0;
	bump(CNT_SSL_ENTER);
	buf = (char *)ctx->si;
	num = (__u64)ctx->dx;
	if (num == 0 || !buf)
		return 0;
	if (num > MAX_SCAN)
		num = MAX_SCAN;
	try_rewrite(buf, (__u32)num, pid);
	return 0;
}

struct sys_enter_connect_args {
	unsigned long long unused;
	long syscall_nr;
	unsigned long fd;
	unsigned long uservaddr;
	unsigned long addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct sys_enter_connect_args *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 fd;
	struct sockaddr_in_min sa = {};
	struct conn_info info = {};
	__u64 ckey;

	if (!bpf_map_lookup_elem(&watched_pids, &pid))
		return 0;
	fd = (__u32)ctx->fd;
	if (bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->uservaddr) < 0)
		return 0;
	if (sa.sin_family != AF_INET)
		return 0;
	info.daddr = sa.sin_addr;
	info.dport = bpf_ntohs(sa.sin_port);
	ckey = ((__u64)pid << 32) | fd;
	bpf_map_update_elem(&conn_fd_map, &ckey, &info, BPF_ANY);
	bpf_map_update_elem(&pid_last_conn, &pid, &info, BPF_ANY);
	return 0;
}
