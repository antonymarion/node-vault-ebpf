/* Minimal vmlinux subset for CO-RE build in Docker.
 * Prefer generating a full vmlinux.h via bpftool on the target kernel for production.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

enum {
	false = 0,
	true = 1,
};

#define AF_INET 2

struct in_addr {
	__be32 s_addr;
};

struct sockaddr {
	__u16 sa_family;
	char sa_data[14];
};

struct sockaddr_in {
	__u16 sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	__u8 sin_zero[8];
};

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
};

struct sock {
	struct sock_common __sk_common;
};

struct trace_event_raw_sys_enter {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long int id;
	unsigned long args[6];
};

#endif /* __VMLINUX_H__ */
