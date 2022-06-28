// +build ignore

#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 2000);
	__uint(key_size, sizeof(u32)*2);
	__uint(value_size, sizeof(u32));
} hash_map SEC(".maps");

SEC("sk_skb/prog_parser")
int _prog_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("sk_skb/prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
    u64 key = ((u64)skb->local_port << 32) | skb->remote_port;
	return bpf_sk_redirect_hash(skb, &hash_map, &key,  0);
}

char _license[] SEC("license") = "GPL";
