// Self-contained eBPF definitions for portable compilation with clang -target bpf
#define SEC(NAME) __attribute__((section(NAME), used))

// Basic types
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef __u16 __be16;
typedef __u32 __be32;

#define IPPROTO_UDP 17

// Ethernet header
struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
} __attribute__((packed));

// UDP header
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
} __attribute__((packed));

// XDP metadata
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

// Return values
enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
};

#define BPF_MAP_TYPE_HASH 1

// eBPF map definition for BTF/ELF loaders (compatible with Aya)
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct quic_route {
    __be32 dst_ip;
    __be16 dst_port;
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
};

// Define the hash map for QUIC CIDs (8-byte keys)
struct bpf_map_def SEC("maps") quic_cid_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = 8,                 // QUIC Destination Connection ID length (8 bytes)
    .value_size = sizeof(struct quic_route),
    .max_entries = 65536,
    .map_flags = 0,
};

// eBPF Helper functions
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;

SEC("xdp")
int xdp_quic_route(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // We only process IPv4 packets
    // 0x0008 is 0x0800 (ETH_P_IP) in big endian (network byte order) on little endian hosts
    if (eth->h_proto != 0x0008)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Check if UDP
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // Handle variable length IP header option fields safely
    __u32 ip_hlen = ip->ihl * 4;
    if (ip_hlen < 20 || ip_hlen > 60)
        return XDP_PASS;

    void *l4 = (void *)ip + ip_hlen;
    struct udphdr *udp = l4;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    void *payload = udp + 1;
    if (payload + 1 > data_end)
        return XDP_PASS;

    __u8 first_byte = *(__u8 *)payload;

    // Verify if QUIC Short Header (bit 7 must be 0, bit 6 must be 1)
    if ((first_byte & 0xC0) != 0x40) {
        return XDP_PASS;
    }

    // Extract Destination Connection ID (DCID) which is 8 bytes immediately following the first byte
    unsigned char *dcid = (unsigned char *)payload + 1;
    if ((void *)(dcid + 8) > data_end)
        return XDP_PASS;

    // Look up the CID in our BPF map
    struct quic_route *route = bpf_map_lookup_elem(&quic_cid_map, dcid);
    if (!route) {
        return XDP_PASS;
    }

    // Modify target L3/L4 information
    ip->daddr = route->dst_ip;
    udp->dest = route->dst_port;

    // Fast UDP Checksum RFC 768: 0 means no checksum verification needed for transit
    udp->check = 0;

    // Recompute IP Checksum
    ip->check = 0;
    __u32 csum = 0;
    __u16 *iph_u16 = (__u16 *)ip;
    
    // We unroll the loop to satisfy the strict eBPF verifier
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        if ((void *)&iph_u16[i + 1] <= (void *)l4) {
            csum += iph_u16[i];
        }
    }
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    ip->check = ~csum;

    // Modify Ethernet MACs to route packet directly to the backend
    __builtin_memcpy(eth->h_dest, route->dst_mac, 6);
    __builtin_memcpy(eth->h_source, route->src_mac, 6);

    // Bounce it back out of the interface it came from
    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
