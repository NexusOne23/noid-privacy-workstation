// SPDX-License-Identifier: GPL-2.0-only
/*
 * NoID Privacy Workstation — physical-link XDP ingress boundary.
 *
 * Native-driver XDP runs before skb allocation. Generic XDP necessarily uses
 * an skb, but the kernel executes it before ptype_all packet taps (including
 * ordinary AF_PACKET capture). Default verdict is XDP_DROP. It passes only:
 *   - checksum-valid, unfragmented TCP/UDP frames matching the explicit
 *     inbound selector of an exact interface/IP/MAC administrator-approved
 *     LAN peer binding;
 *   - checksum-valid, unfragmented replies to short-lived IPv4 flows observed
 *     by the TC egress program, and only when the Ethernet source is the
 *     pinned WAN gateway or an outbound-approved exact LAN peer binding on
 *     that interface;
 *   - EAPOL, which is required for WPA-Enterprise / wired 802.1X;
 *   - structurally valid DHCPv4 server replies matching an exact, short-lived
 *     (interface, transaction ID, BOOTP chaddr) request observed at TC egress;
 *   - structurally valid standard ARP. RFC 5227 Address Conflict Detection
 *     requires requests, replies, probes and announcements to reach the
 *     kernel; permanent neighbour pins provide gateway/peer anti-replacement.
 *
 * The global LAN opt-in is an explicit map bit. It is controlled by the same
 * root transaction as firewalld, topology, WAN-strict and ARP state.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define NOID_EAPOL_ETHERTYPE 0x888e
#define NOID_DHCP_MAGIC 0x63825363
#define NOID_ARPHRD_ETHER 1
#define NOID_ARPOP_REQUEST 1
#define NOID_ARPOP_REPLY 2
#define NOID_ICMP_ECHOREPLY 0
#define NOID_ICMP_DEST_UNREACH 3
#define NOID_ICMP_ECHO 8
#define NOID_ICMP_TIME_EXCEEDED 11
#define NOID_TCP_FLOW_NS (2ULL * 60 * 60 * 1000000000)
#define NOID_UDP_FLOW_NS (5ULL * 60 * 1000000000)
#define NOID_ICMP_FLOW_NS (60ULL * 1000000000)
#define NOID_DHCP_FLOW_NS (90ULL * 1000000000)
#define NOID_IPV4_MAX_LEN 1500
#define NOID_IP_RF 0x8000
#define NOID_IP_MF 0x2000
#define NOID_IP_OFFSET 0x1fff
#define NOID_PEER_OUTBOUND 0x01
#define NOID_PEER_INBOUND 0x02

enum noid_xdp_stat {
    NOID_XDP_PASS_GLOBAL = 0,
    NOID_XDP_PASS_PEER = 1,
    NOID_XDP_PASS_EAPOL = 2,
    NOID_XDP_PASS_DHCP = 3,
    NOID_XDP_PASS_ARP_STANDARD = 4,
    NOID_XDP_PASS_FLOW = 5,
    NOID_XDP_PASS_ICMP_ERROR = 6,
    NOID_XDP_DROP_FRAGMENT = 7,
    NOID_XDP_DROP_DEFAULT = 8,
    NOID_XDP_STAT_MAX = 9,
};

struct noid_mac {
    __u8 addr[ETH_ALEN];
};

struct noid_link_mac {
    __u32 ifindex;
    struct noid_mac mac;
    __u8 pad[2];
};

struct noid_peer4 {
    __u32 ifindex;
    __be32 ip;
    struct noid_mac mac;
    __u8 pad[2];
};

struct noid_peer4_policy {
    __u8 direction;
    __u8 protocol;
    __u16 port_start;
    __u16 port_end;
    __u8 pad[2];
};

struct noid_dhcp4 {
    __u32 ifindex;
    __be32 xid;
    struct noid_mac mac;
    __u8 pad[2];
};

struct noid_flow4 {
    __u32 ifindex;
    __be32 remote_ip;
    __be32 local_ip;
    __be16 remote_port;
    __be16 local_port;
    __u8 protocol;
    __u8 pad[3];
};

struct noid_expiry {
    __u64 expires_ns;
};

/* UAPI headers do not expose struct vlan_hdr consistently across distros. */
struct noid_vlan_hdr {
    __be16 tci;
    __be16 encapsulated_proto;
} __attribute__((packed));

struct noid_arphdr {
    __be16 hardware_type;
    __be16 protocol_type;
    __u8 hardware_len;
    __u8 protocol_len;
    __be16 operation;
} __attribute__((packed));

struct noid_arp_eth_ipv4 {
    struct noid_arphdr header;
    __u8 sender_mac[ETH_ALEN];
    __be32 sender_ip;
    __u8 target_mac[ETH_ALEN];
    __be32 target_ip;
} __attribute__((packed));

struct noid_dhcp_min {
    __u8 op;
    __u8 htype;
    __u8 hlen;
    __u8 hops;
    __be32 xid;
    __be16 secs;
    __be16 flags;
    __be32 ciaddr;
    __be32 yiaddr;
    __be32 siaddr;
    __be32 giaddr;
    __u8 chaddr[16];
    __u8 sname[64];
    __u8 file[128];
    __be32 magic;
} __attribute__((packed));

struct noid_eapol {
    __u8 version;
    __u8 type;
    __be16 body_length;
} __attribute__((packed));

struct noid_icmp_min {
    __u8 type;
    __u8 code;
    __be16 checksum;
    __be16 identifier;
    __be16 sequence;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct noid_link_mac);
    __type(value, __u8);
} noid_xdp_gateway_macs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct noid_peer4);
    __type(value, struct noid_peer4_policy);
} noid_xdp_peer4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, struct noid_link_mac);
    __type(value, __u8);
} noid_xdp_local_macs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, struct noid_dhcp4);
    __type(value, struct noid_expiry);
} noid_xdp_dhcp_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct noid_flow4);
    __type(value, struct noid_expiry);
} noid_xdp_flows_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} noid_xdp_global_allow SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NOID_XDP_STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} noid_xdp_stats SEC(".maps");

static __always_inline int noid_verdict(__u32 reason, int action)
{
    __u64 *counter = bpf_map_lookup_elem(&noid_xdp_stats, &reason);

    if (counter)
        *counter += 1;
    return action;
}

static __always_inline int noid_mac_is_present(void *map, __u32 ifindex,
                                                const __u8 addr[ETH_ALEN])
{
    struct noid_link_mac key = { .ifindex = ifindex };

    __builtin_memcpy(key.mac.addr, addr, ETH_ALEN);
    if (bpf_map_lookup_elem(map, &key))
        return 1;
    return 0;
}

static __always_inline int noid_mac_equal(const __u8 left[ETH_ALEN],
                                           const __u8 right[ETH_ALEN])
{
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (left[i] != right[i])
            return 0;
    }
    return 1;
}

static __always_inline int noid_mac_is_broadcast(const __u8 addr[ETH_ALEN])
{
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++) {
        if (addr[i] != 0xff)
            return 0;
    }
    return 1;
}

static __always_inline int noid_mac_is_unicast_source(const __u8 addr[ETH_ALEN])
{
    __u8 present = 0;

    if (addr[0] & 1)
        return 0;
#pragma unroll
    for (int i = 0; i < ETH_ALEN; i++)
        present |= addr[i];
    return present != 0;
}

/*
 * NetworkManager applies a stable/randomized cloned MAC before address
 * acquisition. The controller necessarily seeds the map earlier, while the
 * permanent hardware MAC is still active. TC egress is the first trusted
 * observation point after that transition: a source MAC on a frame that has
 * reached this physical egress qdisc is locally emitted, not LAN supplied.
 * Register it before the matching DHCP/ARP reply can reach XDP ingress.
 */
static __always_inline void noid_record_local_source_mac(
    __u32 ifindex, const __u8 addr[ETH_ALEN])
{
    struct noid_link_mac key = { .ifindex = ifindex };
    __u8 allowed = 1;

    if (!noid_mac_is_unicast_source(addr))
        return;
    __builtin_memcpy(key.mac.addr, addr, ETH_ALEN);
    if (!bpf_map_lookup_elem(&noid_xdp_local_macs, &key))
        bpf_map_update_elem(&noid_xdp_local_macs, &key, &allowed, BPF_ANY);
}

static __always_inline int noid_mac_is_eapol_group(const __u8 addr[ETH_ALEN])
{
    const __u8 group[ETH_ALEN] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };

    return noid_mac_equal(addr, group);
}

/*
 * Validate a complete Internet one's-complement checksum, including the
 * checksum field. Words are summed in host order; on little-endian BPF this
 * byte-swaps every word consistently, so a valid folded result is still
 * 0xffff. NOID_IPV4_MAX_LEN bounds both verifier work and hostile CPU cost.
 */
struct noid_checksum_loop {
    void *start;
    void *packet_end;
    __u32 length;
    __u32 sum;
    __u8 valid;
};

static long noid_checksum_step(__u32 index, void *opaque)
{
    struct noid_checksum_loop *state = opaque;
    __u32 offset;
    __u8 *cursor;
    __u16 word = 0;

    if (index >= (NOID_IPV4_MAX_LEN + 1) / 2)
        return 1;
    offset = index * 2;
    cursor = state->start + offset;
    if (offset >= state->length)
        return 1;
    if ((void *)(cursor + 1) > state->packet_end) {
        state->valid = 0;
        return 1;
    }
    if (offset + 1 < state->length) {
        if ((void *)(cursor + 2) > state->packet_end) {
            state->valid = 0;
            return 1;
        }
        __builtin_memcpy(&word, cursor, sizeof(word));
    } else {
        word = *cursor;
    }
    state->sum += word;
    return 0;
}

static __attribute__((noinline)) int noid_checksum_valid(
    void *start, __u32 length, void *packet_end, __u32 seed)
{
    struct noid_checksum_loop state = {
        .start = start,
        .packet_end = packet_end,
        .length = length,
        .sum = seed,
        .valid = 1,
    };
    long iterations;

    if (!length || length > NOID_IPV4_MAX_LEN)
        return 0;
    iterations = bpf_loop((length + 1) / 2, noid_checksum_step, &state, 0);
    if (iterations < 0 || !state.valid)
        return 0;
    state.sum = (state.sum & 0xffff) + (state.sum >> 16);
    state.sum = (state.sum & 0xffff) + (state.sum >> 16);
    return (__u16)state.sum == 0xffff;
}

static __attribute__((noinline)) int noid_ipv4_transport_checksum_valid(
    struct iphdr *ip, void *transport, __u16 transport_length,
    void *packet_end)
{
    __u16 *source = (__u16 *)&ip->saddr;
    __u16 *destination = (__u16 *)&ip->daddr;
    __u32 seed = source[0] + source[1] + destination[0] + destination[1];

    seed += bpf_htons((__u16)ip->protocol);
    seed += bpf_htons(transport_length);
    return noid_checksum_valid(transport, transport_length, packet_end, seed);
}

static __always_inline struct noid_peer4_policy *noid_peer4_policy(
    __u32 ifindex, __be32 ip, const __u8 addr[ETH_ALEN])
{
    struct noid_peer4 key = { .ifindex = ifindex, .ip = ip };

    __builtin_memcpy(key.mac.addr, addr, ETH_ALEN);
    return bpf_map_lookup_elem(&noid_xdp_peer4, &key);
}

static __always_inline int noid_flow4_is_live(struct noid_flow4 *key)
{
    struct noid_expiry *value;

    value = bpf_map_lookup_elem(&noid_xdp_flows_v4, key);
    if (!value)
        return 0;
    if (value->expires_ns > bpf_ktime_get_ns())
        return 1;
    bpf_map_delete_elem(&noid_xdp_flows_v4, key);
    return 0;
}

static __always_inline int noid_dhcp4_is_live(__u32 ifindex, __be32 xid,
                                               const __u8 chaddr[ETH_ALEN])
{
    struct noid_dhcp4 key = { .ifindex = ifindex, .xid = xid };
    struct noid_expiry *value;

    __builtin_memcpy(key.mac.addr, chaddr, ETH_ALEN);
    value = bpf_map_lookup_elem(&noid_xdp_dhcp_v4, &key);
    if (!value)
        return 0;
    if (value->expires_ns > bpf_ktime_get_ns())
        return 1;
    bpf_map_delete_elem(&noid_xdp_dhcp_v4, &key);
    return 0;
}

SEC("xdp")
int noid_lan_xdp(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *network;
    __be16 protocol;
    __u32 zero = 0;
    __u8 *global;
    int from_gateway;

    if ((void *)(eth + 1) > data_end)
        return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);

    global = bpf_map_lookup_elem(&noid_xdp_global_allow, &zero);
    if (global && *global)
        return noid_verdict(NOID_XDP_PASS_GLOBAL, XDP_PASS);

    from_gateway = noid_mac_is_present(&noid_xdp_gateway_macs,
                                       ctx->ingress_ifindex,
                                       eth->h_source);

    protocol = eth->h_proto;
    network = eth + 1;

    /* Accept up to two 802.1Q/802.1ad tags before the real EtherType. */
#pragma unroll
    for (int i = 0; i < 2; i++) {
        struct noid_vlan_hdr *vlan;

        if (protocol != bpf_htons(ETH_P_8021Q) &&
            protocol != bpf_htons(ETH_P_8021AD))
            break;
        vlan = network;
        if ((void *)(vlan + 1) > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        protocol = vlan->encapsulated_proto;
        network = vlan + 1;
    }

    /* A third VLAN tag is outside the release-qualified link contract. */
    if (protocol == bpf_htons(ETH_P_8021Q) ||
        protocol == bpf_htons(ETH_P_8021AD))
        return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);

    if (protocol == bpf_htons(NOID_EAPOL_ETHERTYPE)) {
        struct noid_eapol *eapol = network;
        __u16 body_length;

        if ((void *)(eapol + 1) > data_end ||
            !noid_mac_is_unicast_source(eth->h_source) ||
            (!noid_mac_is_eapol_group(eth->h_dest) &&
             !noid_mac_is_present(&noid_xdp_local_macs,
                                  ctx->ingress_ifindex, eth->h_dest)) ||
            eapol->version < 1 || eapol->version > 3 || eapol->type > 4)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        body_length = bpf_ntohs(eapol->body_length);
        if ((void *)(eapol + 1) + body_length > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        return noid_verdict(NOID_XDP_PASS_EAPOL, XDP_PASS);
    }

    if (protocol == bpf_htons(ETH_P_ARP)) {
        struct noid_arp_eth_ipv4 *arp = network;
        __u16 operation;

        if ((void *)(arp + 1) > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        if (arp->header.hardware_type != bpf_htons(NOID_ARPHRD_ETHER) ||
            arp->header.protocol_type != bpf_htons(ETH_P_IP) ||
            arp->header.hardware_len != ETH_ALEN ||
            arp->header.protocol_len != sizeof(__be32))
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        if (!noid_mac_is_unicast_source(eth->h_source) ||
            !noid_mac_equal(eth->h_source, arp->sender_mac))
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        operation = bpf_ntohs(arp->header.operation);
        if (operation == NOID_ARPOP_REQUEST) {
            /* RFC 826 ignores target_mac in a request. Broadcast Probes and
             * Announcements plus valid unicast requests must reach native
             * IPv4 ACD and ordinary neighbour handling. */
            if (!noid_mac_is_broadcast(eth->h_dest) &&
                !noid_mac_is_present(&noid_xdp_local_macs,
                                     ctx->ingress_ifindex, eth->h_dest))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            return noid_verdict(NOID_XDP_PASS_ARP_STANDARD, XDP_PASS);
        }
        if (operation == NOID_ARPOP_REPLY) {
            /* Unicast replies correlate both Ethernet/ARP target MACs.
             * RFC 5227 also permits broadcast replies; their ARP target must
             * still be one of this interface's local MACs. */
            if (!noid_mac_is_present(&noid_xdp_local_macs,
                                     ctx->ingress_ifindex, arp->target_mac))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (!noid_mac_is_broadcast(eth->h_dest) &&
                (!noid_mac_equal(eth->h_dest, arp->target_mac) ||
                 !noid_mac_is_present(&noid_xdp_local_macs,
                                      ctx->ingress_ifindex, eth->h_dest)))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            return noid_verdict(NOID_XDP_PASS_ARP_STANDARD, XDP_PASS);
        }
        return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
    }

    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = network;
        __u32 ihl;
        __u16 total_length;
        __u16 payload_length;
        __u16 fragment;
        void *ip_end;
        struct noid_peer4_policy *peer_policy;
        int peer_present;
        int peer_outbound;
        int peer_inbound;
        int gateway_flow_authorized;
        __u8 peer_protocol = 0;
        __u16 peer_port_start = 0;
        __u16 peer_port_end = 0;
        int link_authorized;
        struct udphdr *udp;
        struct noid_dhcp_min *dhcp;
        struct noid_flow4 flow = {};

        if ((void *)ip + sizeof(struct iphdr) > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        if (ip->version != 4)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        ihl = ip->ihl * 4;
        if (ihl < sizeof(struct iphdr) || ihl > 60 ||
            (void *)ip + ihl > data_end)
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        total_length = bpf_ntohs(ip->tot_len);
        if (total_length < ihl || total_length > NOID_IPV4_MAX_LEN ||
            (void *)ip + total_length > data_end || ip->ttl == 0 ||
            !noid_mac_is_unicast_source(eth->h_source) ||
            !noid_checksum_valid(ip, ihl, data_end, 0))
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        ip_end = (void *)ip + total_length;
        payload_length = total_length - ihl;

        fragment = bpf_ntohs(ip->frag_off);
        if (fragment & (NOID_IP_RF | NOID_IP_MF | NOID_IP_OFFSET))
            return noid_verdict(NOID_XDP_DROP_FRAGMENT, XDP_DROP);

        peer_policy = noid_peer4_policy(ctx->ingress_ifindex, ip->saddr,
                                        eth->h_source);
        peer_present = peer_policy != 0;
        peer_outbound = 0;
        peer_inbound = 0;
        if (peer_policy) {
            peer_outbound = (peer_policy->direction & NOID_PEER_OUTBOUND) != 0;
            peer_inbound = (peer_policy->direction & NOID_PEER_INBOUND) != 0;
            peer_protocol = peer_policy->protocol;
            peer_port_start = peer_policy->port_start;
            peer_port_end = peer_policy->port_end;
        }
        /* An exact peer policy is more specific than the interface gateway
         * MAC role. This prevents a gateway/peer MAC overlap from widening an
         * inbound-only peer through correlated outbound-flow admission. */
        gateway_flow_authorized = from_gateway && !peer_present;
        link_authorized = 0;
        if (noid_mac_is_present(&noid_xdp_local_macs,
                                ctx->ingress_ifindex, eth->h_dest)) {
            if (peer_present)
                link_authorized = 1;
            else if (from_gateway)
                link_authorized = 1;
        }

        if (ip->protocol == IPPROTO_UDP) {
            __u16 udp_length;
            int is_dhcp;

            udp = (void *)ip + ihl;
            if (payload_length < sizeof(*udp) ||
                (void *)(udp + 1) > data_end ||
                (void *)(udp + 1) > ip_end)
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            udp_length = bpf_ntohs(udp->len);
            is_dhcp = udp->source == bpf_htons(67) &&
                      udp->dest == bpf_htons(68);
            if (!is_dhcp && !link_authorized)
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (udp_length < sizeof(*udp) || udp_length != payload_length ||
                udp->check == 0 ||
                !noid_ipv4_transport_checksum_valid(ip, udp, udp_length,
                                                     data_end))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);

            /* DHCP is the only pre-gateway IPv4 ingress bootstrap. */
            if (is_dhcp) {
                dhcp = (void *)(udp + 1);
                if ((void *)(dhcp + 1) > data_end ||
                    (void *)(dhcp + 1) > ip_end || dhcp->op != 2 ||
                    dhcp->htype != NOID_ARPHRD_ETHER ||
                    dhcp->hlen != ETH_ALEN ||
                    dhcp->magic != bpf_htonl(NOID_DHCP_MAGIC) ||
                    !noid_mac_is_present(&noid_xdp_local_macs,
                                         ctx->ingress_ifindex,
                                         dhcp->chaddr) ||
                    (!noid_mac_is_broadcast(eth->h_dest) &&
                     !noid_mac_equal(eth->h_dest, dhcp->chaddr)))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                if (noid_dhcp4_is_live(ctx->ingress_ifindex, dhcp->xid,
                                       dhcp->chaddr))
                    return noid_verdict(NOID_XDP_PASS_DHCP, XDP_PASS);
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            }

            if (peer_inbound && peer_protocol == IPPROTO_UDP &&
                bpf_ntohs(udp->dest) >= peer_port_start &&
                bpf_ntohs(udp->dest) <= peer_port_end)
                return noid_verdict(NOID_XDP_PASS_PEER, XDP_PASS);

            flow.ifindex = ctx->ingress_ifindex;
            flow.remote_ip = ip->saddr;
            flow.local_ip = ip->daddr;
            flow.remote_port = udp->source;
            flow.local_port = udp->dest;
            flow.protocol = IPPROTO_UDP;
        } else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)ip + ihl;
            __u32 tcp_header_length;

            if (payload_length < sizeof(*tcp) ||
                (void *)(tcp + 1) > data_end ||
                (void *)(tcp + 1) > ip_end)
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            tcp_header_length = tcp->doff * 4;
            if (tcp_header_length < sizeof(*tcp) ||
                tcp_header_length > payload_length || tcp->res1 != 0 ||
                !link_authorized ||
                !noid_ipv4_transport_checksum_valid(ip, tcp, payload_length,
                                                     data_end))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (peer_inbound && peer_protocol == IPPROTO_TCP &&
                bpf_ntohs(tcp->dest) >= peer_port_start &&
                bpf_ntohs(tcp->dest) <= peer_port_end)
                return noid_verdict(NOID_XDP_PASS_PEER, XDP_PASS);
            flow.ifindex = ctx->ingress_ifindex;
            flow.remote_ip = ip->saddr;
            flow.local_ip = ip->daddr;
            flow.remote_port = tcp->source;
            flow.local_port = tcp->dest;
            flow.protocol = IPPROTO_TCP;
        } else if (ip->protocol == IPPROTO_ICMP) {
            struct noid_icmp_min *icmp = (void *)ip + ihl;

            if (payload_length < sizeof(*icmp) ||
                (void *)(icmp + 1) > data_end ||
                (void *)(icmp + 1) > ip_end ||
                !link_authorized ||
                !noid_checksum_valid(icmp, payload_length, data_end, 0))
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            if (icmp->type == NOID_ICMP_ECHOREPLY) {
                if (icmp->code != 0)
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                flow.ifindex = ctx->ingress_ifindex;
                flow.remote_ip = ip->saddr;
                flow.local_ip = ip->daddr;
                flow.remote_port = icmp->identifier;
                flow.protocol = IPPROTO_ICMP;
            } else if (icmp->type == NOID_ICMP_DEST_UNREACH ||
                       icmp->type == NOID_ICMP_TIME_EXCEEDED) {
                struct iphdr *inner = (void *)(icmp + 1);
                __u32 inner_ihl;
                __u16 inner_fragment;

                if ((void *)(inner + 1) > data_end ||
                    (void *)(inner + 1) > ip_end || inner->version != 4 ||
                    (icmp->type == NOID_ICMP_DEST_UNREACH &&
                     icmp->code > 15) ||
                    (icmp->type == NOID_ICMP_TIME_EXCEEDED &&
                     icmp->code > 1))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                inner_ihl = inner->ihl * 4;
                if (inner_ihl < sizeof(*inner) ||
                    (void *)inner + inner_ihl + 8 > ip_end ||
                    bpf_ntohs(inner->tot_len) < inner_ihl + 8 ||
                    !noid_checksum_valid(inner, inner_ihl, data_end, 0))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                inner_fragment = bpf_ntohs(inner->frag_off);
                if (inner_fragment & (NOID_IP_RF | NOID_IP_OFFSET))
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                flow.ifindex = ctx->ingress_ifindex;
                flow.remote_ip = inner->daddr;
                flow.local_ip = inner->saddr;
                flow.protocol = inner->protocol;
                if (inner->protocol == IPPROTO_TCP ||
                    inner->protocol == IPPROTO_UDP) {
                    __be16 *ports = (void *)inner + inner_ihl;

                    /* Keep a verifier-visible packet-pointer bounds check;
                     * otherwise LLVM folds it into the already proven scalar
                     * inner-length relation, which the verifier cannot link
                     * back to this variable-offset pointer. */
                    asm volatile("" : "+r"(ports));
                    if ((void *)(ports + 2) > data_end)
                        return noid_verdict(NOID_XDP_DROP_DEFAULT,
                                             XDP_DROP);
                    flow.local_port = ports[0];
                    flow.remote_port = ports[1];
                } else {
                    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
                }
                if ((gateway_flow_authorized || peer_outbound) &&
                    noid_flow4_is_live(&flow))
                    return noid_verdict(NOID_XDP_PASS_ICMP_ERROR,
                                         XDP_PASS);
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            } else {
                return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
            }
        } else {
            return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
        }

        if ((gateway_flow_authorized || peer_outbound) &&
            noid_flow4_is_live(&flow)) {
            return noid_verdict(NOID_XDP_PASS_FLOW, XDP_PASS);
        }
    }

    return noid_verdict(NOID_XDP_DROP_DEFAULT, XDP_DROP);
}

/*
 * Record only packets that reached the physical egress qdisc. Netfilter's
 * output hooks have already rejected forbidden LAN destinations at this
 * point. XDP can therefore admit only the reverse tuple, for a bounded time,
 * before AF_PACKET delivery. Ingress never refreshes a flow lifetime.
 */
SEC("tc")
int noid_lan_egress(struct __sk_buff *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    void *network;
    __be16 protocol;
    struct iphdr *ip;
    __u32 ihl;
    __u16 fragment;
    struct noid_flow4 flow = {};
    struct noid_expiry value = {};

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    noid_record_local_source_mac(ctx->ifindex, eth->h_source);
    protocol = eth->h_proto;
    network = eth + 1;

#pragma unroll
    for (int i = 0; i < 2; i++) {
        struct noid_vlan_hdr *vlan;

        if (protocol != bpf_htons(ETH_P_8021Q) &&
            protocol != bpf_htons(ETH_P_8021AD))
            break;
        vlan = network;
        if ((void *)(vlan + 1) > data_end)
            return TC_ACT_OK;
        protocol = vlan->encapsulated_proto;
        network = vlan + 1;
    }
    if (protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    ip = network;
    if ((void *)ip + sizeof(*ip) > data_end || ip->version != 4)
        return TC_ACT_OK;
    ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip) || (void *)ip + ihl > data_end)
        return TC_ACT_OK;
    fragment = bpf_ntohs(ip->frag_off);
    if ((fragment & NOID_IP_OFFSET) != 0)
        return TC_ACT_OK;

    flow.ifindex = ctx->ifindex;
    flow.remote_ip = ip->daddr;
    flow.local_ip = ip->saddr;
    flow.protocol = ip->protocol;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ihl;

        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        flow.remote_port = tcp->dest;
        flow.local_port = tcp->source;
        value.expires_ns = bpf_ktime_get_ns() + NOID_TCP_FLOW_NS;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ihl;

        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        if (udp->source == bpf_htons(68) && udp->dest == bpf_htons(67)) {
            struct noid_dhcp_min *dhcp = (void *)(udp + 1);
            struct noid_dhcp4 dhcp_key = { .ifindex = ctx->ifindex };
            struct noid_expiry dhcp_expiry = {
                .expires_ns = bpf_ktime_get_ns() + NOID_DHCP_FLOW_NS,
            };

            if ((void *)(dhcp + 1) > data_end || dhcp->op != 1 ||
                dhcp->htype != NOID_ARPHRD_ETHER ||
                dhcp->hlen != ETH_ALEN ||
                dhcp->magic != bpf_htonl(NOID_DHCP_MAGIC))
                return TC_ACT_OK;
            dhcp_key.xid = dhcp->xid;
            __builtin_memcpy(dhcp_key.mac.addr, dhcp->chaddr, ETH_ALEN);
            bpf_map_update_elem(&noid_xdp_dhcp_v4, &dhcp_key, &dhcp_expiry,
                                BPF_ANY);
        }
        flow.remote_port = udp->dest;
        flow.local_port = udp->source;
        value.expires_ns = bpf_ktime_get_ns() + NOID_UDP_FLOW_NS;
    } else if (ip->protocol == IPPROTO_ICMP) {
        struct noid_icmp_min *icmp = (void *)ip + ihl;

        if ((void *)(icmp + 1) > data_end ||
            icmp->type != NOID_ICMP_ECHO)
            return TC_ACT_OK;
        flow.remote_port = icmp->identifier;
        value.expires_ns = bpf_ktime_get_ns() + NOID_ICMP_FLOW_NS;
    } else {
        return TC_ACT_OK;
    }

    bpf_map_update_elem(&noid_xdp_flows_v4, &flow, &value, BPF_ANY);
    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
