#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <linux/pkt_cls.h>
#include <uapi/linux/in.h>

#define GTPU_PORT 2152
#define DEBUG_LEVEL 1
#define SOME_INFO 1

#define TCP_CSUM_OFF ETH_HLEN + IP_HLEN + offsetof(struct tcphdr, check)
#define UDP_CSUM_OFF ETH_HLEN + IP_HLEN + offsetof(struct udphdr, check)

#define IP_HLEN sizeof(struct iphdr)
#define IP_SRC_OFF ETH_HLEN + offsetof(struct iphdr, saddr)
#define IP_DST_OFF ETH_HLEN + offsetof(struct iphdr, daddr)
#define IP_CSUM_OFFSET ETH_HLEN + offsetof(struct iphdr, check)
#define ETH_SRC_OFF offsetof(struct ethhdr, h_source)
#define ETH_DST_OFF offsetof(struct ethhdr, h_dest)

#define GTPU_HEADER_LEN 8

struct upf_entry {
    __u32 ip;
    __u8 mac[6];
};

BPF_HASH(upf_lb_map, u32, struct upf_entry);
// 寫在宿主機綁CONTAINER網卡 並且轉道cilium_vxlan

static inline int is_gtpu_packet(struct iphdr *ip, void *data, void *data_end) {
    struct ethhdr *eth = data;
    
    if ((void *)eth + sizeof(*eth) > data_end)
        return 0;

    // bpf_trace_printk("ETH proto: 0x%x\n", bpf_ntohs(eth->h_proto));
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    if ((void *)ip + sizeof(*ip) > data_end)
        return 0;

    // bpf_trace_printk("IP proto: %u\n", ip->protocol);
    if (ip->protocol != IPPROTO_UDP) {
        // bpf_trace_printk("is_gtpu_packet: not UDP protocol\n");
        return 0;
    }
        
    struct udphdr *udp = (void *)ip + sizeof(struct iphdr);

    if ((void *)udp + sizeof(struct udphdr) > data_end) {
        // bpf_trace_printk("is_gtpu_packet: memory out of bound \n");
        return 0;
    }
    // bpf_trace_printk("UDP dest: %u\n", bpf_ntohs(udp->dest));
   

    if (bpf_ntohs(udp->dest) == GTPU_PORT) {
        // bpf_trace_printk("is_gtpu_packet: is GTP-U Port\n");
        return 1;   
    }
        
    // bpf_trace_printk("is_gtpu_packet: not GTP-U Port\n");
    return 0;
}

static inline unsigned int dnat(struct __sk_buff *skb, struct iphdr *ip_h, __be32 to_ip, unsigned char *to_mac) {
    if (DEBUG_LEVEL >= SOME_INFO) {
        bpf_trace_printk("- DNAT");
        unsigned char *ip_bytes = (unsigned char *)&to_ip;
        bpf_trace_printk("- DNAT to_ip: %d",ip_bytes[0]);
        bpf_trace_printk("- DNAT to_ip: %d",ip_bytes[1]);
        bpf_trace_printk("- DNAT to_ip: %d",ip_bytes[2]);
        bpf_trace_printk("- DNAT to_ip: %d",ip_bytes[3]);
    }
    
    unsigned int csum = 0;
    csum = bpf_csum_diff(&ip_h->daddr, 4, &to_ip, 4, csum);
    // ----- change L4 header -----
    if (ip_h->protocol == IPPROTO_TCP)
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, 0, csum, 0);
    else if (ip_h->protocol == IPPROTO_UDP) {
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, BPF_F_PSEUDO_HDR);
        bpf_trace_printk("csum: %u",csum);
    }
        
    // ----- change L3 header -----
    bpf_skb_store_bytes(skb, IP_DST_OFF, &to_ip, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
    // ----- change L2 header -----
    bpf_skb_store_bytes(skb, ETH_DST_OFF, to_mac, 6, 0);
    return csum;
};

static __always_inline unsigned int snat(struct __sk_buff *skb, struct iphdr *ip_h, __be32 source_ip, unsigned char *source_mac)
{
    // 我們有關 rp_filter
    if (DEBUG_LEVEL >= SOME_INFO)
        bpf_printk("- SNAT");
    unsigned int csum = 0;
    csum = bpf_csum_diff(&ip_h->saddr, 4, &source_ip, 4, csum);
    // ----- change L4 header -----
    if (ip_h->protocol == IPPROTO_TCP)
        bpf_l4_csum_replace(skb, TCP_CSUM_OFF, 0, csum, 0);
    else if (ip_h->protocol == IPPROTO_UDP)
        bpf_l4_csum_replace(skb, UDP_CSUM_OFF, 0, csum, 0);
    // ----- change L3 header -----
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &source_ip, 4, 0);
    bpf_l3_csum_replace(skb, IP_CSUM_OFFSET, 0, csum, 0);
    // ----- change L2 header -----
    bpf_skb_store_bytes(skb, ETH_SRC_OFF, source_mac, 6, 0);
    return csum;
};

static inline void echo_ipv4(struct iphdr *ip_h)
{
    bpf_trace_printk("IP");
    bpf_trace_printk("  From: %pI4", &ip_h->saddr);
    bpf_trace_printk("  To:   %pI4", &ip_h->daddr);
}

int loadbalancer(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;
    
    echo_ipv4(ip);

    if (!is_gtpu_packet(ip, data, data_end)) {
        // bpf_trace_printk("mirror_traffic: not GTP-U packet");
        return TC_ACT_OK;
    }

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    // 取得 GTP-U header
    __u8 *gtp = (void *)(udp + 1);
    if ((void *)(gtp + GTPU_HEADER_LEN) > data_end)
        return TC_ACT_OK;

    __u32 teid;
    __builtin_memcpy(&teid, gtp + 4, sizeof(__u32));
    teid = __builtin_bswap32(teid);  // network to host
    bpf_trace_printk("TEID: %u\n", teid);

    // 根據 TEID 做 hash 負載平衡
    __u32 index = teid % 2; // 假設有兩個 UPF
    bpf_trace_printk("index: %u\n", index);
    struct upf_entry *dst = upf_lb_map.lookup(&index);
    if (!dst) return TC_ACT_OK;

    // 改成負載目的地
    dnat(skb, ip, dst->ip, dst->mac);

    return TC_ACT_OK;
}
