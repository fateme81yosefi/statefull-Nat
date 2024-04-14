#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <time.h>

struct connection_state
{
    __u32 src_ip;
    __u32 dest_ip;
    __u32 translated_src_ip;
    __u32 translated_dst_ip;
    time_t current_time;
};

// Connection state table
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct connection_state));
    __uint(value_size, sizeof(struct connection_state));
    __uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_state_map SEC(".maps");

static inline void *bpf_hdr_pointer(const struct __sk_buff *skb, __u32 offset)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + offset <= data_end)
        return data + offset;

    return NULL;
}

int delete_old_connections(struct __sk_buff *skb)
{
    struct connection_state *conn_state;
    __u32 key = 0; // Key to access the map

    // Iterate over the connection state map
    for (int i = 0; i < 1024; i++)
    {
        // Get the connection state at index i
        conn_state = bpf_map_lookup_elem(&connection_state_map, &key);
        if (!conn_state)
            break; // End of map

        // Get the current time
        time_t now = bpf_ktime_get_ns() / 1000000000;

        // Check if the current time is more than 30 seconds after the connection time
        if (now - conn_state->current_time > 30)
        {
            // Delete the old connection state
            bpf_map_delete_elem(&connection_state_map, &key);
        }

        // Move to the next key
        key++;
    }

    return 0;
}

SEC("nat")

int nat_prog(struct __sk_buff *skb)
{

    delete_old_connections(skb);
    // Get Ethernet header
    struct ethhdr *eth = bpf_hdr_pointer(skb, 0);

    // Check if it's an IP packet
    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    // Get IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);

    // Check if it's an ICMP packet
    if (ip->protocol != IPPROTO_ICMP)
        return 0;

    // Get ICMP header
    struct icmphdr *icmp = (struct icmphdr *)(ip + 1);

    // Only handle ICMP Echo Request (Ping) packets
    if (icmp->type != 8)
        return 0;

    // Get connection state
    struct connection_state key = {
        .src_ip = bpf_ntohl(ip->saddr),
    };
    struct connection_state key1 = {
        .dest_ip = bpf_ntohl(ip->daddr),
    };

    struct connection_state *conn_state = bpf_map_lookup_elem(&connection_state_map, &key);
    struct connection_state *conn_state1 = bpf_map_lookup_elem(&connection_state_map, &key1);

    if (!conn_state && !conn_state1)
    {
        // New connection, perform NAT translation
        __u32 translated_src_ip;
        __u32 translated_dst_ip;

        if (ip->saddr == htonl(0x0a020602) && ip->daddr == bpf_htonl(0x0A010601))
        {
            translated_src_ip = bpf_htonl(10 << 24 | 1 << 16 | 6 << 8 | 2);
            // Update connection state with translated IP
            struct connection_state new_conn_state = {
                .src_ip = key.src_ip,
                .dest_ip = bpf_ntohl(ip->daddr),
                .translated_src_ip = translated_src_ip,
                .translated_dst_ip = bpf_ntohl(ip->daddr),
                .current_time = bpf_ktime_get_ns() / 1000000000};

            bpf_skb_store_bytes(skb, offsetof(struct __sk_buff, data) + offsetof(struct icmphdr, un.echo.id),
                                &translated_src_ip, sizeof(translated_src_ip), BPF_F_RECOMPUTE_CSUM);
            bpf_map_update_elem(&connection_state_map, &key, &new_conn_state, BPF_ANY);
        }
        else if (ip->saddr == bpf_htonl(0x0a010602) && ip->daddr == bpf_htonl(0x0a020602))
        {
            translated_dst_ip = bpf_htonl(10 << 24 | 2 << 16 | 6 << 8 | 1);
            // Update connection state with translated IP
            struct connection_state new_conn_state = {
                .src_ip = key1.src_ip,
                .dest_ip = bpf_ntohl(ip->daddr),
                .translated_src_ip = bpf_ntohl(ip->saddr),
                .translated_dst_ip = translated_dst_ip,
                .current_time = bpf_ktime_get_ns() / 1000000000};

            bpf_skb_store_bytes(skb, offsetof(struct __sk_buff, data) + offsetof(struct icmphdr, un.echo.id),
                                &translated_dst_ip, sizeof(translated_dst_ip), BPF_F_RECOMPUTE_CSUM);
            bpf_map_update_elem(&connection_state_map, &key1, &new_conn_state, BPF_ANY);
        }
    }
    else
    {
        if (ip->saddr == htonl(0x0a020602) && ip->daddr == bpf_htonl(0x0A010601))
        {
            ip->saddr = bpf_htonl(conn_state->translated_src_ip);
            conn_state->current_time = bpf_ktime_get_ns() / 1000000000;
        }
        else if (ip->saddr == bpf_htonl(0x0a010602) && ip->daddr == bpf_htonl(0x0a020602))
        {
            ip->daddr = bpf_htonl(conn_state1->translated_dst_ip);
            conn_state1->current_time = bpf_ktime_get_ns() / 1000000000;
        }
    }

    if (ip->saddr == htonl(0x0a020602) && ip->daddr == bpf_htonl(0x0A010601))
    {

        if (bpf_l3_csum_replace(skb, offsetof(struct __sk_buff, data) + offsetof(struct iphdr, saddr), &ip->saddr, &ip->daddr, sizeof(ip->saddr)) == 0)
        {
            // Forward packet
            return bpf_redirect(skb->ifindex, 0);
        }
        else
            return BPF_DROP;
    }

    else if (ip->saddr == bpf_htonl(0x0a010602) && ip->daddr == bpf_htonl(0x0a020602))
    {
        if (bpf_l3_csum_replace(skb, offsetof(struct __sk_buff, data) + offsetof(struct iphdr, daddr), &ip->daddr, &ip->daddr + 1, sizeof(ip->daddr)) == 0)
        {
            // Forward packet
            return bpf_redirect(skb->ifindex, 0);
        }
        else
            return BPF_DROP;
    }
}

char _license[] SEC("license") = "GPL";
