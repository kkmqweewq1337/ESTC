//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define MAX_LISTEN_PORTS 4096

#define FILTER_EPHEMERAL_PORTS 0
#define EPHEMERAL_PORT_THRESHOLD 32768

/* ── Структуры данных ── */
struct conn_event {
    __u64  timestamp_ns;
    __u32  src_ip;
    __u32  dst_ip;
    __u16  src_port;
    __u16  dst_port;
    __u8   protocol;      // 6 = TCP, 17 = UDP
    __u8   direction;     // 0 = outbound, 1 = inbound
    __u32  pid;
    char   comm[TASK_COMM_LEN];
    __u16  service_port;
    char   service_comm[TASK_COMM_LEN];
    __u32  netns_ino;
};

struct listen_key {
    __u16 port;
    __u32 netns_ino;
};

struct listen_info {
    __u32  pid;
    char   comm[TASK_COMM_LEN];
};

/* ── Карты (Maps) ── */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_LISTEN_PORTS);
    __type(key, struct listen_key);
    __type(value, struct listen_info);
} listen_ports SEC(".maps");

// Map для корреляции kprobe/kretprobe tcp_v4_connect
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64); // pid_tgid
    __type(value, struct sock *);
} tcp_connect_socks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB
} events SEC(".maps");

/* ── Вспомогательные функции ── */
static __always_inline __u32 get_netns_ino(struct sock *sk) {
    return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline void fill_basic_event(struct conn_event *e) {
    e->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

/* ══════════════════════════════════════════════
   1. Отслеживаем listening-сокеты
   ══════════════════════════════════════════════ */
SEC("kprobe/inet_listen")
int BPF_KPROBE(inet_listen, struct socket *sock, int backlog) {
    struct sock *sk = BPF_CORE_READ(sock, sk);
    if (!sk) return 0;

    __u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (port == 0) return 0;

    struct listen_key key = {};
    key.port = port;
    key.netns_ino = get_netns_ino(sk);

    struct listen_info info = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));

    bpf_map_update_elem(&listen_ports, &key, &info, BPF_ANY);
    return 0;
}

/* ══════════════════════════════════════════════
   2. Очистка при закрытии слушающего сокета
   ══════════════════════════════════════════════ */
SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(inet_csk_listen_stop, struct sock *sk) {
    if (!sk) return 0;
    
    __u16 port = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (port == 0) return 0;

    struct listen_key key = {};
    key.port = port;
    key.netns_ino = get_netns_ino(sk);

    bpf_map_delete_elem(&listen_ports, &key);
    return 0;
}

/* ══════════════════════════════════════════════
   3. Исходящие TCP (ИСПРАВЛЕНО: паттерн kprobe + kretprobe)
   ══════════════════════════════════════════════ */
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    // Сохраняем указатель на сокет для использования в kretprobe
    bpf_map_update_elem(&tcp_connect_socks, &pid_tgid, &sk, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    if (ret != 0) return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&tcp_connect_socks, &pid_tgid);
    if (!skp) return 0;

    struct sock *sk = *skp;
    bpf_map_delete_elem(&tcp_connect_socks, &pid_tgid);

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_basic_event(e);
    
    // ИСПРАВЛЕНО: копируем comm в service_comm для исходящих соединений
    __builtin_memcpy(e->service_comm, e->comm, sizeof(e->comm));
    
    e->protocol = 6;
    e->direction = 0;
    e->netns_ino = get_netns_ino(sk);

    struct inet_sock *inet = (struct inet_sock *)sk;
    e->src_ip = BPF_CORE_READ(inet, inet_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (e->dst_ip == 0 || e->src_ip == 0 || e->dst_port == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════
   4. Входящие TCP
   ══════════════════════════════════════════════ */
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept, struct sock *newsk) {
    if (!newsk) return 0;

    __u16 dst_port = BPF_CORE_READ(newsk, __sk_common.skc_num);
    __u32 netns = get_netns_ino(newsk);

    struct listen_key key = {};
    key.port = dst_port;
    key.netns_ino = netns;

    struct listen_info *info = bpf_map_lookup_elem(&listen_ports, &key);

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_basic_event(e);
    
    e->protocol = 6; // TCP
    e->direction = 1; // inbound
    e->netns_ino = netns;

    e->src_ip = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
    e->dst_ip = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
    e->src_port = bpf_ntohs(BPF_CORE_READ(newsk, __sk_common.skc_dport));
    e->dst_port = dst_port;
    e->service_port = dst_port;

    if (info) {
        e->pid = info->pid;
        __builtin_memcpy(e->comm, info->comm, sizeof(e->comm));
        __builtin_memcpy(e->service_comm, info->comm, sizeof(e->service_comm));
    } else {
        __builtin_memcpy(e->service_comm, "unknown", 8);
    }

    if (e->dst_ip == 0 || e->src_ip == 0 || e->dst_port == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════
   5. Исходящие UDP
   ══════════════════════════════════════════════ */
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    if (!sk) return 0;

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_basic_event(e);
    
    // ИСПРАВЛЕНО: копируем comm в service_comm
    __builtin_memcpy(e->service_comm, e->comm, sizeof(e->comm));
    
    e->protocol = 17;
    e->direction = 0;
    e->netns_ino = get_netns_ino(sk);

    struct inet_sock *inet = (struct inet_sock *)sk;
    e->src_ip = BPF_CORE_READ(inet, inet_saddr);
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dst_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (e->src_ip == 0 || e->src_port == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* ══════════════════════════════════════════════
   6. Входящие UDP
   ══════════════════════════════════════════════ */

SEC("kprobe/udp_queue_rcv_skb")
int BPF_KPROBE(udp_queue_rcv_skb, struct sock *sk, struct sk_buff *skb) {
    if (!sk || !skb) return 0;

    __u16 dst_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 netns = get_netns_ino(sk);

    struct listen_key key = {};
    key.port = dst_port;
    key.netns_ino = netns;

    // Оптимизация: игнорируем, если порт не слушается
    struct listen_info *info = bpf_map_lookup_elem(&listen_ports, &key);
    if (!info) return 0;

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_basic_event(e);
    e->protocol = 17; // UDP
    e->direction = 1; // inbound
    e->netns_ino = netns;
    e->dst_port = dst_port;
    e->service_port = dst_port;
    e->dst_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->pid = info->pid;
    __builtin_memcpy(e->comm, info->comm, sizeof(e->comm));
    __builtin_memcpy(e->service_comm, info->comm, sizeof(e->service_comm));

    // 🛡️ БЕЗОПАСНОЕ ЧТЕНИЕ: используем skb->head + network_header/transport_header
    // К моменту вызова udp_queue_rcv_skb ядро уже разобрало заголовки,
    // и эти смещения гарантированно указывают на валидные данные в линейной части skb.
    unsigned char *skb_head = BPF_CORE_READ(skb, head);
    __u16 nh_offset = BPF_CORE_READ(skb, network_header);
    __u16 th_offset = BPF_CORE_READ(skb, transport_header);

    if (skb_head && nh_offset > 0 && th_offset > nh_offset) {
        // Читаем IP-заголовок из skb->head + network_header
        struct iphdr iph;
        if (bpf_probe_read_kernel(&iph, sizeof(iph), skb_head + nh_offset) == 0) {
            e->src_ip = iph.saddr;
        }
        // Читаем UDP-заголовок из skb->head + transport_header
        struct udphdr udph;
        if (bpf_probe_read_kernel(&udph, sizeof(udph), skb_head + th_offset) == 0) {
            e->src_port = bpf_ntohs(udph.source);
        }
    }

    if (e->dst_ip == 0 || e->src_ip == 0 || e->dst_port == 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
