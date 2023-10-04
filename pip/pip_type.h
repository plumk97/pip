//
//  pip_type.h
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_type_h
#define pip_type_h

#include <iostream>
#include <chrono>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#if __APPLE__
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else

#include <WinSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#endif

#include "pip_opt.h"


#define PIP_UINT32_MAX 4294967295

#define PIP_MAX(A, B) (A > B ? A : B)
#define PIP_MIN(A, B) (A < B ? A : B)


typedef uint8_t pip_uint8;
typedef uint16_t pip_uint16;
typedef uint32_t pip_uint32;
typedef uint64_t pip_uint64;

typedef int32_t pip_int32;

typedef struct in_addr pip_in_addr;
typedef struct in6_addr pip_in6_addr;

typedef enum : pip_uint8 {
    pip_tcp_status_closed,
    /* received SYN wait response */
    pip_tcp_status_wait_establishing,
    pip_tcp_status_establishing,
    pip_tcp_status_established,
    pip_tcp_status_fin_wait_1,
    pip_tcp_status_fin_wait_2,
    /* ignore pip_tcp_status_time_wait, */
    pip_tcp_status_close_wait,
    
    pip_tcp_status_released,
    
} pip_tcp_status;


static inline pip_uint64 get_current_time() {
    auto now = std::chrono::steady_clock::now();
    auto now_millisec = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    return pip_uint64(now_millisec);
}


#ifndef __APPLE__

/*
 * Structure of an internet header, naked of options.
 */
struct ip {
#ifdef _IP_VHL
    pip_uint8  ip_vhl;                 /* version << 4 | header length >> 2 */
#else
#if BYTE_ORDER == LITTLE_ENDIAN
    pip_uint8   ip_hl : 4,                /* header length */
        ip_v : 4;                     /* version */
#else
    pip_uint8   ip_v : 4,                 /* version */
        ip_hl : 4;                    /* header length */
#endif
#endif /* not _IP_VHL */
    pip_uint8  ip_tos;                 /* type of service */
    pip_uint16 ip_len;                 /* total length */
    pip_uint16 ip_id;                  /* identification */
    pip_uint16 ip_off;                 /* fragment offset field */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
    pip_uint8  ip_ttl;                 /* time to live */
    pip_uint8  ip_p;                   /* protocol */
    pip_uint16 ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst;  /* source and dest address */
};

/*
 * Definition for internet protocol version 6.
 * RFC 2460
 */

struct ip6_hdr {
    union {
        struct ip6_hdrctl {
            pip_uint32 ip6_un1_flow; /* 20 bits of flow-ID */
            pip_uint16 ip6_un1_plen; /* payload length */
            pip_uint8  ip6_un1_nxt;  /* next header */
            pip_uint8  ip6_un1_hlim; /* hop limit */
        } ip6_un1;
        pip_uint8 ip6_un2_vfc;   /* 4 bits version, top 4 bits class */
    } ip6_ctlun;
    struct in6_addr ip6_src;        /* source address */
    struct in6_addr ip6_dst;        /* destination address */
};

/*
 * TCP header.
 * Per RFC 793, September, 1981.
 */
struct tcphdr {
    pip_uint16  th_sport;       /* source port */
    pip_uint16  th_dport;       /* destination port */
    pip_uint32 th_seq;                 /* sequence number */
    pip_uint32 th_ack;                 /* acknowledgement number */
#if __DARWIN_BYTE_ORDER == __DARWIN_LITTLE_ENDIAN
    pip_uint8    th_x2 : 4,        /* (unused) */
        th_off : 4;                   /* data offset */
#else
    pip_uint8    th_off : 4,       /* data offset */
        th_x2 : 4;                    /* (unused) */
#endif
    pip_uint8   th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_AE   0x100                   /* maps into th_x2 */
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_FLAGS_ALL    (TH_FLAGS|TH_PUSH)
#define TH_ACCEPT       (TH_FIN|TH_SYN|TH_RST|TH_ACK)
#define TH_ACE          (TH_AE|TH_CWR|TH_ECE)

    pip_uint16  th_win;         /* window */
    pip_uint16  th_sum;         /* checksum */
    pip_uint16  th_urp;         /* urgent pointer */
};


/*
 * Udp protocol header.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
    pip_uint16 uh_sport;               /* source port */
    pip_uint16 uh_dport;               /* destination port */
    pip_uint16 uh_ulen;                /* udp length */
    pip_uint16 uh_sum;                 /* udp checksum */
};


#endif // !__APPLE__



#endif /* pip_type_h */
