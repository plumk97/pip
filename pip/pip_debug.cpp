//
//  pip_debug.cpp
//
//  Created by Plumk on 2022/1/9.
//

#include "pip_debug.h"

void pip_debug_output_iden(const char *iden) {
#if PIP_DEBUG
    printf("[%s]: \n", iden);
#endif
}

/// 打印IP
/// @param hdr _
/// @param iden 标识
void pip_debug_output_ip(struct ip *hdr, const char *iden) {
    
#if PIP_DEBUG
    pip_debug_output_iden(iden);
    printf("ip_hl: %u \n", hdr->ip_hl);
    printf("ip_v: %u \n", hdr->ip_v);
    printf("ip_tos: %u \n", hdr->ip_tos);
    printf("ip_len: %u \n", ntohs(hdr->ip_len));
    printf("ip_id: %u \n", ntohs(hdr->ip_id));
    printf("ip_off: %u \n", ntohs(hdr->ip_off));
    printf("ip_ttl: %u \n", hdr->ip_ttl);
    printf("ip_p: %u \n", hdr->ip_p);
    printf("ip_sum: %u \n", ntohs(hdr->ip_sum));
    printf("ip_src: %u \n", ntohl(hdr->ip_src.s_addr));
    printf("ip_src_str: %s \n", inet_ntoa(hdr->ip_src));
    printf("ip_dst: %u \n", ntohl(hdr->ip_dst.s_addr));
    printf("ip_dst_str: %s \n", inet_ntoa(hdr->ip_dst));
    printf("\n\n");
#endif
    
}

/// 打印IP
/// @param header _
/// @param iden 标识
void pip_debug_output_ipheader(pip_ip_header *header, const char *iden) {
    
#if PIP_DEBUG
    pip_debug_output_iden(iden);
    printf("version: %u \n", header->version());
    printf("protocol: %u \n", header->protocol());
    printf("has_options: %u \n", header->has_options());
    printf("ttl: %u \n", header->ttl());
    printf("headerlen: %u \n", header->headerlen());
    printf("datalen: %u \n", header->datalen());
    printf("src_str: %s \n", header->src_str());
    printf("dst_str: %s \n", header->dst_str());
    printf("\n\n");
#endif
    
}

/// 打印UDP
/// @param hdr _
/// @param iden 标识
void pip_debug_output_udp(struct udphdr *hdr, const char *iden) {
    
#if PIP_DEBUG
    pip_debug_output_iden(iden);
    printf("uh_sport: %u \n", ntohs(hdr->uh_sport));
    printf("uh_dport: %u \n", ntohs(hdr->uh_dport));
    printf("uh_ulen: %u \n", ntohs(hdr->uh_ulen));
    printf("uh_sum: %u \n", ntohs(hdr->uh_sum));
    printf("datalen: %lu \n", ntohs(hdr->uh_ulen) - sizeof(struct udphdr));
    printf("\n\n");
#endif
}


/// 打印TCP
/// @param tcp _
/// @param packet _
/// @param iden _
void pip_debug_output_tcp(pip_tcp * tcp, pip_tcp_packet * packet, const char *iden) {
    
#if PIP_DEBUG
    tcphdr * hdr = packet->hdr();
    pip_debug_output_tcp(tcp, hdr, packet->payload_len(), iden);
#endif
    
}

void pip_debug_output_tcp(pip_tcp * tcp, struct tcphdr *hdr, pip_uint32 datalen, const char *iden) {
    
#if PIP_DEBUG
    if (tcp == nullptr) {
        return;
    }
    
    pip_ip_header * ip_header = tcp->ip_header();
    pip_debug_output_iden(iden);
    if (ip_header) {
        printf("src %s port %u\n", ip_header->src_str(), tcp->src_port());
        printf("dst %s port %u\n", ip_header->dst_str(), tcp->dst_port());
    }
    
    printf("iden: %u\n", tcp->iden());
    
    printf("flags: ");
    if (hdr->th_flags & TH_FIN) {
        printf("FIN ");
    }

    if (hdr->th_flags & TH_SYN) {
        printf("SYN ");
    }

    if (hdr->th_flags & TH_RST) {
        printf("RST ");
    }

    if (hdr->th_flags & TH_PUSH) {
        printf("PUSH ");
    }

    if (hdr->th_flags & TH_ACK) {
        printf("ACK ");
    }

    if (hdr->th_flags & TH_URG) {
        printf("URG ");
    }

    if (hdr->th_flags & TH_ECE) {
        printf("ECE ");
    }

    if (hdr->th_flags & TH_CWR) {
        printf("CWR ");
    }
    printf("\n");
    
    printf("win: %u\n", tcp->wind());
    printf("ack: %u\n", tcp->ack());
    printf("seq: %u\n", tcp->seq());
    
    printf("opp_win: %u\n", ntohs(hdr->th_win));
    printf("opp_ack: %u\n", ntohl(hdr->th_ack));
    printf("opp_seq: %u\n", ntohl(hdr->th_seq));
    
    printf("datalen: %d\n", datalen);
    printf("\n\n");
#endif
}


/// 打印ICMP
/// @param hdr _
/// @param iden _
void pip_debug_output_icmp(struct icmp *hdr, const char *iden) {
    
#if PIP_DEBUG
    if (hdr == nullptr) {
        return;
    }
    
    pip_debug_output_iden(iden);
    printf("icmp_type: %u\n", hdr->icmp_type);
    printf("icmp_code: %u\n", hdr->icmp_code);
    printf("icmp_cksum: %u\n", hdr->icmp_cksum);
    printf("\n\n");
#endif
}
