//
//  pip_udp.cpp
//
//  Created by Plumk on 2022/1/13.
//

#include "pip_udp.h"
#include "../pip_debug.h"
#include "../pip_netif.h"
#include "../pip_checksum.h"

void pip_udp::input(const void *bytes, pip_ip_header *ip_header) {
    
    struct udphdr *hdr = (struct udphdr *)bytes;
    
    pip_uint16 src_port = ntohs(hdr->uh_sport);
    pip_uint16 dst_port = ntohs(hdr->uh_dport);
    
    pip_uint16 datalen = ntohs(hdr->uh_ulen) - sizeof(struct udphdr);
    void * data = (pip_uint8 *)bytes + sizeof(struct udphdr);
    
    pip_netif * netif = pip_netif::shared();
    if (netif->received_udp_data_callback) {
        netif->received_udp_data_callback(netif, data, datalen, ip_header->src_str(), src_port, ip_header->dst_str(), dst_port, ip_header->version());
    }
    
#if PIP_DEBUG
    pip_debug_output_udp(hdr, "udp_input");
#endif
    
    delete ip_header;
}

void pip_udp::output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port) {
 
    pip_buf * payload_buf = new pip_buf((void *)buffer, buffer_len, 0);
    pip_buf * udp_head_buf = new pip_buf(sizeof(struct udphdr));
    udp_head_buf->set_next(payload_buf);
    
    pip_uint16 total_len = sizeof(struct udphdr) + buffer_len;
    
    struct udphdr *hdr = (struct udphdr*)udp_head_buf->payload();
    hdr->uh_dport = htons(dst_port);
    hdr->uh_sport = htons(src_port);
    hdr->uh_ulen = htons(total_len);
    hdr->uh_sum = 0;
    
    pip_in_addr src;
    pip_in6_addr src6;
    
    if (inet_pton(AF_INET, src_ip, &src) > 0) {
        /// IPv4地址
        pip_in_addr dst;
        inet_pton(AF_INET, dst_ip, &dst);
        
        hdr->uh_sum = pip_inet_checksum_buf(udp_head_buf, IPPROTO_UDP, src, dst);
        hdr->uh_sum = htons(hdr->uh_sum);
        
        pip_netif::shared()->output4(udp_head_buf, IPPROTO_UDP, src, dst);
        
    } else if (inet_pton(AF_INET6, src_ip, &src6) > 0) {
        /// IPv6地址
        pip_in6_addr dst6;
        inet_pton(AF_INET6, dst_ip, &dst6);
        
        hdr->uh_sum = pip_inet6_checksum_buf(udp_head_buf, IPPROTO_UDP, src6, dst6);
        hdr->uh_sum = htons(hdr->uh_sum);
        
        pip_netif::shared()->output6(udp_head_buf, IPPROTO_UDP, src6, dst6);
    }
    

    delete udp_head_buf;
    
}
