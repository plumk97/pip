//
//  pip_icmp.cpp
//
//  Created by Plumk on 2022/1/13.
//

#include "pip_icmp.h"
#include "../pip_netif.h"
#include "../pip_debug.h"


void pip_icmp::input(const void *bytes, pip_ip_header *ip_header) {
    
    pip_uint16 datalen = ip_header->datalen();
    
#if PIP_DEBUG
    struct icmp *hdr = (struct icmp *)bytes;
    pip_debug_output_icmp(hdr, "icmp_input");
#endif
    
    pip_netif * netif = pip_netif::shared();
    if (netif->received_icmp_data_callback) {
        netif->received_icmp_data_callback(netif, (void *)bytes, datalen, ip_header->src_str(), ip_header->dst_str(), ip_header->ttl());
    }
    
    delete ip_header;
}


void pip_icmp::output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, const char * dst_ip) {
    
    pip_buf * payload_buf = new pip_buf((void *)buffer, buffer_len, 0);
    
    pip_in_addr src;
    pip_in6_addr src6;
    
    if (inet_pton(AF_INET, src_ip, &src) > 0) {
        /// IPv4地址
        pip_in_addr dst;
        inet_pton(AF_INET, dst_ip, &dst);
        pip_netif::shared()->output4(payload_buf, IPPROTO_ICMP, src, dst);
        
    } else if (inet_pton(AF_INET6, src_ip, &src6) > 0) {
        /// IPv6地址
        pip_in6_addr dst6;
        inet_pton(AF_INET6, dst_ip, &dst6);
        pip_netif::shared()->output6(payload_buf, IPPROTO_ICMP, src6, dst6);
    }
    
    delete payload_buf;
    
}
