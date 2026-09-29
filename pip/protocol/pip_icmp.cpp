//
//  pip_icmp.cpp
//
//  Created by Plumk on 2022/1/13.
//

#include "pip_icmp.h"
#include "../pip_netif.h"
#include "../pip_checksum.h"


void pip_icmp::input(const void *bytes, std::shared_ptr<pip_ip_header> ip_header) {
    
    pip_uint16 datalen = ip_header->datalen();
    
    pip_netif & netif = pip_netif::shared();
    if (netif.received_icmp_data_callback) {
        netif.received_icmp_data_callback(netif, (void *)bytes, datalen, ip_header->src_str(), ip_header->dst_str(), ip_header->ttl());
    }
    
}


void pip_icmp::output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, const char * dst_ip) {
    
    /// type(1) + code(1) + checksum(2)
    if (buffer == nullptr || buffer_len < 4) {
        return;
    }
    
    auto payload_buf = std::make_shared<pip_buf>(buffer, buffer_len, 1);
    pip_uint8 * msg = (pip_uint8 *)payload_buf->payload();
    msg[2] = 0;
    msg[3] = 0;
    
    pip_in_addr src;
    pip_in6_addr src6;
    
    if (inet_pton(AF_INET, src_ip, &src) > 0) {
        /// IPv4地址
        pip_in_addr dst;
        inet_pton(AF_INET, dst_ip, &dst);
        
        pip_uint16 checksum = htons(pip_ip_checksum(msg, buffer_len));
        memcpy(msg + 2, &checksum, sizeof(checksum));
        
        pip_netif::shared().output4(payload_buf, IPPROTO_ICMP, src, dst);
        
    } else if (inet_pton(AF_INET6, src_ip, &src6) > 0) {
        /// IPv6地址 校验和包含伪头部 (RFC 4443)
        pip_in6_addr dst6;
        inet_pton(AF_INET6, dst_ip, &dst6);
        
        pip_uint16 checksum = htons(pip_inet6_checksum(msg, IPPROTO_ICMPV6, src6, dst6, buffer_len));
        memcpy(msg + 2, &checksum, sizeof(checksum));
        
        pip_netif::shared().output6(payload_buf, IPPROTO_ICMPV6, src6, dst6);
    }
    
}
