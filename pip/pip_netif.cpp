//
//  pip_netif.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_netif.hpp"
#include "pip_tcp.hpp"
#include "pip_udp.hpp"
#include "pip_icmp.hpp"

#include "pip_checksum.hpp"
#include <iostream>
#include <mutex>
#include "pip_ip_header.hpp"
#include "pip_debug.hpp"

using namespace std;

mutex _lock;
static pip_netif * netif = NULL;

pip_netif::pip_netif() {
    this->_identifer = 0;
    this->_isn = 1;
    
    this->output_ip_data_callback = NULL;
    this->new_tcp_connect_callback = NULL;
    this->received_udp_data_callback = NULL;
    
}

pip_netif * pip_netif::shared() {
    
    if (netif == NULL) {
        _lock.lock();
        if (netif == NULL) {
            netif = new pip_netif();
        }
        _lock.unlock();
    }
    
    return netif;
}

void pip_netif::input(const void *buffer) {
    
    pip_ip_header * ip_header = new pip_ip_header(buffer);
#if PIP_DEBUG
    pip_debug_output_ipheader(ip_header, "ip_input");
#endif
    
    
    if (ip_header->version == 4) {
        /// - 检测是否有options 不支持options
        if (ip_header->has_options) {
            delete ip_header;
            return;
        }
    }
    
    pip_uint8 * data = ((pip_uint8 *)buffer) + ip_header->headerlen;
    switch (ip_header->protocol) {
        case IPPROTO_UDP:
            pip_udp::input(data, ip_header);
            break;
            
        case IPPROTO_TCP:
            pip_tcp::input(data, ip_header);
            break;
            
        case IPPROTO_ICMP:
            pip_icmp::input(data, ip_header);
            break;
            
        default:
            delete ip_header;
            break;
    }
}


void pip_netif::output4(pip_buf * buf, pip_uint8 proto, pip_in_addr src, pip_in_addr dst) {
    
    pip_buf * ip_head_buf = new pip_buf(sizeof(struct ip));
    ip_head_buf->set_next(buf);
    
    struct ip *hdr = (struct ip *)ip_head_buf->payload;
    hdr->ip_v = 4;
    hdr->ip_hl = 5;
    hdr->ip_tos = 0;
    hdr->ip_len = htons(ip_head_buf->total_len);
    hdr->ip_id = htons(this->_identifer++);
    hdr->ip_off = htons(IP_DF);
    hdr->ip_ttl = 64;
    hdr->ip_p = proto;
    hdr->ip_sum = 0;
    hdr->ip_src = src;
    hdr->ip_dst = dst;
    hdr->ip_sum = htons(pip_ip_checksum(hdr, sizeof(struct ip)));
    
    if (this->output_ip_data_callback) {
        this->output_ip_data_callback(this, ip_head_buf);
    }
    
#if PIP_DEBUG
    pip_debug_output_ip(hdr, "ip_output");
#endif
    
    ip_head_buf->set_next(NULL);
    delete ip_head_buf;
}

void pip_netif::output6(pip_buf * buf, pip_uint8 proto, pip_in6_addr src, pip_in6_addr dst) {
 
    pip_buf * ip_head_buf = new pip_buf(sizeof(struct ip6_hdr));
    ip_head_buf->set_next(buf);
    
    struct ip6_hdr *hdr = (struct ip6_hdr *)ip_head_buf->payload;
    
    // version | traffic class | flow label
    pip_uint32 vtf = htonl(0x60000000);
    memcpy(ip_head_buf->payload, &vtf, 4);
    
//    hdr->ip6_ctlun.ip6_un2_vfc = 6 << 4 | 0;
//    hdr->ip6_ctlun.ip6_un1.ip6_un1_flow = 0; /// 不知道该怎么设置
    hdr->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(buf->total_len);
    hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt = proto;
    hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;
    
    hdr->ip6_src = src;
    hdr->ip6_dst = dst;
    
    if (this->output_ip_data_callback) {
        this->output_ip_data_callback(this, ip_head_buf);
    }
    
    ip_head_buf->set_next(NULL);
    delete ip_head_buf;
}

void pip_netif::timer_tick() {
    if (this->_isn >= PIP_UINT32_MAX) {
        this->_isn = 0;
    } else {
        this->_isn += 1;
    }
    
    pip_tcp::timer_tick();
}

pip_uint32 pip_netif::get_isn() {
    return this->_isn;
}
