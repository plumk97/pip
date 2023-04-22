//
//  pip_ip_header.cpp
//
//  Created by Plumk on 2022/1/15.
//

#include "pip_ip_header.hpp"
#include "pip_debug.hpp"

pip_ip_header::pip_ip_header(const void * bytes) {
    
    
    struct ip *hdr = (struct ip*)bytes;
    if (hdr->ip_v == 4) {
        this->version = 4;
        this->protocol = hdr->ip_p;
        this->has_options = hdr->ip_hl > 5;
        this->ttl = hdr->ip_ttl;
        this->headerlen = hdr->ip_hl * 4;
        this->datalen = ntohs(hdr->ip_len) - this->headerlen;
        
        this->ip_src = hdr->ip_src;
        this->ip_dst = hdr->ip_dst;
        
        this->src_str = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
        this->dst_str = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
        
        inet_ntop(AF_INET, &this->ip_src, this->src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &this->ip_dst, this->dst_str, INET_ADDRSTRLEN);
        
    } else {
        
        struct ip6_hdr *hdr = (struct ip6_hdr*)bytes;
        
        this->version = hdr->ip6_ctlun.ip6_un2_vfc >> 4;
        this->protocol = hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        this->has_options = false;
        this->ttl = hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
        this->headerlen = 40;
        this->datalen = ntohs(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);
        
        this->ip6_src = hdr->ip6_src;
        this->ip6_dst = hdr->ip6_dst;
        
        
        this->src_str = (char *)calloc(INET6_ADDRSTRLEN, sizeof(char));
        this->dst_str = (char *)calloc(INET6_ADDRSTRLEN, sizeof(char));
        
        inet_ntop(AF_INET6, &this->ip6_src, this->src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &this->ip6_dst, this->dst_str, INET6_ADDRSTRLEN);
    }
}



pip_ip_header::~pip_ip_header() {
    
    if (this->src_str != nullptr) {
        free(this->src_str);
        this->src_str = nullptr;
    }
    
    if (this->dst_str != nullptr) {
        free(this->dst_str);
        this->dst_str = nullptr;
    }
}


/// 生成32位标识
pip_uint32 pip_ip_header::generate_iden() {
    
    if (this->version == 4) {
        return this->ip_src.s_addr ^ this->ip_dst.s_addr ^ 4;
    }
    
    pip_uint32 *s_addrs = (pip_uint32 *)&this->ip6_src;
    pip_uint32 *d_addrs = (pip_uint32 *)&this->ip6_dst;
    
    return (s_addrs[0] ^ s_addrs[1] ^ s_addrs[2] ^ s_addrs[3] ^
            d_addrs[0] ^ d_addrs[1] ^ d_addrs[2] ^ d_addrs[3] ^ 6);
}
