//
//  pip_ip_header.cpp
//
//  Created by Plumk on 2022/1/15.
//

#include "pip_ip_header.h"
#include "pip_debug.h"

pip_ip_header::pip_ip_header(const void* bytes) {

    struct ip* hdr = (struct ip*)bytes;
    if (hdr->ip_v == 4) {
        this->_version = 4;
        this->_protocol = hdr->ip_p;
        this->_has_options = hdr->ip_hl > 5;
        this->_ttl = hdr->ip_ttl;
        this->_headerlen = hdr->ip_hl * 4;
        this->_datalen = ntohs(hdr->ip_len) - this->_headerlen;

        this->_ip_src = hdr->ip_src;
        this->_ip_dst = hdr->ip_dst;

        this->_src_str = (char*)calloc(INET_ADDRSTRLEN, sizeof(char));
        this->_dst_str = (char*)calloc(INET_ADDRSTRLEN, sizeof(char));

        inet_ntop(AF_INET, &this->_ip_src, this->_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &this->_ip_dst, this->_dst_str, INET_ADDRSTRLEN);

    }
    else {

        struct ip6_hdr* hdr = (struct ip6_hdr*)bytes;

        this->_version = hdr->ip6_ctlun.ip6_un2_vfc >> 4;
        this->_protocol = hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        this->_has_options = false;
        this->_ttl = hdr->ip6_ctlun.ip6_un1.ip6_un1_hlim;
        this->_headerlen = 40;
        this->_datalen = ntohs(hdr->ip6_ctlun.ip6_un1.ip6_un1_plen);

        this->_ip6_src = hdr->ip6_src;
        this->_ip6_dst = hdr->ip6_dst;


        this->_src_str = (char*)calloc(INET6_ADDRSTRLEN, sizeof(char));
        this->_dst_str = (char*)calloc(INET6_ADDRSTRLEN, sizeof(char));

        inet_ntop(AF_INET6, &this->_ip6_src, this->_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &this->_ip6_dst, this->_dst_str, INET6_ADDRSTRLEN);
    }
}

pip_ip_header::~pip_ip_header() {
    
    if (this->_src_str != nullptr) {
        free(this->_src_str);
        this->_src_str = nullptr;
    }
    
    if (this->_dst_str != nullptr) {
        free(this->_dst_str);
        this->_dst_str = nullptr;
    }
}


/// 生成32位标识
pip_uint32 pip_ip_header::generate_iden() {
    
    if (this->_version == 4) {
        return this->_ip_src.s_addr ^ this->_ip_dst.s_addr ^ 4;
    }
    
    pip_uint32 *s_addrs = (pip_uint32 *)&this->_ip6_src;
    pip_uint32 *d_addrs = (pip_uint32 *)&this->_ip6_dst;
    
    return (s_addrs[0] ^ s_addrs[1] ^ s_addrs[2] ^ s_addrs[3] ^
            d_addrs[0] ^ d_addrs[1] ^ d_addrs[2] ^ d_addrs[3] ^ 6);
}
