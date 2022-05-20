//
//  pip_ip_header.cpp
//
//  Created by Plumk on 2022/1/15.
//

#include "pip_ip_header.hpp"


pip_ip_header::pip_ip_header(const void * bytes) {
    
    struct ip *hdr = (struct ip*)bytes;
    if (hdr->ip_v == 4) {
        
        this->version = 4;
        this->protocol = hdr->ip_p;
        this->has_options = hdr->ip_hl > 5;
        this->ttl = hdr->ip_ttl;
        this->headerlen = hdr->ip_hl * 4;
        this->datalen = ntohs(hdr->ip_len);
        
        this->src = ntohl(hdr->ip_src.s_addr);
        this->dest = ntohl(hdr->ip_dst.s_addr);
        
        this->src_str = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
        this->dest_str = (char *)calloc(INET_ADDRSTRLEN, sizeof(char));
        
        inet_ntop(AF_INET, &hdr->ip_src.s_addr, this->src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &hdr->ip_dst.s_addr, this->dest_str, INET_ADDRSTRLEN);
        
    } else {
        this->version = 6;
        
        this->src_str = NULL;
        this->dest_str = NULL;
    }
}



pip_ip_header::~pip_ip_header() {
    
    
    if (this->src_str != NULL) {
        free(this->src_str);
        this->src_str = NULL;
    }
    
    if (this->dest_str != NULL) {
        free(this->dest_str);
        this->dest_str = NULL;
    }
}
