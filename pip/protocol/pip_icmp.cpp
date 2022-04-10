//
//  pip_icmp.cpp
//
//  Created by Plumk on 2022/1/13.
//

#include "pip_icmp.hpp"
#include "pip_netif.hpp"
#include "pip_debug.hpp"


void pip_icmp::input(const void *bytes, struct ip *ip) {
    
    
    
    char * src_ip = (char *)calloc(15, sizeof(char));
    char * dest_ip = (char *)calloc(15, sizeof(char));
    strcpy(src_ip, inet_ntoa(ip->ip_src));
    strcpy(dest_ip, inet_ntoa(ip->ip_dst));
    
    pip_uint16 datalen = htons(ip->ip_len) - ip->ip_hl * 4;
    
#if PIP_DEBUG
    struct icmp *hdr = (struct icmp *)bytes;
    pip_debug_output_icmp(hdr, "icmp_input");
#endif
    
    pip_netif * netif = pip_netif::shared();
    if (netif->received_icmp_data_callback) {
        netif->received_icmp_data_callback(netif, (void *)bytes, datalen, src_ip, dest_ip);
    }
    
    free(src_ip);
    free(dest_ip);
}
