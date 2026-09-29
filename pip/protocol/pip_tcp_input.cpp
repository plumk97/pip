//
//  pip_tcp_input.cpp
//
//  Created by Plumk on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "pip_tcp_manager.h"

void pip_tcp::input(const void * bytes, std::shared_ptr<pip_ip_header> ip_header) {
    pip_uint16 ip_datalen = ip_header->datalen();
    if (ip_datalen < sizeof(struct tcphdr)) {
        return;
    }

    struct tcphdr *hdr = (struct tcphdr *)bytes;
    pip_uint16 tcp_header_len = hdr->th_off * 4;
    if (hdr->th_off < 5 || tcp_header_len > ip_datalen) {
        return;
    }

    pip_uint16 datalen = ip_datalen - tcp_header_len;
    pip_uint16 dport = ntohs(hdr->th_dport);
    pip_uint16 sport = ntohs(hdr->th_sport);
    
    if (!(dport >= 1 && dport <= 65535)) {
        return;
    }
    
    
    pip_tcp_key key(ip_header, sport, dport);
    std::shared_ptr<pip_tcp> tcp = pip_tcp_manager::shared().fetch_tcp(key);
    if (tcp == nullptr) {
        
        if (!(hdr->th_flags & TH_SYN) || pip_tcp_manager::shared().size() >= PIP_TCP_MAX_CONNS) {
            
            // 不能对 RST 回复 RST
            if (hdr->th_flags & TH_RST) {
                return;
            }
            
            // 不存在的连接 直接返回RST
            tcp = std::make_shared<pip_tcp>();
            tcp->_key = key;
            tcp->_ip_header = ip_header;
            
            tcp->_src_port = sport;
            tcp->_dst_port = dport;
            
            pip_uint8 flags = TH_RST;
            if (hdr->th_flags & TH_ACK) {
                tcp->_seq = ntohl(hdr->th_ack);
                tcp->_ack = 0;
            } else {
                tcp->_seq = 0;
                tcp->_ack = increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen);
                flags |= TH_ACK;
            }
            
            std::unique_lock<std::mutex> lock(tcp->_mutex);
            auto packet = tcp->create_tcp_packet(flags, nullptr, nullptr);
            tcp->send_packet(packet);
            tcp->release();
            tcp->finish(lock);
            
            return;
        }
        
        
        tcp = std::make_shared<pip_tcp>();
        tcp->_key = key;
        tcp->_seq = pip_tcp_generate_isn();
        tcp->_ip_header = ip_header;

        tcp->_src_port = sport;
        tcp->_dst_port = dport;
        tcp = pip_tcp_manager::shared().add_tcp_if_absent(key, tcp);
        
    }

#if PIP_DEBUG
    pip_debug_output_tcp(tcp, hdr, datalen, "tcp_input");
#endif
    std::unique_lock<std::mutex> lock(tcp->_mutex);
    tcp->handle_input(ip_header, hdr, bytes, datalen);
    tcp->finish(lock);
}
