//
//  pip_tcp_input.cpp
//  example
//
//  Created by ayo on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "pip_tcp_manager.h"

void pip_tcp::input(const void * bytes, std::shared_ptr<pip_ip_header> ip_header) {
    struct tcphdr *hdr = (struct tcphdr *)bytes;

    pip_uint16 ip_datalen = ip_header->datalen();
    pip_uint16 tcp_header_len = hdr->th_off * 4;
    if (ip_datalen < sizeof(struct tcphdr) || hdr->th_off < 5 || tcp_header_len > ip_datalen) {
        return;
    }

    pip_uint16 datalen = ip_datalen - tcp_header_len;
    pip_uint16 dport = ntohs(hdr->th_dport);
    pip_uint16 sport = ntohs(hdr->th_sport);
    
    if (!(dport >= 1 && dport <= 65535)) {
        return;
    }
    
    
    pip_uint32 iden = ip_header->generate_iden() ^ dport ^ sport;
    std::shared_ptr<pip_tcp> tcp = pip_tcp_manager::shared().fetch_tcp(iden);
    if (tcp == nullptr) {
        
        if (!(hdr->th_flags & TH_SYN) || pip_tcp_manager::shared().size() >= PIP_TCP_MAX_CONNS) {
            
            // 不存在的连接 直接返回RST
            tcp = std::make_shared<pip_tcp>();
            tcp->set_iden(iden);
            tcp->set_seq(iden);
            tcp->set_ip_header(ip_header);
            
            tcp->set_src_port(ntohs(hdr->th_sport));
            tcp->set_dst_port(dport);
            
            tcp->set_seq(ntohl(hdr->th_ack));
            tcp->set_ack(increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen));
            
            auto packet = std::make_shared<pip_tcp_packet>(tcp, TH_RST | TH_ACK, nullptr, nullptr);
            tcp->send_packet(packet);
            tcp->release();
            
            return;
        }
        
        
        tcp = std::make_shared<pip_tcp>();
        tcp->set_iden(iden);
        tcp->set_seq(iden);
        tcp->set_ip_header(ip_header);

        tcp->set_src_port(sport);
        tcp->set_dst_port(dport);
        pip_tcp_manager::shared().add_tcp(iden, tcp);
        
    }

#if PIP_DEBUG
    pip_debug_output_tcp(tcp, hdr, datalen, "tcp_input");
#endif
    tcp->_mutex.lock();
    tcp->handle_input(ip_header, hdr, bytes, datalen);
    tcp->_mutex.unlock();
    tcp->process_events();
}
