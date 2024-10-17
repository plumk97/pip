//
//  pip_tcp_packet.cpp
//
//  Created by Plumk on 2023/5/19.
//  Copyright © 2023 Plumk. All rights reserved.
//

#include "pip_tcp_packet.h"
#include "pip_tcp.h"

#include "../pip_checksum.h"

pip_tcp_packet::
pip_tcp_packet(std::shared_ptr<pip_tcp> tcp, pip_uint8 flags, std::shared_ptr<pip_buf> option_buf, std::shared_ptr<pip_buf> payload_buf) {
    
    this->_send_time = 0;
    this->_send_count = 0;
    
    // -- 赋值BUF
    auto head_buf = std::make_shared<pip_buf>(sizeof(struct tcphdr));
    pip_uint8 * buffer = (pip_uint8 *)head_buf->payload();
    memset(buffer, 0, head_buf->payload_len());
    
    if (option_buf != nullptr) {
        head_buf->set_next(option_buf);
        option_buf->set_next(payload_buf);
    } else if (payload_buf != nullptr) {
        head_buf->set_next(payload_buf);
    }
    
    
    this->_head_buf = head_buf;


    if (payload_buf) {
        this->_payload_len = payload_buf->total_len();
    } else {
        this->_payload_len = 0;
    }
    
    // - 填充头部
    pip_uint8 offset = 0;
    if (true) {
        // 源端口
        pip_uint8 len = sizeof(pip_uint16);
        pip_uint16 port = htons(tcp->dst_port());
        memcpy(buffer + offset, &port, len);
        
        offset += len;
    }
    
    if (true) {
        // 目标端口
        pip_uint8 len = sizeof(pip_uint16);
        pip_uint16 port = htons(tcp->src_port());
        memcpy(buffer + offset, &port, len);
        
        offset += len;
    }
    
    if (true) {
        // 序号
        pip_uint8 len = sizeof(pip_uint32);
        pip_uint32 seq = htonl(tcp->seq());
        memcpy(buffer + offset, &seq, len);
        
        offset += len;
    }
    
    if (true) {
        // 确认号
        pip_uint8 len = sizeof(pip_uint32);
        pip_uint32 ack = htonl(tcp->ack());
        memcpy(buffer + offset, &ack, len);
        
        offset += len;
    }
    
    
    if (true) {
        // 头部长度 保留 标识
        pip_uint8 len = sizeof(pip_uint16);
        pip_uint16 h_flags = 0;
        
        pip_uint16 headlen = head_buf->payload_len();
        if (option_buf != nullptr) {
            headlen += option_buf->payload_len();
        }
        
        h_flags = (headlen / 4) << 12;
        h_flags = h_flags | flags;
        h_flags = htons(h_flags);
        memcpy(buffer + offset, &h_flags, len);
        
        offset += len;
    }
    
    
    if (true) {
        // 窗口大小
        pip_uint8 len = sizeof(pip_uint16);
        pip_uint16 wind = htons(tcp->wind());
        memcpy(buffer + offset, &wind, len);
        
        offset += len;
    }
    
    // 校验和偏移
    pip_uint8 checksum_offset = offset;
    offset += sizeof(pip_uint16);
    
    // 紧急指针
    offset += sizeof(pip_uint16);
    
    
    if (true) {
        // 计算校验和
        pip_uint16 checksum = 0;
        if (tcp->ip_header()->version() == 4) {
            checksum = pip_inet_checksum_buf(head_buf, IPPROTO_TCP, tcp->ip_header()->ip_dst(), tcp->ip_header()->ip_src());
        } else {
            checksum = pip_inet6_checksum_buf(head_buf, IPPROTO_TCP, tcp->ip_header()->ip6_dst(), tcp->ip_header()->ip6_src());
        }
        checksum = htons(checksum);
        memcpy(buffer + checksum_offset, &checksum, sizeof(pip_uint16));
    }
}

pip_tcp_packet::
~pip_tcp_packet() {

}

struct tcphdr *
pip_tcp_packet::hdr() {
    return (struct tcphdr *)this->head_buf()->payload();
}

void
pip_tcp_packet::sended() {
    this->_send_time = get_current_time();
    this->_send_count += 1;
}
