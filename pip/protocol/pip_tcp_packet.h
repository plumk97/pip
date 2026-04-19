//
//  pip_tcp_packet.hpp
//
//  Created by Plumk on 2023/5/19.
//  Copyright © 2023 Plumk. All rights reserved.
//

#ifndef pip_tcp_packet_hpp
#define pip_tcp_packet_hpp

#include "../pip_type.h"
#include "../pip_buf.h"
#include "../pip_ip_header.h"

class pip_tcp;
class pip_tcp_packet {
    
    /// 头部 buf
    std::shared_ptr<pip_buf> _head_buf;
    
    /// 数据长度
    pip_uint32 _payload_len;
    
    /// 发送时间
    pip_uint64 _send_time;
    
    /// 发送次数
    pip_uint8 _send_count;
    
public:
    ~pip_tcp_packet();
    pip_tcp_packet(std::shared_ptr<pip_ip_header> ip_header,
                   pip_uint16 src_port,
                   pip_uint16 dst_port,
                   pip_uint32 seq,
                   pip_uint32 ack,
                   pip_uint32 wind,
                   pip_uint8 flags,
                   std::shared_ptr<pip_buf> option_buf,
                   std::shared_ptr<pip_buf> payload_buf);
  
    struct tcphdr * hdr();
    /// 发送一次调用一次
    void sended();

    std::shared_ptr<pip_buf> head_buf() { return this->_head_buf; }
    pip_uint32 payload_len() { return this->_payload_len; }
    pip_uint64 send_time() { return this->_send_time; }
    pip_uint8 send_count() { return this->_send_count; }
    
};

#endif /* pip_tcp_packet_hpp */
