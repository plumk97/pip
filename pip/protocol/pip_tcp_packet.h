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
#include "../pip_macro.h"

class pip_tcp;
class pip_tcp_packet {
    
    /// 头部 buf
    PIP_READONLY_PROPERTY(std::shared_ptr<pip_buf>, head_buf);
    
    /// 数据长度
    PIP_READONLY_PROPERTY(pip_uint32, payload_len);
    
    /// 发送时间
    PIP_READONLY_PROPERTY(pip_uint64, send_time);
    
    /// 发送次数
    PIP_READONLY_PROPERTY(pip_uint8, send_count);
    
public:
    ~pip_tcp_packet();
    pip_tcp_packet(std::shared_ptr<pip_tcp> tcp, pip_uint8 flags, std::shared_ptr<pip_buf> option_buf, std::shared_ptr<pip_buf> payload_buf);
  
    struct tcphdr * hdr();
    /// 发送一次调用一次
    void sended();
    
};

#endif /* pip_tcp_packet_hpp */
