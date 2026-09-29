//
//  icmp_echo.cpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "icmp_echo.hpp"

#include <cstring>
#include <vector>

#include "pip.h"
#include "log.hpp"

namespace icmp_echo {

namespace {

constexpr pip_uint8 k_icmp_echo_request = 8;
constexpr pip_uint8 k_icmp_echo_reply = 0;
constexpr pip_uint8 k_icmp6_echo_request = 128;
constexpr pip_uint8 k_icmp6_echo_reply = 129;

void on_received(pip_netif & netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, const char * dst_ip, pip_uint8 ttl) {
    (void)netif;
    (void)ttl;
    
    // type(1) + code(1) + checksum(2) + identifier(2) + sequence(2)
    if (buffer_len < 8) {
        return;
    }
    
    const pip_uint8 * msg = (const pip_uint8 *)buffer;
    bool is_ipv6 = strchr(src_ip, ':') != nullptr;
    
    pip_uint8 reply_type;
    if (!is_ipv6 && msg[0] == k_icmp_echo_request) {
        reply_type = k_icmp_echo_reply;
    } else if (is_ipv6 && msg[0] == k_icmp6_echo_request) {
        reply_type = k_icmp6_echo_reply;
    } else {
        return;
    }
    
    // 原样返回 identifier / sequence / data, 校验和由 pip 计算
    std::vector<pip_uint8> reply(msg, msg + buffer_len);
    reply[0] = reply_type;
    
    VLOG("icmp echo %s -> %s, %u bytes", src_ip, dst_ip, buffer_len);
    pip_icmp::output(reply.data(), (pip_uint16)reply.size(), dst_ip, src_ip);
}

} // namespace

void start() {
    pip_netif::shared().received_icmp_data_callback = on_received;
}

}
