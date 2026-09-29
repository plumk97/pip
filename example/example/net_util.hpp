//
//  net_util.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef net_util_hpp
#define net_util_hpp

#include <string>
#include <sys/socket.h>

#include "options.hpp"

/// 出站连接的目标地址
struct endpoint {
    struct sockaddr_storage addr = {};
    socklen_t len = 0;
    
    int family() const { return addr.ss_family; }
    std::string str() const;
};

/// 计算出站目标: 配置了 redirect 时使用 redirect 地址, 否则使用原目标地址, 端口不变
bool resolve_target(const options & opts, const char * dst_ip, unsigned short dst_port, endpoint & out);

/// 创建绑定到出站网卡的 socket, 失败返回 -1
int create_outbound_socket(const options & opts, int family, int type);

/// 带超时的 connect, 成功后 socket 恢复为阻塞模式
bool connect_with_timeout(int fd, const endpoint & ep, int timeout_ms);

#endif /* net_util_hpp */
