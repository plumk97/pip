//
//  udp_proxy.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef udp_proxy_hpp
#define udp_proxy_hpp

#include <cstddef>

#include "options.hpp"

/// 把 pip 接收到的 UDP 数据按四元组转发到出站 socket, 并把回包写回 pip
namespace udp_proxy {

/// 注册 pip 回调并启动收包线程, opts 需要在进程生命周期内有效
void start(const options & opts);

/// 当前活跃的 UDP 会话数
size_t active_flows();

}

#endif /* udp_proxy_hpp */
