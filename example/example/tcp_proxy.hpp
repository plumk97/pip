//
//  tcp_proxy.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef tcp_proxy_hpp
#define tcp_proxy_hpp

#include <cstddef>

#include "options.hpp"

/// 把 pip 接收到的 TCP 连接转发到出站 socket
namespace tcp_proxy {

/// 注册 pip 回调, opts 需要在进程生命周期内有效
void start(const options & opts);

/// 当前转发中的连接数
size_t active_sessions();

}

#endif /* tcp_proxy_hpp */
