//
//  options.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef options_hpp
#define options_hpp

#include <string>
#include <vector>

struct options {
    /// utun 本端地址 (系统侧)
    std::string local_ip = "192.168.33.1";
    
    /// utun 对端地址, 发往该地址的流量由 pip 处理
    std::string peer_ip = "192.168.33.2";
    
    /// 额外路由到 utun 的网段, 例如 1.1.1.1/32
    std::vector<std::string> routes;
    
    /// 非空时所有 TCP/UDP 连接都转发到该地址 (端口不变), 为空时连接原目标地址
    std::string redirect_ip = "127.0.0.1";
    
    /// 出站 socket 绑定的网卡, 避免出站流量又被路由回 utun
    std::string out_iface = "lo0";
    
    /// 出站网卡索引, 由 out_iface 解析
    unsigned int out_ifindex = 0;
    
    /// 打印每个连接
    bool verbose = false;
};

/// 解析命令行参数, 失败或 -h 时打印用法并返回 false
bool parse_options(int argc, const char * argv[], options & opts);

#endif /* options_hpp */
