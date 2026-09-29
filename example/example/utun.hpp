//
//  utun.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef utun_hpp
#define utun_hpp

#include <memory>
#include <string>
#include <vector>

#include "pip.h"

/// macOS utun 虚拟网卡
/// 读写的数据带有 4 字节地址族头部 (AF_INET / AF_INET6, 网络字节序)
class utun {
    int _fd = -1;
    std::string _name;
    
public:
    utun() = default;
    ~utun();
    
    utun(const utun &) = delete;
    utun & operator=(const utun &) = delete;
    
    /// 创建 utun 并配置点对点地址和 MTU
    bool open(const std::string & local_ip, const std::string & peer_ip, int mtu);
    
    /// 添加一条到本网卡的路由, cidr 例如 1.1.1.1/32
    bool add_route(const std::string & cidr);
    
    /// 地址族头部长度, read 读到的 IP 包从 buffer[header_size] 开始
    static constexpr int header_size = 4;
    
    /// 读取一个 IP 包到 buffer, 返回 IP 包的长度, 超时返回 0, 出错返回 -1
    int read(std::vector<uint8_t> & buffer, int timeout_ms);
    
    /// 写出一个 IP 包 (pip 输出的 buf 链)
    bool write(const std::shared_ptr<pip_buf> & buf);
    
    const std::string & name() const { return _name; }
    int fd() const { return _fd; }
};

#endif /* utun_hpp */
