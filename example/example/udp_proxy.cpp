//
//  udp_proxy.cpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "udp_proxy.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "pip.h"
#include "log.hpp"
#include "net_util.hpp"

namespace udp_proxy {

namespace {

/// 空闲超过该时间的会话会被回收
constexpr auto k_idle_timeout = std::chrono::seconds(60);

using steady = std::chrono::steady_clock;

/// 一个 (源地址, 源端口, 目的地址, 目的端口) 对应一个出站 socket
struct flow {
    std::string src_ip;
    pip_uint16 src_port = 0;
    std::string dst_ip;
    pip_uint16 dst_port = 0;
    int fd = -1;
    steady::time_point last_active;
    
    std::string name() const {
        return src_ip + ":" + std::to_string(src_port) + " -> " + dst_ip + ":" + std::to_string(dst_port);
    }
    
    ~flow() {
        if (fd >= 0) {
            close(fd);
        }
    }
};

struct state {
    const options * opts = nullptr;
    std::mutex mutex;
    std::unordered_map<std::string, std::shared_ptr<flow>> flows;
    
    /// 唤醒收包线程重新构建 poll 列表
    int wake_pipe[2] = {-1, -1};
};

/// 不析构: 收包线程在进程退出期间仍可能访问
state & shared() {
    static state * s = new state();
    return *s;
}

std::string make_key(const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port) {
    return std::string(src_ip) + "|" + std::to_string(src_port) + "|" + dst_ip + "|" + std::to_string(dst_port);
}

std::shared_ptr<flow> create_flow(const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port) {
    const options & opts = *shared().opts;
    
    endpoint ep;
    if (!resolve_target(opts, dst_ip, dst_port, ep)) {
        return nullptr;
    }
    
    int fd = create_outbound_socket(opts, ep.family(), SOCK_DGRAM);
    if (fd < 0) {
        return nullptr;
    }
    
    // connect 后只接收来自目标地址的回包
    if (connect(fd, (const struct sockaddr *)&ep.addr, ep.len) != 0) {
        close(fd);
        return nullptr;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    
    auto f = std::make_shared<flow>();
    f->src_ip = src_ip;
    f->src_port = src_port;
    f->dst_ip = dst_ip;
    f->dst_port = dst_port;
    f->fd = fd;
    VLOG("udp %s new via %s", f->name().c_str(), ep.str().c_str());
    return f;
}

void on_received(pip_netif & netif, void * buffer, pip_uint16 buffer_len,
                 const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port, pip_uint8 version) {
    (void)netif;
    (void)version;
    
    auto & st = shared();
    std::string key = make_key(src_ip, src_port, dst_ip, dst_port);
    
    std::shared_ptr<flow> f;
    bool created = false;
    {
        std::lock_guard<std::mutex> lock(st.mutex);
        auto it = st.flows.find(key);
        if (it != st.flows.end()) {
            f = it->second;
        } else {
            f = create_flow(src_ip, src_port, dst_ip, dst_port);
            if (f == nullptr) {
                return;
            }
            st.flows[key] = f;
            created = true;
        }
        f->last_active = steady::now();
    }
    
    if (created) {
        char c = 0;
        (void)::write(st.wake_pipe[1], &c, 1);
    }
    
    if (send(f->fd, buffer, buffer_len, 0) < 0) {
        VLOG("udp %s send failed: %s", f->name().c_str(), strerror(errno));
    }
}

void receive_loop() {
    auto & st = shared();
    std::vector<uint8_t> buffer(65535);
    
    while (true) {
        std::vector<std::shared_ptr<flow>> polled;
        std::vector<struct pollfd> pfds;
        pfds.push_back({st.wake_pipe[0], POLLIN, 0});
        
        {
            std::lock_guard<std::mutex> lock(st.mutex);
            
            // 回收空闲会话, fd 在最后一个引用释放时关闭
            auto now = steady::now();
            for (auto it = st.flows.begin(); it != st.flows.end();) {
                if (now - it->second->last_active > k_idle_timeout) {
                    VLOG("udp %s idle, closed", it->second->name().c_str());
                    it = st.flows.erase(it);
                } else {
                    polled.push_back(it->second);
                    pfds.push_back({it->second->fd, POLLIN, 0});
                    ++it;
                }
            }
        }
        
        int ret = poll(pfds.data(), (nfds_t)pfds.size(), 1000);
        if (ret <= 0) {
            continue;
        }
        
        if (pfds[0].revents & POLLIN) {
            char drain[64];
            while (::read(st.wake_pipe[0], drain, sizeof(drain)) > 0) {}
        }
        
        for (size_t i = 1; i < pfds.size(); i++) {
            if (!(pfds[i].revents & POLLIN)) {
                continue;
            }
            
            auto & f = polled[i - 1];
            while (true) {
                ssize_t n = recv(f->fd, buffer.data(), buffer.size(), 0);
                if (n < 0) {
                    break;
                }
                {
                    std::lock_guard<std::mutex> lock(st.mutex);
                    f->last_active = steady::now();
                }
                // 回包从原目的地址发回给原来源
                pip_udp::output(buffer.data(), (pip_uint16)n, f->dst_ip.c_str(), f->dst_port, f->src_ip.c_str(), f->src_port);
            }
        }
    }
}

} // namespace

void start(const options & opts) {
    auto & st = shared();
    st.opts = &opts;
    
    if (pipe(st.wake_pipe) == 0) {
        fcntl(st.wake_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(st.wake_pipe[1], F_SETFL, O_NONBLOCK);
    }
    
    std::thread(receive_loop).detach();
    pip_netif::shared().received_udp_data_callback = on_received;
}

size_t active_flows() {
    auto & st = shared();
    std::lock_guard<std::mutex> lock(st.mutex);
    return st.flows.size();
}

}
