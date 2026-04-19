//
//  main.cpp
//
//  Created by Plumk on 2021/10/28.
//


#include <iostream>
#include "pip.h"
#include "hex.hpp"
#include "tun.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <mutex>
#include <thread>
#include "tcp_birdge.hpp"
#include <map>
#include <unordered_map>
#include <vector>

int tun_sock_fd = -1;

namespace {

struct udp_route {
    std::string src_ip;
    pip_uint16 src_port = 0;
    std::string dst_ip;
};

struct udp_relay_state {
    int fd = -1;
    bool receiver_running = false;
    std::mutex mutex;
    std::unordered_map<pip_uint64, udp_route> routes;
};

udp_relay_state g_udp_relay_state;

pip_uint64 make_udp_route_key(pip_uint32 addr, pip_uint16 port) {
    return (static_cast<pip_uint64>(addr) << 16) | port;
}

constexpr const char * k_udp_target_ip = "127.0.0.1";

void reset_udp_relay_locked() {
    if (g_udp_relay_state.fd >= 0) {
        close(g_udp_relay_state.fd);
    }
    g_udp_relay_state.fd = -1;
    g_udp_relay_state.receiver_running = false;
    g_udp_relay_state.routes.clear();
}

void udp_relay_receive_loop(int fd) {
    std::vector<uint8_t> recv_buffer(65535);
    while (true) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        socklen_t len = sizeof(addr);
        ssize_t ret = recvfrom(fd, recv_buffer.data(), recv_buffer.size(), 0, (struct sockaddr *)&addr, &len);
        if (ret <= 0) {
            break;
        }

        udp_route route;
        {
            std::lock_guard<std::mutex> lock(g_udp_relay_state.mutex);
            if (g_udp_relay_state.fd != fd) {
                break;
            }

            auto it = g_udp_relay_state.routes.find(make_udp_route_key(addr.sin_addr.s_addr, ntohs(addr.sin_port)));
            if (it == g_udp_relay_state.routes.end()) {
                continue;
            }
            route = it->second;
        }

        pip_udp::output(recv_buffer.data(), (pip_uint16)ret, route.dst_ip.c_str(), ntohs(addr.sin_port), route.src_ip.c_str(), route.src_port);
    }

    std::lock_guard<std::mutex> lock(g_udp_relay_state.mutex);
    if (g_udp_relay_state.fd == fd) {
        reset_udp_relay_locked();
    }
}

bool ensure_udp_relay_ready() {
    std::lock_guard<std::mutex> lock(g_udp_relay_state.mutex);
    if (g_udp_relay_state.fd >= 0) {
        return true;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }

    int index = if_nametoindex("lo0");
    if (index == 0) {
        close(fd);
        return false;
    }

    if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) == -1) {
        close(fd);
        return false;
    }

    g_udp_relay_state.fd = fd;
    g_udp_relay_state.receiver_running = true;
    std::thread thread(udp_relay_receive_loop, fd);
    thread.detach();
    return true;
}

} // namespace

/// 输出IP包
void _pip_netif_output_ip_data_callback (pip_netif & netif, std::shared_ptr<pip_buf> buf) {
    
    uint32_t inet = htonl(AF_INET);
    uint32_t total_len = buf->total_len() + sizeof(uint32_t);
    
    uint8_t * buffer = (uint8_t *)malloc(total_len);
    memcpy(buffer, &inet, sizeof(uint32_t));
    
    auto p = buf;
    int offset = sizeof(uint32_t);
    while (p) {
        memcpy(buffer + offset, p->payload(), p->payload_len());
        offset += p->payload_len();
        p = p->next();
    }
    
    if (tun_sock_fd >= 0) {
        send(tun_sock_fd, buffer, total_len, MSG_NOSIGNAL);
    }
    
    free(buffer);
}

/// 接受到TCP连接
void _pip_netif_new_tcp_connect_callback (pip_netif & netif, std::shared_ptr<pip_tcp> tcp, const void * handshake_data, pip_uint16 take_data_len) {
    tcp_bridge(tcp, handshake_data, take_data_len);
}

/// 接受到UDP包
void _pip_netif_received_udp_data_callback(pip_netif & netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port, pip_uint8 version) {
    (void)netif;

    if (version != 4) {
        return;
    }

    if (ensure_udp_relay_ready() == false) {
        return;
    }

    pip_in_addr addr_value;
    if (inet_pton(AF_INET, k_udp_target_ip, &addr_value) != 1) {
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dst_port);
    addr.sin_addr = addr_value;
    addr.sin_len = sizeof(addr);

    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(g_udp_relay_state.mutex);
        if (g_udp_relay_state.fd < 0) {
            return;
        }
        fd = g_udp_relay_state.fd;
        g_udp_relay_state.routes[make_udp_route_key(addr.sin_addr.s_addr, dst_port)] = {src_ip, src_port, dst_ip};
    }

    auto ret = sendto(fd, buffer, buffer_len, 0, (struct sockaddr *)&addr, sizeof(sockaddr_in));
    if (ret == buffer_len) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_udp_relay_state.mutex);
    if (g_udp_relay_state.fd == fd) {
        reset_udp_relay_locked();
    }
}


int main(int argc, const char * argv[]) {
    
    /**
     PIP 工作在IP层，七层模型中的第三层，主要处理IP包得到TCP、UDP连接
     该示例展示了TCP、UDP转发
     当前只路由 1.1.1.1 到当前 Tun device 并转发到127.0.0.1以测试iperf3
     发起的链接需要根据地址选择对应的interface 比如127.0.0.1对应lo0
     */
    
    
    pip_netif::shared().output_ip_data_callback = _pip_netif_output_ip_data_callback;
    pip_netif::shared().new_tcp_connect_callback = _pip_netif_new_tcp_connect_callback;
    pip_netif::shared().received_udp_data_callback = _pip_netif_received_udp_data_callback;

    

    // 创建 tun 虚拟网卡
    tun_sock_fd = open_tun_socket();
    if (tun_sock_fd < 0) {
        return tun_sock_fd;
    }


    uint8_t * buffer = (uint8_t *)malloc(PIP_MTU + 4);
    while (true) {
        ssize_t len = recv(tun_sock_fd, buffer, PIP_MTU + 4, 0);
        if (len > 0) {
            // 前4个字节代表地址族
//            uint32_t family = 0;
//            memcpy(&family, buffer, 4);
//            family = htonl(family);

            // 获取ip包数据写入pip处理
            pip_netif::shared().input((const void *)(buffer+4));
        }
    }
    return 0;
}
