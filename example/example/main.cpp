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
#include <thread>
#include "tcp_birdge.hpp"
#include <map>

int tun_sock_fd = -1;

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
    
    static int fd = -1;
    static std::map<pip_uint32, pip_uint16> udp_ports;
    
    if (fd < 0) {
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return;
        
        // - 绑定 interface
        int index = if_nametoindex("lo0");
        if (index == 0) {
            close(fd);
            fd = -1;
            return;
        }
        
        if (setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index)) == -1) {
            close(fd);
            fd = -1;
            return;
        }
        
        
        std::thread thread([] {
            // - 接受数据
            uint8_t * recv_buffer = (uint8_t *)malloc(65535);
            struct sockaddr_in addr;
            socklen_t len = sizeof(sockaddr_in);
            while (true) {
                auto ret = recvfrom(fd, (void *)recv_buffer, 65535, 0, (struct sockaddr *)&addr, &len);
                if (ret <= 0) {
                    std::cout << strerror(errno) << std::endl;
                    break;
                }
                
        
                char * ip = inet_ntoa(addr.sin_addr);
                
                // 查找对应的src_port
                pip_uint32 iden = addr.sin_addr.s_addr ^ addr.sin_port;
                if (udp_ports.find(iden) == udp_ports.end()) {
                    continue;
                }
                pip_uint16 src_port = udp_ports[iden];
                
                // - 将数据输出到pip进行处理 注意地址来源交换
                if (strcmp(ip, "127.0.0.1") == 0) {
                    pip_udp::output(recv_buffer, ret, "1.1.1.1", ntohs(addr.sin_port), "192.168.33.1", src_port);
                } else {
                    pip_udp::output(recv_buffer, ret, ip, ntohs(addr.sin_port), "192.168.33.1", src_port);
                }
            }
            
        
            free(recv_buffer);
            close(fd);
            fd = -1;
        });
        thread.detach();
    }
    

    // - 向远端发起数据
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dst_port);
    if (strcmp(dst_ip, "1.1.1.1") == 0) {
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    } else {
        addr.sin_addr.s_addr = inet_addr(dst_ip);
    }
    addr.sin_len = sizeof(struct sockaddr_in);

    // 记录src_port
    udp_ports[addr.sin_addr.s_addr ^ addr.sin_port] = src_port;
    
    auto ret = sendto(fd, buffer, buffer_len, 0, (struct sockaddr *)&addr, sizeof(sockaddr_in));
    if (ret <= 0) {
        close(fd);
        fd = -1;
        return;
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
