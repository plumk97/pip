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
void _pip_netif_output_ip_data_callback (pip_netif * netif, pip_buf * buf) {
    
    uint32_t inet = htonl(AF_INET);
    uint32_t total_len = buf->total_len() + sizeof(uint32_t);
    
    uint8_t * buffer = (uint8_t *)malloc(total_len);
    memcpy(buffer, &inet, sizeof(uint32_t));
    
    pip_buf * p = buf;
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
void _pip_netif_new_tcp_connect_callback (pip_netif * netif, pip_tcp * tcp, const void * take_data, pip_uint16 take_data_len) {
    
    tcp_bridge(tcp, take_data, take_data_len);
}

/// 接受到UDP包
void _pip_netif_received_udp_data_callback(pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port, pip_uint8 version) {
    
    std::thread thread([=] {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return;
        
        ssize_t ret = 0;
        
        // - 绑定 interface
        int index = if_nametoindex("en0");
        if (index == 0) {
            close(fd);
            return;
        }
        
        ret = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index));
        if (ret == -1) {
            close(fd);
            return;
        }
        
        // - 向远端发起数据
        struct sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(struct sockaddr_in));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(dst_port);
        servaddr.sin_addr.s_addr = inet_addr(dst_ip);
        servaddr.sin_len = sizeof(struct sockaddr_in);
        
        
        ret = sendto(fd, buffer, buffer_len, 0, (struct sockaddr *)&servaddr, sizeof(sockaddr_in));
        if (ret <= 0) {
            close(fd);
            return;
        }
        
        // - 接受数据
        uint8_t * recv_buffer = (uint8_t *)malloc(65535);
        ret = recvfrom(fd, (void *)recv_buffer, 65535, 0, nullptr, nullptr);
        if (ret <= 0) {
            free(recv_buffer);
            close(fd);
            return;
        }
        
        // - 将数据输出到pip进行处理 注意地址来源交换
        pip_udp::output(recv_buffer, ret, dst_ip, dst_port, src_ip, src_port);
        free(recv_buffer);
        close(fd);
    });
    thread.detach();
}


int main(int argc, const char * argv[]) {
    
    /**
     PIP 工作在IP层，七层模型中的第三层，主要处理IP包得到TCP、UDP连接
     该示例展示了TCP、UDP转发
     当前只路由 1.1.1.1 到当前 Tun device 并转发到127.0.0.1以测试iperf3
     发起的链接需要根据地址选择对应的interface 比如127.0.0.1对应lo0
     */
    pip_netif::shared()->output_ip_data_callback = _pip_netif_output_ip_data_callback;
    pip_netif::shared()->new_tcp_connect_callback = _pip_netif_new_tcp_connect_callback;
    pip_netif::shared()->received_udp_data_callback = _pip_netif_received_udp_data_callback;


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
            pip_netif::shared()->input((const void *)(buffer+4));
        }
    }

    return 0;
}
