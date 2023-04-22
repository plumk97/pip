//
//  main.cpp
//  example
//
//  Created by Plumk on 2021/10/28.
//

#import <Foundation/Foundation.h>

#include <iostream>
#include "pip.hpp"
#include "hex.hpp"
#include "tun.hpp"
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <map>


int tun_sock_fd = -1;
dispatch_queue_t queue = dispatch_queue_create("queue", nullptr);
static std::map<pip_uint32, dispatch_source_t> conn_read_sources;

void read_once(pip_tcp *tcp) {
    if (tcp->arg) {
        
        pip_uint32 iden = tcp->get_iden();
        if (conn_read_sources.find(iden) != conn_read_sources.end()) {
            dispatch_resume(conn_read_sources[iden]);
            return;
        }
        
        int maxlen = 65535 << tcp->opp_wind_shift;
        int fd = *((int *)tcp->arg);
        dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, queue);
        dispatch_source_set_event_handler(source, ^{
            uint8_t * buffer = (uint8_t *)malloc(maxlen);
            ssize_t len = recv(fd, buffer, maxlen, 0);
            if (len > 0) {
                tcp->write(buffer, (pip_uint32)len, 0);
                dispatch_suspend(source);
            } else {
                free(tcp->arg);
                tcp->arg = nullptr;
                tcp->close();
                dispatch_source_cancel(source);
            }
            free(buffer);
        });
        
        dispatch_resume(source);
        conn_read_sources[iden] = source;
    }
}


void _pip_tcp_connected_callback(pip_tcp * tcp) {
    read_once(tcp);
}

/// tcp接受到数据
void _pip_tcp_received_callback(pip_tcp * tcp, const void * buffer, pip_uint32 buffer_len) {
    
    if (tcp->arg) {
        int fd = *((int *)tcp->arg);
        send(fd, buffer, buffer_len, MSG_NOSIGNAL);
    }
    
    /// 调用该方法更新窗口
    tcp->received(buffer_len);
}

void _pip_tcp_written_callback(pip_tcp * tcp, pip_uint32 writeen_len, bool has_push, bool is_drop) {
    if (tcp->arg && (has_push || writeen_len == 0)) {
        read_once(tcp);
    }
}

void _pip_tcp_closed_callback(pip_tcp * tcp, void *arg) {
    conn_read_sources.erase(tcp->get_iden());
    
    if (arg) {
        int fd = *((int *)arg);
        close(fd);
        free(arg);
    }
}

/// 输出IP包
void _pip_netif_output_ip_data_callback (pip_netif * netif, pip_buf * buf) {
    
    uint32_t inet = htonl(AF_INET);
    uint32_t total_len = buf->get_total_len() + sizeof(uint32_t);
    
    uint8_t * buffer = (uint8_t *)malloc(total_len);
    memcpy(buffer, &inet, sizeof(uint32_t));
    
    pip_buf * p = buf;
    int offset = sizeof(uint32_t);
    while (p) {
        memcpy(buffer + offset, p->get_payload(), p->get_payload_len());
        offset += p->get_payload_len();
        p = p->get_next();
    }
    
    if (tun_sock_fd >= 0) {
        send(tun_sock_fd, buffer, total_len, MSG_NOSIGNAL);
    }
    
    free(buffer);
}

/// 接受到TCP连接
void _pip_netif_new_tcp_connect_callback (pip_netif * netif, pip_tcp * tcp, const void * take_data, pip_uint16 take_data_len) {
    
    /// 注册回调
    tcp->connected_callback = _pip_tcp_connected_callback;
    tcp->received_callback = _pip_tcp_received_callback;
    tcp->written_callback = _pip_tcp_written_callback;
    tcp->closed_callback = _pip_tcp_closed_callback;
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    
    ssize_t ret = 0;
    
    // - 绑定 interface
    int index = if_nametoindex("lo0");
    if (index == 0) {
        close(fd);
        return;
    }
    
    ret = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index));
    if (ret == -1) {
        close(fd);
        return;
    }
    
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(tcp->dst_port);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_len = sizeof(struct sockaddr_in);
    ret = connect(fd, (const struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        std::cout << strerror(errno) << std::endl;
        tcp->close();
        close(fd);
        return;
    }
    
    void * arg = malloc(sizeof(int));
    memcpy(arg, &fd, sizeof(int));
    tcp->arg = arg;
    
    /// 直接回应连接, 并没有连接到远端服务器
    tcp->connected(take_data);
}

/// 接受到UDP包
void _pip_netif_received_udp_data_callback(pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port, pip_uint8 version) {
    
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    
    ssize_t ret = 0;
    
    // - 绑定 interface
    int index = if_nametoindex("en1");
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
    
    
    // 创建250ms定时器
    dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
    dispatch_source_set_timer(timer, DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC, 0);
    dispatch_source_set_event_handler(timer, ^{
        pip_netif::shared()->timer_tick();
    });
    dispatch_resume(timer);
    
    
    // 读取tun数据
    dispatch_source_t read_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, tun_sock_fd, 0, queue);
    dispatch_source_set_event_handler(read_source, ^{
        uint8_t * buffer = (uint8_t *)malloc(PIP_MTU + 4);
        ssize_t len = recv(tun_sock_fd, buffer, PIP_MTU + 4, 0);
        if (len > 0) {
            // 前4个字节代表地址族
//            uint32_t family = 0;
//            memcpy(&family, buffer, 4);
//            family = htonl(family);
            
            // 获取ip包数据写入pip处理
            pip_netif::shared()->input((const void *)(buffer+4));
        }
        free(buffer);
        
    });
    dispatch_resume(read_source);
    
    
    [[NSRunLoop mainRunLoop] run];
    return 0;
}
