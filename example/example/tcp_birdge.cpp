//
//  tcp_birdge.cpp
//
//  Created by Plumk on 2023/5/27.
//  Copyright © 2023 Plumk. All rights reserved.
//

#include "tcp_birdge.hpp"
#include <unistd.h>
#include <net/if.h>
#include <sys/socket.h>
#include <thread>

void read_once(int fd, pip_tcp * tcp) {
    int maxlen = 65535 << tcp->opp_wind_shift();
    uint8_t * buffer = (uint8_t *)malloc(maxlen);
    
    ssize_t len = recv(fd, buffer, maxlen, 0);
    if (len <= 0) {
        free(buffer);
        close(fd);
        tcp->close();
        return;
    }
    
    tcp->write(buffer, (pip_uint32)len, 0);
    free(buffer);
}

/// tcp接受到数据
void _pip_tcp_received_callback(pip_tcp * tcp, const void * buffer, pip_uint32 buffer_len) {
    int fd = *((int *)tcp->arg());
    send(fd, buffer, buffer_len, MSG_NOSIGNAL);

    /// 调用该方法更新窗口
    tcp->received(buffer_len);
}

void _pip_tcp_written_callback(pip_tcp * tcp, pip_uint32 writeen_len, bool has_push, bool is_drop) {
    int fd = *((int *)tcp->arg());
    if (has_push || writeen_len == 0) {
        std::thread thread(read_once, fd, tcp);
        thread.detach();
    }
}

void _pip_tcp_connected_callback(pip_tcp* tcp) {
    int fd = *((int *)tcp->arg());
    std::thread thread(read_once, fd, tcp);
    thread.detach();
}

void _pip_tcp_closed_callback(pip_tcp * tcp, void *arg) {
    int fd = *((int *)arg);
    close(fd);
}

void tcp_bridge(pip_tcp *tcp, const void * take_data, pip_uint16 take_data_len) {
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        tcp->close();
        return;
    }
    
    ssize_t ret = 0;
    
    // - 绑定 interface
    int index = if_nametoindex("lo0");
    if (index == 0) {
        close(fd);
        tcp->close();
        return;
    }
    
    ret = setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index));
    if (ret == -1) {
        close(fd);
        tcp->close();
        return;
    }
    
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(tcp->dst_port());
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_len = sizeof(struct sockaddr_in);
    ret = connect(fd, (const struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        std::cout << strerror(errno) << std::endl;
        close(fd);
        tcp->close();
        return;
    }
    
    int *ptr = (int *)malloc(sizeof(int));
    memcpy(ptr, &fd, sizeof(int));
    
    tcp->set_arg(ptr);
    
    tcp->closed_callback = _pip_tcp_closed_callback;
    tcp->received_callback = _pip_tcp_received_callback;
    tcp->connected_callback = _pip_tcp_connected_callback;
    tcp->written_callback = _pip_tcp_written_callback;
    
    /// 直接回应连接, 并没有连接到远端服务器
    tcp->connected(take_data);
}
