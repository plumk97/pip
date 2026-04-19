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
#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

namespace {

struct tcp_bridge_context {
    explicit tcp_bridge_context(int socket_fd) : fd(socket_fd) {}

    int fd;
    std::atomic<bool> closed = false;
    std::atomic<bool> reader_started = false;
    std::mutex mutex;
    std::condition_variable writable_cv;
    bool writable = false;
};

std::shared_ptr<tcp_bridge_context> get_tcp_bridge_context(void *arg) {
    if (arg == nullptr) {
        return nullptr;
    }
    auto context_ptr = static_cast<std::shared_ptr<tcp_bridge_context> *>(arg);
    return *context_ptr;
}

void close_local_socket(const std::shared_ptr<tcp_bridge_context> &context) {
    if (context == nullptr) {
        return;
    }
    
    if (context->closed.exchange(true) == false) {
        shutdown(context->fd, SHUT_RDWR);
        close(context->fd);
    }
    
    {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->writable = true;
    }
    context->writable_cv.notify_all();
}

void close_bridge(const std::shared_ptr<pip_tcp> &tcp, const std::shared_ptr<tcp_bridge_context> &context, bool close_tcp) {
    close_local_socket(context);
    if (close_tcp) {
        tcp->close();
    }
}

bool send_all_to_local(const std::shared_ptr<tcp_bridge_context> &context, const void *buffer, pip_uint32 buffer_len) {
    const uint8_t *data = (const uint8_t *)buffer;
    pip_uint32 offset = 0;
    while (offset < buffer_len) {
        ssize_t sent_len = send(context->fd, data + offset, buffer_len - offset, MSG_NOSIGNAL);
        if (sent_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        
        if (sent_len == 0) {
            return false;
        }
        
        offset += (pip_uint32)sent_len;
    }
    return true;
}

void local_to_remote_loop(std::shared_ptr<pip_tcp> tcp, std::shared_ptr<tcp_bridge_context> context) {
    std::vector<uint8_t> buffer(65535);
    while (context->closed.load() == false) {
        ssize_t len = recv(context->fd, buffer.data(), buffer.size(), 0);
        if (len < 0) {
            if (errno == EINTR) {
                continue;
            }
            close_bridge(tcp, context, true);
            return;
        }
        
        if (len == 0) {
            close_bridge(tcp, context, true);
            return;
        }
        
        pip_uint32 offset = 0;
        while (offset < (pip_uint32)len && context->closed.load() == false) {
            pip_uint32 written = tcp->write(buffer.data() + offset, (pip_uint32)len - offset, 0);
            if (written > 0) {
                offset += written;
                continue;
            }
            
            std::unique_lock<std::mutex> lock(context->mutex);
            context->writable_cv.wait(lock, [&context] {
                return context->closed.load() || context->writable;
            });
            context->writable = false;
        }
    }
}

} // namespace

/// tcp接受到数据
void _pip_tcp_received_callback(std::shared_ptr<pip_tcp> tcp, const void * buffer, pip_uint32 buffer_len) {
    auto context = get_tcp_bridge_context(tcp->arg());
    if (context == nullptr || context->closed.load()) {
        return;
    }
    
    if (send_all_to_local(context, buffer, buffer_len) == false) {
        close_bridge(tcp, context, true);
        return;
    }
    
    tcp->received(buffer_len);
}

void _pip_tcp_written_callback(std::shared_ptr<pip_tcp> tcp, pip_uint32 writeen_len, bool has_push) {
    auto context = get_tcp_bridge_context(tcp->arg());
    if (context == nullptr || context->closed.load()) {
        return;
    }
    
    (void)writeen_len;
    (void)has_push;
    
    {
        std::lock_guard<std::mutex> lock(context->mutex);
        context->writable = true;
    }
    context->writable_cv.notify_one();
}

void _pip_tcp_connected_callback(std::shared_ptr<pip_tcp> tcp) {
    auto context = get_tcp_bridge_context(tcp->arg());
    if (context == nullptr) {
        tcp->close();
        return;
    }
    
    if (context->reader_started.exchange(true) == false) {
        std::thread thread(local_to_remote_loop, tcp, context);
        thread.detach();
    }
}

void _pip_tcp_closed_callback(std::shared_ptr<pip_tcp> tcp, void *arg) {
    (void)tcp;
    auto context = get_tcp_bridge_context(arg);
    close_local_socket(context);
    delete static_cast<std::shared_ptr<tcp_bridge_context> *>(arg);
}

void tcp_bridge(std::shared_ptr<pip_tcp> tcp, const void * handshake_data, pip_uint16 take_data_len) {
    (void)take_data_len;
    
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
    
    auto context = std::make_shared<tcp_bridge_context>(fd);
    tcp->set_arg(new std::shared_ptr<tcp_bridge_context>(context));
    
    tcp->set_closed_callback(_pip_tcp_closed_callback);
    tcp->set_received_callback(_pip_tcp_received_callback);
    tcp->set_connected_callback(_pip_tcp_connected_callback);
    tcp->set_written_callback(_pip_tcp_written_callback);
    
    /// 直接回应连接, 并没有连接到远端服务器
    tcp->connected(handshake_data);
}
