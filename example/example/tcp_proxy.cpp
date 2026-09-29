//
//  tcp_proxy.cpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "tcp_proxy.hpp"

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <mutex>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "pip.h"
#include "log.hpp"
#include "net_util.hpp"

namespace tcp_proxy {

namespace {

/// 数据流向:
///   reader 线程: 出站 socket -> tcp->write
///   writer 线程: received 回调写入的队列 -> 出站 socket -> tcp->received 更新窗口
struct session {
    std::shared_ptr<pip_tcp> tcp;
    std::string name;
    int fd = -1;
    
    std::mutex mutex;
    std::condition_variable cv;
    
    /// 待发往出站 socket 的数据
    std::deque<std::vector<uint8_t>> to_remote;
    
    /// pip 可以继续写入 (connected / written 回调)
    bool writable = false;
    
    /// pip 侧连接已关闭 (closed 回调), writer 发完队列后结束
    bool local_closed = false;
    
    /// 已进入销毁流程
    bool closing = false;
    
    ~session() {
        if (fd >= 0) {
            close(fd);
        }
    }
};

enum class pip_action { none, close, reset };

struct state {
    const options * opts = nullptr;
    std::mutex mutex;
    std::unordered_map<pip_tcp *, std::shared_ptr<session>> sessions;
};

/// 不析构: pip 的定时器线程和转发线程在进程退出期间仍可能访问
state & shared() {
    static state * s = new state();
    return *s;
}

std::shared_ptr<session> find_session(pip_tcp * tcp) {
    auto & st = shared();
    std::lock_guard<std::mutex> lock(st.mutex);
    auto it = st.sessions.find(tcp);
    return it == st.sessions.end() ? nullptr : it->second;
}

/// 结束会话, 可重复调用
void teardown(const std::shared_ptr<session> & s, pip_action action) {
    int fd;
    {
        std::lock_guard<std::mutex> lock(s->mutex);
        if (s->closing) {
            return;
        }
        s->closing = true;
        fd = s->fd;
    }
    s->cv.notify_all();
    
    if (action == pip_action::close) {
        s->tcp->close();
    } else if (action == pip_action::reset) {
        s->tcp->reset();
    }
    
    {
        auto & st = shared();
        std::lock_guard<std::mutex> lock(st.mutex);
        st.sessions.erase(s->tcp.get());
    }
    
    // 唤醒阻塞在 recv/send 上的线程, fd 在 session 析构时关闭
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
    }
    VLOG("tcp %s closed", s->name.c_str());
}

bool send_all(int fd, const uint8_t * data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        ssize_t n = send(fd, data + offset, len - offset, 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        offset += n;
    }
    return true;
}

void writer_loop(std::shared_ptr<session> s) {
    while (true) {
        std::vector<uint8_t> chunk;
        {
            std::unique_lock<std::mutex> lock(s->mutex);
            s->cv.wait(lock, [&] { return !s->to_remote.empty() || s->local_closed || s->closing; });
            
            if (s->closing) {
                return;
            }
            
            if (s->to_remote.empty()) {
                // pip 侧已关闭且数据已全部发出
                lock.unlock();
                teardown(s, pip_action::none);
                return;
            }
            
            chunk = std::move(s->to_remote.front());
            s->to_remote.pop_front();
        }
        
        if (!send_all(s->fd, chunk.data(), chunk.size())) {
            VLOG("tcp %s send failed: %s", s->name.c_str(), strerror(errno));
            teardown(s, pip_action::reset);
            return;
        }
        
        // 数据已交给出站 socket, 归还接收窗口
        s->tcp->received((pip_uint16)chunk.size());
    }
}

void reader_loop(std::shared_ptr<session> s) {
    std::vector<uint8_t> buffer(64 * 1024);
    while (true) {
        ssize_t n = recv(s->fd, buffer.data(), buffer.size(), 0);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            break;
        }
        
        pip_uint32 offset = 0;
        while (offset < (pip_uint32)n) {
            pip_uint32 written = s->tcp->write(buffer.data() + offset, (pip_uint32)n - offset, true);
            if (written > 0) {
                offset += written;
                continue;
            }
            
            // 对方窗口已满或等待 PUSH 确认, 等 written 回调; 超时后重试一次兜底
            std::unique_lock<std::mutex> lock(s->mutex);
            s->cv.wait_for(lock, std::chrono::seconds(1), [&] { return s->writable || s->local_closed || s->closing; });
            if (s->local_closed || s->closing) {
                return;
            }
            s->writable = false;
        }
    }
    
    bool local_closed;
    {
        std::lock_guard<std::mutex> lock(s->mutex);
        local_closed = s->local_closed;
    }
    
    // 出站连接结束: 关闭 pip 连接, 已写入的数据会在 FIN 之前发完
    if (!local_closed) {
        teardown(s, pip_action::close);
    }
}

void connect_and_run(std::shared_ptr<session> s, std::vector<uint8_t> handshake) {
    const options & opts = *shared().opts;
    auto ip_header = s->tcp->ip_header();
    
    endpoint ep;
    if (!resolve_target(opts, ip_header->dst_str(), s->tcp->dst_port(), ep)) {
        teardown(s, pip_action::reset);
        return;
    }
    
    int fd = create_outbound_socket(opts, ep.family(), SOCK_STREAM);
    if (fd < 0 || !connect_with_timeout(fd, ep, 5000)) {
        VLOG("tcp %s connect %s failed: %s", s->name.c_str(), ep.str().c_str(), strerror(errno));
        if (fd >= 0) {
            close(fd);
        }
        teardown(s, pip_action::reset);
        return;
    }
    
    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
    
    {
        std::lock_guard<std::mutex> lock(s->mutex);
        s->fd = fd;
        if (s->closing) {
            return;
        }
    }
    
    VLOG("tcp %s connected via %s", s->name.c_str(), ep.str().c_str());
    
    std::thread(writer_loop, s).detach();
    
    // 出站连接成功后才完成与客户端的握手, 失败时客户端收到 RST
    s->tcp->connected(handshake.data());
    reader_loop(s);
}

// MARK: - pip 回调

void on_connected(std::shared_ptr<pip_tcp> tcp) {
    auto s = find_session(tcp.get());
    if (s == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(s->mutex);
        s->writable = true;
    }
    s->cv.notify_all();
}

void on_written(std::shared_ptr<pip_tcp> tcp, pip_uint32 written_len, bool has_push) {
    (void)written_len;
    (void)has_push;
    on_connected(tcp);
}

void on_received(std::shared_ptr<pip_tcp> tcp, const void * buffer, pip_uint32 buffer_len) {
    if (buffer_len == 0) {
        return;
    }
    
    auto s = find_session(tcp.get());
    if (s == nullptr) {
        return;
    }
    
    // buffer 只在回调期间有效
    const uint8_t * data = (const uint8_t *)buffer;
    {
        std::lock_guard<std::mutex> lock(s->mutex);
        s->to_remote.emplace_back(data, data + buffer_len);
    }
    s->cv.notify_all();
}

void on_closed(std::shared_ptr<pip_tcp> tcp, void * arg) {
    (void)arg;
    auto s = find_session(tcp.get());
    if (s == nullptr) {
        return;
    }
    
    bool has_fd;
    {
        std::lock_guard<std::mutex> lock(s->mutex);
        s->local_closed = true;
        has_fd = s->fd >= 0;
    }
    s->cv.notify_all();
    
    // 尚未连接成功时没有 writer 线程, 直接结束
    if (!has_fd) {
        teardown(s, pip_action::none);
    }
}

void on_new_connection(pip_netif & netif, std::shared_ptr<pip_tcp> tcp, const void * handshake_data, pip_uint16 handshake_data_len) {
    (void)netif;
    
    auto s = std::make_shared<session>();
    s->tcp = tcp;
    
    auto ip_header = tcp->ip_header();
    s->name = std::string(ip_header->src_str()) + ":" + std::to_string(tcp->src_port()) +
              " -> " + ip_header->dst_str() + ":" + std::to_string(tcp->dst_port());
    
    {
        auto & st = shared();
        std::lock_guard<std::mutex> lock(st.mutex);
        st.sessions[tcp.get()] = s;
    }
    
    // arg 非空时 pip 才会触发 closed 回调, 会话本身由 sessions 持有
    tcp->set_arg(s.get());
    tcp->set_connected_callback(on_connected);
    tcp->set_written_callback(on_written);
    tcp->set_received_callback(on_received);
    tcp->set_closed_callback(on_closed);
    
    VLOG("tcp %s new", s->name.c_str());
    
    // 握手数据只在回调期间有效
    const uint8_t * hs = (const uint8_t *)handshake_data;
    std::vector<uint8_t> handshake(hs, hs + handshake_data_len);
    
    // 不能在 pip 回调中阻塞 connect, 否则会阻塞所有流量
    std::thread(connect_and_run, s, std::move(handshake)).detach();
}

} // namespace

void start(const options & opts) {
    shared().opts = &opts;
    pip_netif::shared().new_tcp_connect_callback = on_new_connection;
}

size_t active_sessions() {
    auto & st = shared();
    std::lock_guard<std::mutex> lock(st.mutex);
    return st.sessions.size();
}

}
