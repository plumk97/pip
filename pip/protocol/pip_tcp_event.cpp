//
//  pip_tcp_event.cpp
//
//  Created by Plumk on 2026/1/8.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp_event.h"
#include "pip_tcp.h"
#include "pip_tcp_manager.h"
#include "../pip_netif.h"

void pip_tcp::finish(std::unique_lock<std::mutex> & lock) {
    std::vector<std::shared_ptr<pip_tcp_packet>> outputs = std::move(this->_outputs);
    this->_outputs.clear();
    
    bool should_dispatch = false;
    if (!this->_events.empty()) {
        if (this->_dispatching) {
            // 交给正在派发的线程处理, 当前线程返回后 input 缓冲区将失效
            for (auto & e : this->_events) {
                if (auto ev = std::get_if<pip_tcp_received_event>(&e)) {
                    ev->retain();
                }
            }
        } else {
            this->_dispatching = true;
            should_dispatch = true;
        }
    }
    lock.unlock();
    
    this->flush_outputs(outputs);
    
    if (!should_dispatch) {
        return;
    }
    
    lock.lock();
    while (!this->_events.empty()) {
        std::vector<pip_tcp_event_variant> events = std::move(this->_events);
        this->_events.clear();
        lock.unlock();
        
        this->dispatch_events(events);
        
        lock.lock();
    }
    this->_dispatching = false;
    lock.unlock();
}

void pip_tcp::flush_outputs(std::vector<std::shared_ptr<pip_tcp_packet>> & outputs) {
    if (outputs.empty()) {
        return;
    }
    
    std::lock_guard<std::recursive_mutex> guard(this->_output_mutex);
    pip_netif & netif = pip_netif::shared();
    for (auto & packet : outputs) {
        if (this->_ip_header->version() == 4) {
            netif.output4(packet->head_buf(), IPPROTO_TCP, this->_ip_header->ip_dst(), this->_ip_header->ip_src());
        } else {
            netif.output6(packet->head_buf(), IPPROTO_TCP, this->_ip_header->ip6_dst(), this->_ip_header->ip6_src());
        }
    }
}

void pip_tcp::dispatch_events(std::vector<pip_tcp_event_variant> & events) {
    for (auto& e : events) {
        std::visit([this](auto& ev){
            using T = std::decay_t<decltype(ev)>;
            
            if constexpr (std::is_same_v<T, pip_tcp_connect_event>) {
                pip_netif & netif = pip_netif::shared();
                if (netif.new_tcp_connect_callback != nullptr) {
                    netif.new_tcp_connect_callback(netif, shared_from_this(), ev.buffer(), ev.buffer_len());
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_connected_event>) {
                pip_tcp_connected_callback callback;
                {
                    std::lock_guard<std::mutex> lock(this->_mutex);
                    callback = this->_connected_callback;
                }
                if (callback != nullptr) {
                    callback(shared_from_this());
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_closed_event>) {
                pip_tcp_manager::shared().remove_tcp(this->_key, this);
                
                pip_tcp_closed_callback callback;
                {
                    std::lock_guard<std::mutex> lock(this->_mutex);
                    callback = this->_closed_callback;
                }
                if (callback != nullptr) {
                    callback(shared_from_this(), ev.arg);
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_written_event>) {
                pip_tcp_written_callback callback;
                {
                    std::lock_guard<std::mutex> lock(this->_mutex);
                    callback = this->_written_callback;
                }
                if (callback != nullptr) {
                    callback(shared_from_this(), ev.written_len, ev.has_push);
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_received_event>) {
                pip_tcp_received_callback callback;
                {
                    std::lock_guard<std::mutex> lock(this->_mutex);
                    callback = this->_received_callback;
                }
                if (callback != nullptr) {
                    callback(shared_from_this(), ev.buffer(), ev.buffer_len());
                }
            }
        }, e);
    }
}
