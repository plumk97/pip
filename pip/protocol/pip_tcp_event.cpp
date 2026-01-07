//
//  pip_tcp_event.cpp
//  example
//
//  Created by Plumk on 2026/1/8.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp_event.h"
#include "pip_tcp.h"
#include "pip_tcp_manager.h"
#include "../pip_netif.h"

void pip_tcp::process_events() {
    std::vector<decltype(this->_events)::value_type> events;
    {
        std::lock_guard<std::mutex> lock(this->_mutex);
        events = this->_events;
        this->_events.clear();
    }

    for (auto& e : events) {
        std::visit([this](auto& ev){
            using T = std::decay_t<decltype(ev)>;
            
            if constexpr (std::is_same_v<T, pip_tcp_connect_event>) {
                pip_netif & netif = pip_netif::shared();
                if (netif.new_tcp_connect_callback != nullptr) {
                    netif.new_tcp_connect_callback(netif, shared_from_this(), ev.handshake_data, ev.handshake_data_len);
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_connected_event>) {
                if (this->connected_callback != nullptr) {
                    this->connected_callback(shared_from_this());
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_closed_event>) {
                pip_tcp_manager::shared().remove_tcp(this->iden());
                
                if (this->closed_callback != nullptr) {
                    this->closed_callback(shared_from_this(), ev.arg);
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_written_event>) {
                if (this->written_callback != nullptr) {
                    this->written_callback(shared_from_this(), ev.written_len, ev.has_push, ev.is_drop);
                }
            } else if constexpr (std::is_same_v<T, pip_tcp_received_event>) {
                if (this->received_callback != nullptr) {
                    this->received_callback(shared_from_this(), ev.buffer, ev.buffer_len);
                }
            }
        }, e);
    }
}
