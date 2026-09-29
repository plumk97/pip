//
//  pip_tcp_public.cpp
//
//  Created by Plumk on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "pip_tcp_manager.h"


void pip_tcp::connected(const void *handshake_data) {
    std::unique_lock<std::mutex> lock(_mutex);
    _connected(handshake_data);
    finish(lock);
}

void pip_tcp::close() {
    std::unique_lock<std::mutex> lock(_mutex);
    _arg = nullptr;
    _connected_callback = nullptr;
    _closed_callback = nullptr;
    _received_callback = nullptr;
    _written_callback = nullptr;
    _close();
    finish(lock);
}

void pip_tcp::reset() {
    std::unique_lock<std::mutex> lock(_mutex);
    _arg = nullptr;
    _connected_callback = nullptr;
    _closed_callback = nullptr;
    _received_callback = nullptr;
    _written_callback = nullptr;
    _reset();
    finish(lock);
}


pip_uint32 pip_tcp::write(const void *bytes, pip_uint32 len, bool is_copy) {
    std::unique_lock<std::mutex> lock(_mutex);
    pip_uint32 written = _write(bytes, len, is_copy);
    finish(lock);
    return written;
}

void pip_tcp::received(pip_uint16 len) {
    std::unique_lock<std::mutex> lock(_mutex);
    _received(len);
    finish(lock);
}

pip_uint32 pip_tcp::maximum_write_length() {
    std::lock_guard<std::mutex> lock(_mutex);
    return this->_maximum_write_length();
}



pip_uint32 pip_tcp::current_connections() {
    return pip_tcp_manager::shared().size();
}
