//
//  pip_tcp_public.cpp
//
//  Created by Plumk on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "pip_tcp_manager.h"


void pip_tcp::connected(const void *handshake_data) {
    _mutex.lock();
    _connected(handshake_data);
    _mutex.unlock();
}

void pip_tcp::close() {
    _mutex.lock();
    _arg = nullptr;
    _connected_callback = nullptr;
    _closed_callback = nullptr;
    _received_callback = nullptr;
    _written_callback = nullptr;
    _close();
    _mutex.unlock();
    this->process_events();
}

void pip_tcp::reset() {
    _mutex.lock();
    _arg = nullptr;
    _connected_callback = nullptr;
    _closed_callback = nullptr;
    _received_callback = nullptr;
    _written_callback = nullptr;
    _reset();
    _mutex.unlock();
    this->process_events();
}


pip_uint32 pip_tcp::write(const void *bytes, pip_uint32 len, bool is_copy) {
    _mutex.lock();
    pip_uint32 written = _write(bytes, len, is_copy);
    _mutex.unlock();
    return written;
}

void pip_tcp::received(pip_uint16 len) {
    _mutex.lock();
    _received(len);
    _mutex.unlock();
}

pip_uint32 pip_tcp::maximum_write_length() {
    _mutex.lock();
    pip_uint32 ret = this->_maximum_write_length();
    _mutex.unlock();
    return ret;
}



pip_uint32 pip_tcp::current_connections() {
    return pip_tcp_manager::shared().size();
}
