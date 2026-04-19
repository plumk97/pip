//
//  pip_tcp_event.h
//
//  Created by Plumk on 2026/1/8.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef pip_tcp_event_h
#define pip_tcp_event_h

#include "../pip_type.h"
#include <vector>

class pip_tcp_connect_event {
public:
    std::vector<pip_uint8> handshake_data;

    pip_tcp_connect_event(const void * handshake_data, pip_uint16 handshake_data_len) {
        if (handshake_data != nullptr && handshake_data_len > 0) {
            const pip_uint8 * ptr = (const pip_uint8 *)handshake_data;
            this->handshake_data.assign(ptr, ptr + handshake_data_len);
        }
    }

    const void * buffer() const {
        return this->handshake_data.empty() ? nullptr : this->handshake_data.data();
    }

    pip_uint16 buffer_len() const {
        return (pip_uint16)this->handshake_data.size();
    }
};

class pip_tcp_connected_event {
    
};

class pip_tcp_closed_event {
    
public:
    void *arg;
    pip_tcp_closed_event(void *arg){
        this->arg = arg;
    }
};

class pip_tcp_written_event {
    
public:
    pip_uint16 written_len;
    bool has_push;
    
    pip_tcp_written_event(pip_uint16 written_len, bool has_push) {
        this->written_len = written_len;
        this->has_push = has_push;
    }
};

class pip_tcp_received_event {
    
public:
    const void *data;
    pip_uint32 data_len;
    
    pip_tcp_received_event(const void *buffer, pip_uint32 buffer_len) {
        this->data = buffer;
        this->data_len = buffer_len;
    }

    const void * buffer() const {
        return this->data;
    }

    pip_uint32 buffer_len() const {
        return this->data_len;
    }
};

using pip_tcp_event_variant = std::variant<
    pip_tcp_connect_event,
    pip_tcp_connected_event,
    pip_tcp_closed_event,
    pip_tcp_written_event,
    pip_tcp_received_event
>;

#endif /* pip_tcp_event_h */
