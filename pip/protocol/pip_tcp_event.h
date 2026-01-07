//
//  pip_tcp_event.h
//  example
//
//  Created by Plumk on 2026/1/8.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef pip_tcp_event_h
#define pip_tcp_event_h

#include "../pip_type.h"

class pip_tcp_connect_event {
public:
    const void * handshake_data;
    pip_uint16 handshake_data_len;
    pip_tcp_connect_event(const void * handshake_data, pip_uint16 handshake_data_len) {
        this->handshake_data = handshake_data;
        this->handshake_data_len = handshake_data_len;
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
    bool is_drop;
    
    pip_tcp_written_event(pip_uint16 written_len, bool has_push, bool is_drop) {
        this->written_len = written_len;
        this->has_push = has_push;
        this->is_drop = is_drop;
    }
};

class pip_tcp_received_event {
    
public:
    const void * buffer;
    pip_uint32 buffer_len;
    
    pip_tcp_received_event(const void *buffer, pip_uint32 buffer_len) {
        this->buffer = buffer;
        this->buffer_len = buffer_len;
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
