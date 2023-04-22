//
//  pip_buf.cpp
//
//  Created by Plumk on 2021/3/20.
//

#include "pip_buf.hpp"
#include <string.h>

pip_buf::pip_buf(void * payload, pip_uint32 payload_len, pip_uint8 is_copy) {
    
    
    this->payload_len = payload_len;
    if (is_copy && payload_len > 0) {
        void * b = malloc(sizeof(char) * payload_len);
        memcpy(b, payload, payload_len);
        this->payload = b;
    } else {
        this->payload = payload;
    }
    
    this->is_alloc = is_copy;
    this->total_len = this->payload_len;
    
    this->next = nullptr;
    this->prev = nullptr;
}

pip_buf::pip_buf(pip_uint32 length) {
    this->is_alloc = 1;
    this->payload = calloc(length, sizeof(char));
    this->payload_len = length;
    this->total_len = length;
    
    this->next = nullptr;
    this->prev = nullptr;
}

pip_buf::~pip_buf() {
    
    if (this->prev) {
        this->prev->total_len -= this->total_len;
        this->prev->next = nullptr;
        this->prev = nullptr;
    }
    
    delete this->next;
    
    if (this->is_alloc && this->payload_len > 0) {
        operator delete(this->payload);
    }
    
    this->total_len = 0;
    this->payload_len = 0;
}

void pip_buf::set_next(pip_buf *buf) {
    if (buf == nullptr) {
        if (this->next) {
            this->total_len -= this->next->total_len;
            this->next->prev = nullptr;
            this->next = nullptr;
        }
        
        return;
    }
    
    if (this->next != nullptr) {
        this->total_len -= this->next->total_len;
        this->next->prev = nullptr;
    }
    
    this->total_len += buf->total_len;
    this->next = buf;
    buf->prev = this;
}


void * pip_buf::get_payload() {
    return this->payload;
}


pip_uint32 pip_buf::get_payload_len() {
    return this->payload_len;
}

pip_uint32 pip_buf::get_total_len() {
    return this->total_len;
}

pip_buf * pip_buf::get_next() {
    return this->next;
}

pip_buf * pip_buf::get_prev() {
    return this->prev;
}
