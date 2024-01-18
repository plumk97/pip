//
//  pip_buf.cpp
//
//  Created by Plumk on 2021/3/20.
//

#include "pip_buf.h"
#include <string.h>

pip_buf::pip_buf(void * payload, pip_uint32 payload_len, pip_uint8 is_copy) {
    
    this->_payload_len = payload_len;
    if (is_copy && payload_len > 0) {
        void * b = malloc(sizeof(char) * payload_len);
        memcpy(b, payload, payload_len);
        this->_payload = b;
    } else {
        this->_payload = payload;
    }
    
    this->_is_alloc = is_copy && payload_len > 0;
    this->_total_len = this->_payload_len;
    
    this->_next = nullptr;
}

pip_buf::pip_buf(pip_uint32 length) {
    this->_is_alloc = 1;
    this->_payload = calloc(length, sizeof(char));
    this->_payload_len = length;
    this->_total_len = length;
    
    this->_next = nullptr;
}

pip_buf::~pip_buf() {
    if (this->_next) {
        delete this->_next;
    }
    
    if (this->_is_alloc && this->_payload_len > 0) {
        free(this->_payload);
    }
}

void pip_buf::set_next(pip_buf *buf) {
    
    if (this->_next) {
        this->_total_len -= this->_next->_total_len;
    }
    
    if (buf == nullptr) {
        this->_next = nullptr;
        return;
    }
    
    
    this->_total_len += buf->_total_len;
    this->_next = buf;
}
