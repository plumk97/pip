//
//  pip_buf.cpp
//
//  Created by Plumk on 2021/3/20.
//

#include "pip_buf.h"
#include <string.h>


pip_buf::~pip_buf() {
    
    if (this->_is_alloc && this->_payload_len > 0) {
        free(this->_payload);
    }
}

pip_buf::pip_buf(const void * payload, pip_uint32 payload_len, pip_uint8 is_copy) {
    if (is_copy && payload_len > 0) {
        void * b = malloc(sizeof(char) * payload_len);
        memcpy(b, payload, payload_len);
        this->_payload = b;
    } else {
        this->_payload = (void *)payload;
    }
    
    this->_is_alloc = is_copy && payload_len > 0;
    this->_payload_len = payload_len;
    this->_total_len = this->_payload_len;
}

pip_buf::pip_buf(pip_uint32 length) {
    this->_is_alloc = true;
    this->_payload = calloc(length, sizeof(char));
    this->_payload_len = length;
    this->_total_len = length;
}

void pip_buf::set_next(std::shared_ptr<pip_buf> buf) {
    
    if (this->_next) {
        this->_total_len -= this->_next->_total_len;
    }
    
    if (buf == nullptr) {
        this->_next = nullptr;
        return;
    }
    
    
    this->_total_len += buf->_total_len;
    this->_next = buf;
    buf->_prev = std::weak_ptr(shared_from_this());
}
