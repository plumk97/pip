//
//  pip_buf.cpp
//
//  Created by Plumk on 2021/3/20.
//

#include "pip_buf.hpp"
#include <string.h>
#include <stdlib.h>

pip_buf::pip_buf(void * payload, int payload_len, int is_copy) {
    
    
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
    
    this->next = NULL;
    this->pre = NULL;
}

pip_buf::pip_buf(int length) {
    this->is_alloc = 1;
    this->payload = calloc(length, sizeof(char));
    this->payload_len = length;
    this->total_len = length;
    
    this->next = NULL;
    this->pre = NULL;
}

pip_buf::~pip_buf() {
    
    if (this->pre) {
        this->pre->total_len -= this->total_len;
        this->pre->next = NULL;
        this->pre = NULL;
    }
    
    delete this->next;
    
    if (this->is_alloc && this->payload_len > 0) {
        free(this->payload);
    }
    
    this->total_len = 0;
    this->payload_len = 0;
}

void pip_buf::set_next(pip_buf *buf) {
    if (buf == NULL) {
        if (this->next) {
            this->total_len -= this->next->total_len;
            this->next->pre = NULL;
            this->next = NULL;
        }
        
        return;
    }
    
    if (this->next != NULL) {
        this->total_len -= this->next->total_len;
        this->next->pre = NULL;
    }
    
    this->total_len += buf->total_len;
    this->next = buf;
    buf->pre = this;
}
