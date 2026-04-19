//
//  pip_buf.hpp
//
//  Created by Plumk on 2021/3/20.
//

#ifndef pip_buf_hpp
#define pip_buf_hpp

#include "pip_type.h"
#include <memory>

class pip_buf : public std::enable_shared_from_this<pip_buf> {
    void* _payload = nullptr;
    pip_uint32 _payload_len = 0;
    pip_uint8 _is_alloc = 0;
    pip_uint32 _total_len = 0;
    std::weak_ptr<pip_buf> _prev;
    std::shared_ptr<pip_buf> _next;

public:
    ~pip_buf() {
        if (_is_alloc && _payload) {
            free(_payload);
            _payload = nullptr;
        }
        _payload_len = 0;
        _total_len = 0;
    }

    pip_buf(const pip_buf&) = delete;
    pip_buf& operator=(const pip_buf&) = delete;

    pip_buf(const void* payload, pip_uint32 payload_len, pip_uint8 is_copy) {
        if (is_copy && payload_len > 0) {
            if (!payload) {
                throw std::invalid_argument("payload is null");
            }
            
            void* b = malloc(payload_len);
            if (!b) {
                throw std::bad_alloc();
            }
            
            memcpy(b, payload, payload_len);
            _payload = b;
            _is_alloc = 1;
        } else {
            _payload = const_cast<void*>(payload);
            _is_alloc = 0;
        }

        _payload_len = payload_len;
        _total_len = payload_len;
    }

    pip_buf(pip_uint32 length) {
        _payload = calloc(length, 1);
        if (length > 0 && !_payload) {
            throw std::bad_alloc();
        }
        _is_alloc = 1;
        _payload_len = length;
        _total_len = length;
    }
    
    void * payload() {
        return this->_payload;
    }
    
    pip_uint32 payload_len() {
        return this->_payload_len;
    }
    
    pip_uint32 total_len() {
        return this->_total_len;
    }
    
    std::shared_ptr<pip_buf> next() { return this->_next; }

    void set_next(std::shared_ptr<pip_buf> buf) {
        if (buf.get() == this) {
            throw std::invalid_argument("cannot set self as next");
        }

        if (_next) {
            update_total_len_upwards(-(pip_int32)_next->_total_len);
            _next->_prev.reset();
        }

        _next = buf;

        if (_next) {
            _next->_prev = shared_from_this();
            update_total_len_upwards((pip_int32)_next->_total_len);
        }
    }

private:
    void update_total_len_upwards(pip_int32 diff) {
        if (diff < 0 && _total_len < (pip_uint32)(-diff)) {
            throw std::overflow_error("total_len underflow");
        }
        _total_len += diff;

        if (auto p = _prev.lock()) {
            p->update_total_len_upwards(diff);
        }
    }
};

#endif /* pip_buf_hpp */
