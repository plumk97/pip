//
//  pip_buf.hpp
//
//  Created by Plumk on 2021/3/20.
//

#ifndef pip_buf_hpp
#define pip_buf_hpp

#include "pip_type.h"
#include "pip_macro.h"

class pip_buf {

    PIP_READONLY_PROPERTY(void *, payload);
    PIP_READONLY_PROPERTY(pip_uint32, payload_len);
    PIP_READONLY_PROPERTY(pip_uint8, is_alloc);
    PIP_READONLY_PROPERTY(pip_uint32, total_len);
    PIP_READONLY_PROPERTY(pip_buf *, prev);
    
    pip_buf *_next;
    
public:
    ~pip_buf();
    pip_buf(void * payload, pip_uint32 payload_len, pip_uint8 is_copy);
    pip_buf(pip_uint32 length);
    
    void set_next(pip_buf *buf);
    pip_buf * next() { return this->_next; }
    
};

#endif /* pip_buf_hpp */
