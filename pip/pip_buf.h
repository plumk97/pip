//
//  pip_buf.hpp
//
//  Created by Plumk on 2021/3/20.
//

#ifndef pip_buf_hpp
#define pip_buf_hpp

#include "pip_type.h"
#include "pip_macro.h"
#include <memory>

class pip_buf : public std::enable_shared_from_this<pip_buf>  {

    PIP_READONLY_PROPERTY(void *, payload);
    PIP_READONLY_PROPERTY(pip_uint32, payload_len);
    PIP_READONLY_PROPERTY(pip_uint8, is_alloc);
    PIP_READONLY_PROPERTY(pip_uint32, total_len);
    PIP_READONLY_PROPERTY(std::weak_ptr<pip_buf>, prev);
    
    std::shared_ptr<pip_buf> _next;
    
public:
    ~pip_buf();
    pip_buf(const void * payload, pip_uint32 payload_len, pip_uint8 is_copy);
    pip_buf(pip_uint32 length);
    
    void set_next(std::shared_ptr<pip_buf> buf);
    std::shared_ptr<pip_buf> next() { return this->_next; }
};

#endif /* pip_buf_hpp */
