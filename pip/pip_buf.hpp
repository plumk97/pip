//
//  pip_buf.hpp
//
//  Created by Plumk on 2021/3/20.
//

#ifndef pip_buf_hpp
#define pip_buf_hpp

#include "pip_type.hpp"

class pip_buf {
    
public:
    ~pip_buf();
    pip_buf(void * payload, pip_uint32 payload_len, pip_uint8 is_copy);
    pip_buf(pip_uint32 length);
    
    void set_next(pip_buf *buf);
    
    void *get_payload();
    pip_uint32 get_payload_len();
    pip_uint32 get_total_len();
    pip_buf * get_next();
    pip_buf * get_prev();
    
private:
    void *payload;
    pip_uint32 payload_len;
    
    pip_uint8 is_alloc;
    pip_uint32 total_len;
    pip_buf *next;
    pip_buf *prev;
    
};

#endif /* pip_buf_hpp */
