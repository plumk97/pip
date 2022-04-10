//
//  pip_buf.hpp
//
//  Created by Plumk on 2021/3/20.
//

#ifndef pip_buf_hpp
#define pip_buf_hpp

#include <stdio.h>

class pip_buf {
    
public:
    ~pip_buf();
    pip_buf(void * payload, int payload_len, int is_copy);
    pip_buf(int length);
    
    void set_next(pip_buf *buf);
    
    void *payload;
    int payload_len;
    
    int is_alloc;
    int total_len;
    pip_buf *next;
    pip_buf *pre;
    
};

#endif /* pip_buf_hpp */
