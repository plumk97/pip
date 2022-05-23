//
//  pip_udp.hpp
//
//  Created by Plumk on 2022/1/13.
//

#ifndef pip_udp_hpp
#define pip_udp_hpp

#include "pip_type.hpp"
#include "pip_ip_header.hpp"

class pip_udp {
    
public:
    static void input(const void *bytes, pip_ip_header * ip_data);
    static void output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port);
};


#endif /* pip_udp_hpp */
