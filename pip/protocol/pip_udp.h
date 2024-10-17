//
//  pip_udp.hpp
//
//  Created by Plumk on 2022/1/13.
//

#ifndef pip_udp_hpp
#define pip_udp_hpp

#include "../pip_type.h"
#include "../pip_ip_header.h"

class pip_udp {
    
public:
    static void input(const void *bytes, std::shared_ptr<pip_ip_header> ip_header);
    static void output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port);
};


#endif /* pip_udp_hpp */
