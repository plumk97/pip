//
//  pip_icmp.hpp
//
//  Created by Plumk on 2022/1/13.
//

#ifndef pip_icmp_hpp
#define pip_icmp_hpp

#include "../pip_type.h"
#include "../pip_ip_header.h"

class pip_icmp {
    
public:
    static void input(const void *bytes, std::shared_ptr<pip_ip_header> ip_header);
    static void output(const void *buffer, pip_uint16 buffer_len, const char * src_ip, const char * dst_ip);
};

#endif /* pip_icmp_hpp */
