//
//  pip_icmp.hpp
//
//  Created by Plumk on 2022/1/13.
//

#ifndef pip_icmp_hpp
#define pip_icmp_hpp

#include "pip_type.hpp"

class pip_icmp {
    
public:
    static void input(const void *bytes, struct ip *ip);
};

#endif /* pip_icmp_hpp */
