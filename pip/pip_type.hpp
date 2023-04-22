//
//  pip_type.h
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_type_h
#define pip_type_h

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "pip_opt.hpp"


#define PIP_UINT32_MAX 4294967295

#define PIP_MAX(A, B) (A > B ? A : B)
#define PIP_MIN(A, B) (A < B ? A : B)


typedef uint8_t pip_uint8;
typedef uint16_t pip_uint16;
typedef uint32_t pip_uint32;
typedef uint64_t pip_uint64;

typedef int32_t pip_int32;

typedef struct in_addr pip_in_addr;
typedef struct in6_addr pip_in6_addr;

typedef enum : pip_uint8 {
    pip_tcp_status_closed,
    /* received SYN wait response */
    pip_tcp_status_wait_establishing,
    pip_tcp_status_establishing,
    pip_tcp_status_established,
    pip_tcp_status_fin_wait_1,
    pip_tcp_status_fin_wait_2,
    /* ignore pip_tcp_status_time_wait, */
    pip_tcp_status_close_wait,
    
    /* connection released */
    pip_tcp_status_released,
    
} pip_tcp_status;


static inline pip_uint64 get_current_time() {
    auto now = std::chrono::steady_clock::now();
    auto now_millisec = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    
    return pip_uint64(now_millisec);
}


#endif /* pip_type_h */
