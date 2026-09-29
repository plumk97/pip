//
//  icmp_echo.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef icmp_echo_hpp
#define icmp_echo_hpp

/// 在 pip 内直接应答 ICMP / ICMPv6 Echo 请求, 即 ping 经过 utun 的地址会由 pip 回复
namespace icmp_echo {

void start();

}

#endif /* icmp_echo_hpp */
