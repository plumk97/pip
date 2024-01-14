//
//  tcp_birdge.hpp
//
//  Created by Plumk on 2023/5/27.
//  Copyright © 2023 Plumk. All rights reserved.
//

#ifndef tcp_birdge_hpp
#define tcp_birdge_hpp

#include <iostream>
#include "pip.h"

void tcp_bridge(pip_tcp *tcp, const void * take_data, pip_uint16 take_data_len);
#endif /* tcp_birdge_hpp */
