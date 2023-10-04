//
//  hex.hpp
//
//  Created by Plumk on 2023/3/25.
//  Copyright © 2023 Plumk. All rights reserved.
//

#ifndef hex_hpp
#define hex_hpp

#include <stdio.h>
#include <iostream>

namespace hex {
    uint8_t * decode(const char * str, size_t *outlen);
    std::string encode(const uint8_t *data, size_t datalen);
}


#endif /* hex_hpp */
