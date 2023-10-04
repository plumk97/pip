//
//  hex.cpp
//
//  Created by Plumk on 2023/3/25.
//  Copyright © 2023 Plumk. All rights reserved.
//

#include "hex.hpp"
#include <string>
#include <sstream>
#include <iomanip>

uint8_t * hex::decode(const char * str, size_t *outlen){
    
    std::stringstream stream;
    size_t slen = strlen(str);
    size_t datalen = (slen + 1) / 2;
    uint8_t *data = (uint8_t *)calloc(datalen, sizeof(uint8_t));
    
    if (outlen != nullptr) {
        *outlen = datalen;
    }
    
    size_t i = 0, j = 0;
    while (i < slen) {
        if (i % 2 == 0 && i != 0) {
            uint16_t byte = 0;
            stream >> std::hex >> byte;
            data[j++] = byte;
            stream.clear();
        }
        
        stream << str[i];
        i ++;
    }
    
    uint16_t byte = 0;
    stream >> std::hex >> byte;
    data[j] = byte;
        
    return data;
}

std::string hex::encode(const uint8_t *data, size_t datalen) {
    
    std::ostringstream stream;
    for (size_t i = 0; i < datalen; i ++) {
        stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<uint16_t>(data[i]);
    }
    
    return stream.str();
}
