//
//  pip_checksum.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_checksum.hpp"

pip_uint32 pip_fold_uint32(pip_uint32 num) {
    return (num & 0x0000FFFFUL) + (num >> 16);
}

pip_uint32 pip_standard_checksum(const void * payload, int len, pip_uint32 sum) {
    const pip_uint8 * ptr = (const pip_uint8 *)payload;
    
    int i = 0;
    while (i < len) {
        if (i + 1 >= len)
            break;
        sum += ptr[i] << 8 | ptr[i + 1];
        i += 2;
        sum = pip_fold_uint32(sum);
        sum = pip_fold_uint32(sum);
    }
    
    if (i < len) {
        sum += ptr[i] << 8 | 0;
        sum = pip_fold_uint32(sum);
        sum = pip_fold_uint32(sum);
    }
    
    return sum;
}

pip_uint16 pip_ip_checksum(const void * payload, int len) {
    
    pip_uint32 sum = pip_standard_checksum(payload, len, 0);
    return ~((pip_uint16)sum);
}


pip_uint16 pip_inet_checksum(const void * payload, pip_uint8 proto, pip_uint32 src, pip_uint32 dest, pip_uint16 len) {
    pip_uint32 sum = 0;
    sum += ((pip_uint32)src & 0xFFFF0000) >> 16;
    sum += ((pip_uint32)src & 0x00000FFFF) >> 0;
    pip_fold_uint32(sum);
    
    sum += ((pip_uint32)dest & 0xFFFF0000) >> 16;
    sum += ((pip_uint32)dest & 0x00000FFFF) >> 0;
    pip_fold_uint32(sum);
    
    sum += proto;
    pip_fold_uint32(sum);
    
    sum += (pip_uint16)len;
    pip_fold_uint32(sum);
    
    sum = pip_standard_checksum(payload, len, sum);
    return ~((pip_uint16)sum);
}


pip_uint16 pip_inet_checksum_buf(pip_buf * buf, pip_uint8 proto, pip_uint32 src, pip_uint32 dest) {
    pip_uint32 sum = 0;
    sum += ((pip_uint32)src & 0xFFFF0000) >> 16;
    sum += ((pip_uint32)src & 0x00000FFFF) >> 0;
    pip_fold_uint32(sum);
    
    sum += ((pip_uint32)dest & 0xFFFF0000) >> 16;
    sum += ((pip_uint32)dest & 0x00000FFFF) >> 0;
    pip_fold_uint32(sum);
    
    sum += proto;
    pip_fold_uint32(sum);
    
    sum += (pip_uint16)buf->total_len;
    pip_fold_uint32(sum);
    
    
    for (pip_buf * q = buf; q != NULL; q = q->next) {
        sum = pip_standard_checksum(q->payload, q->payload_len, sum);
    }

    return ~((pip_uint16)sum);
}


