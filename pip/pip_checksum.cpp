//
//  pip_checksum.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_checksum.hpp"

pip_uint32 pip_fold_uint32(pip_uint32 num) {
    return (num & 0x0000FFFFUL) + (num >> 16);
}

pip_uint32 pip_standard_checksum(const void * payload, pip_uint32 len, pip_uint32 sum) {
    const pip_uint8 * ptr = (const pip_uint8 *)payload;
    
    pip_uint32 i = 0;
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

pip_uint16 pip_ip_checksum(const void * payload, pip_uint32 len) {
    
    pip_uint32 sum = pip_standard_checksum(payload, len, 0);
    return ~((pip_uint16)sum);
}


pip_uint16 pip_inet_checksum(const void * payload, pip_uint8 proto, pip_in_addr src, pip_in_addr dst, pip_uint16 len) {
    
    pip_uint32 sum = 0;
    pip_uint32 addr = 0;
    
    addr = ntohl(src.s_addr);
    sum += (addr & 0xFFFF0000) >> 16;
    sum += (addr & 0x0000FFFF) >> 0;

    addr = ntohl(dst.s_addr);
    sum += (addr & 0xFFFF0000) >> 16;
    sum += (addr & 0x0000FFFF) >> 0;
    
    sum += (pip_uint16)proto;
    sum = pip_fold_uint32(sum);

    sum += (pip_uint16)len;
    sum = pip_fold_uint32(sum);

    sum = pip_standard_checksum(payload, len, sum);
    
    return ~((pip_uint16)sum);
}

pip_uint16 pip_inet6_checksum(const void * payload, pip_uint8 proto, pip_in6_addr src, pip_in6_addr dst, pip_uint16 len) {
    
    pip_uint32 * _src = (pip_uint32 *)&src;
    pip_uint32 * _dst = (pip_uint32 *)&dst;
    
    pip_uint32 sum = 0;
    pip_uint32 addr = 0;
    
    /// 计算源地址 与 目的地址 checksum
    /// 注意字节序
    for (pip_uint8 i = 0; i < 4; i ++) {

        addr = ntohl(_src[i]);
        sum += (addr & 0xFFFF0000) >> 16;
        sum += (addr & 0x0000FFFF) >> 0;
    
        addr = ntohl(_dst[i]);
        sum += (addr & 0xFFFF0000) >> 16;
        sum += (addr & 0x0000FFFF) >> 0;
    }
    
    sum = pip_fold_uint32(sum);
    sum = pip_fold_uint32(sum);
    
    /// 计算32位长度
    /// 注意字节序 需要先转16 在转32
    pip_uint32 len32 = ntohl((pip_uint32)ntohs(len));
    sum += (len32 & 0xFFFF0000) >> 16;
    sum += (len32 & 0x0000FFFF) >> 0;
    
    /// 计算32位协议
    /// 注意字节序 需要先转16 在转32
    pip_uint32 proto32 = ntohl((pip_uint32)ntohs(proto));
    sum += (proto32 & 0xFFFF0000) >> 16;
    sum += (proto32 & 0x0000FFFF) >> 0;
    
    sum = pip_standard_checksum(payload, len, sum);
    return ~((pip_uint16)sum);
}


pip_uint16 pip_inet_checksum_buf(pip_buf * buf, pip_uint8 proto, pip_in_addr src, pip_in_addr dst) {
    
    pip_uint32 sum = 0;
    pip_uint32 addr = 0;
    
    addr = ntohl(src.s_addr);
    sum += (addr & 0xFFFF0000) >> 16;
    sum += (addr & 0x0000FFFF) >> 0;

    addr = ntohl(dst.s_addr);
    sum += (addr & 0xFFFF0000) >> 16;
    sum += (addr & 0x0000FFFF) >> 0;
    
    sum += (pip_uint16)proto;
    sum = pip_fold_uint32(sum);

    sum += (pip_uint16)buf->total_len;
    sum = pip_fold_uint32(sum);
    
    
    for (pip_buf * q = buf; q != NULL; q = q->next) {
        sum = pip_standard_checksum(q->payload, q->payload_len, sum);
    }

    return ~((pip_uint16)sum);
}


pip_uint16 pip_inet6_checksum_buf(pip_buf * buf, pip_uint8 proto, pip_in6_addr src, pip_in6_addr dst) {
    
    pip_uint32 * _src = (pip_uint32 *)&src;
    pip_uint32 * _dst = (pip_uint32 *)&dst;
    
    pip_uint32 sum = 0;
    pip_uint32 addr = 0;
    
    /// 计算源地址 与 目的地址 checksum
    /// 注意字节序
    for (pip_uint8 i = 0; i < 4; i ++) {

        addr = ntohl(_src[i]);
        sum += (addr & 0xFFFF0000) >> 16;
        sum += (addr & 0x0000FFFF) >> 0;
    
        addr = ntohl(_dst[i]);
        sum += (addr & 0xFFFF0000) >> 16;
        sum += (addr & 0x0000FFFF) >> 0;
    }
    
    sum = pip_fold_uint32(sum);
    sum = pip_fold_uint32(sum);
    
    /// 计算32位长度
    /// 注意字节序 需要先转16 在转32
    pip_uint32 len32 = ntohl((pip_uint32)ntohs((pip_uint16)buf->total_len));
    sum += (len32 & 0xFFFF0000) >> 16;
    sum += (len32 & 0x0000FFFF) >> 0;
    
    /// 计算32位协议
    /// 注意字节序 需要先转16 在转32
    pip_uint32 proto32 = ntohl((pip_uint32)ntohs(proto));
    sum += (proto32 & 0xFFFF0000) >> 16;
    sum += (proto32 & 0x0000FFFF) >> 0;
    
    for (pip_buf * q = buf; q != NULL; q = q->next) {
        sum = pip_standard_checksum(q->payload, q->payload_len, sum);
    }
    
    return ~((pip_uint16)sum);
}
