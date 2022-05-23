//
//  pip_ip_header.hpp
//
//  Created by Plumk on 2022/1/15.
//

#ifndef pip_ip_header_hpp
#define pip_ip_header_hpp

#include "pip_type.hpp"

class pip_ip_header {
    
public:
    pip_ip_header(const void * bytes);
    ~pip_ip_header();
    
    /// 版本号
    pip_uint8 version;
    
    /// 协议类型
    pip_uint8 protocol;
    
    /// ipv4 是否有可选项
    pip_uint8 has_options;
    
    /// ttl
    pip_uint8 ttl;
    
    /// 头部长度
    pip_uint16 headerlen;
    
    /// 携带数据长度
    pip_uint16 datalen;
    
    /// ip4 源地址
    pip_in_addr ip_src;
    
    /// ip4 目的地址
    pip_in_addr ip_dst;
    
    /// ip6 源地址
    pip_in6_addr ip6_src;
    
    /// ip6 目的地址
    pip_in6_addr ip6_dst;
    
    /// 源地址 字符串
    char * src_str;
    
    /// 目的地址 字符串
    char * dst_str;
    
    /// 生成32位标识
    pip_uint32 generate_iden();
};
#endif /* pip_ip_header_hpp */
