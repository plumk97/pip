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
    
    char * src_str;
    char * dst_str;
    
    
public:
    
    /// ip4地址转换为字符串
    static char * ip4_to_str(pip_in_addr addr);
    
    /// ip6地址转换为字符串
    static char * ip6_to_str(pip_in6_addr addr);
    
};
#endif /* pip_ip_header_hpp */
