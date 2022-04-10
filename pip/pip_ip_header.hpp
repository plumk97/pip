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
    
    /// 头部长度
    pip_uint16 headerlen;
    
    /// 携带数据长度
    pip_uint16 datalen;
    
    pip_uint32 src;
    pip_uint32 dest;
    
    char * src_str;
    char * dest_str;
    
};
#endif /* pip_ip_header_hpp */
