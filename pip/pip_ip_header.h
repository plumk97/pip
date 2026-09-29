//
//  pip_ip_header.hpp
//
//  Created by Plumk on 2022/1/15.
//

#ifndef pip_ip_header_hpp
#define pip_ip_header_hpp

#include <mutex>

#include "pip_type.h"

class pip_ip_header {
    
    /// 版本号
    pip_uint8 _version = 0;
    
    /// 协议类型
    pip_uint8 _protocol = 0;
    
    /// ipv4 是否有可选项
    pip_uint8 _has_options = 0;
    
    /// ttl
    pip_uint8 _ttl = 0;
    
    /// 头部长度
    pip_uint16 _headerlen = 0;
    
    /// 携带数据长度
    pip_uint16 _datalen = 0;
    
    /// ip4 源地址
    pip_in_addr _ip_src = {};
    
    /// ip4 目的地址
    pip_in_addr _ip_dst = {};
    
    /// ip6 源地址
    pip_in6_addr _ip6_src = {};
    
    /// ip6 目的地址
    pip_in6_addr _ip6_dst = {};
    
    /// 源地址 字符串 首次访问时生成
    char _src_str[INET6_ADDRSTRLEN] = {};
    std::once_flag _src_str_once;
    
    /// 目的地址 字符串 首次访问时生成
    char _dst_str[INET6_ADDRSTRLEN] = {};
    std::once_flag _dst_str_once;
    
public:
    pip_ip_header(const void * bytes);
    
    pip_ip_header(const pip_ip_header&) = delete;
    pip_ip_header& operator=(const pip_ip_header&) = delete;

    pip_uint8 version() { return this->_version; }
    pip_uint8 protocol() { return this->_protocol; }
    pip_uint8 has_options() { return this->_has_options; }
    pip_uint8 ttl() { return this->_ttl; }
    pip_uint16 headerlen() { return this->_headerlen; }
    pip_uint16 datalen() { return this->_datalen; }
    pip_in_addr ip_src() { return this->_ip_src; }
    pip_in_addr ip_dst() { return this->_ip_dst; }
    pip_in6_addr ip6_src() { return this->_ip6_src; }
    pip_in6_addr ip6_dst() { return this->_ip6_dst; }
    const char * src_str();
    const char * dst_str();
};
#endif /* pip_ip_header_hpp */
