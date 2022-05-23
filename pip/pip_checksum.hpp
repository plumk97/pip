//
//  pip_checksum.hpp
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_checksum_hpp
#define pip_checksum_hpp

#include "pip_type.hpp"
#include "pip_buf.hpp"

/// 计算checksum
/// @param payload payload
/// @param len len
/// @param sum 初始值
pip_uint32 pip_standard_checksum(const void * payload, int len, pip_uint32 sum);

/// 计算IP checksum
/// @param payload payload
/// @param len len
pip_uint16 pip_ip_checksum(const void * payload, int len);

/// 计算TCP/UDP checksum
/// @param payload payload
/// @param proto TCP / UDP
/// @param src src
/// @param dst dst
/// @param len len
pip_uint16 pip_inet_checksum(const void * payload, pip_uint8 proto, pip_in_addr src, pip_in_addr dst, pip_uint16 len);
pip_uint16 pip_inet6_checksum(const void * payload, pip_uint8 proto, pip_in6_addr src, pip_in6_addr dst, pip_uint16 len);

pip_uint16 pip_inet_checksum_buf(pip_buf * buf, pip_uint8 proto, pip_in_addr src, pip_in_addr dst);
pip_uint16 pip_inet6_checksum_buf(pip_buf * buf, pip_uint8 proto, pip_in6_addr src, pip_in6_addr dst);
#endif /* pip_checksum_hpp */
