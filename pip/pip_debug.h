//
//  pip_debug.hpp
//
//  Created by Plumk on 2022/1/9.
//

#ifndef pip_debug_hpp
#define pip_debug_hpp

#include "pip_type.h"
#include "protocol/pip_tcp.h"
#include "protocol/pip_tcp_packet.h"

/// 打印IP
/// @param hdr _
/// @param iden 标识
void pip_debug_output_ip(struct ip *hdr, const char *iden);
void pip_debug_output_ipheader(std::shared_ptr<pip_ip_header> header, const char *iden);

/// 打印UDP
/// @param hdr _
/// @param iden 标识
void pip_debug_output_udp(struct udphdr *hdr, const char *iden);


/// 打印TCP
/// @param tcp _
/// @param packet _
/// @param iden _
void pip_debug_output_tcp(std::shared_ptr<pip_tcp> tcp, std::shared_ptr<pip_tcp_packet> packet, const char *iden);
void pip_debug_output_tcp(std::shared_ptr<pip_tcp> tcp, struct tcphdr *hdr, pip_uint32 datalen, const char *iden);


/// 打印ICMP
/// @param hdr _
/// @param iden _
void pip_debug_output_icmp(struct icmp *hdr, const char *iden);
#endif /* pip_debug_hpp */
