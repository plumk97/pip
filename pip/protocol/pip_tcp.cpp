//
//  pip_tcp.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include <random>

#include "pip_tcp.h"
#include "pip_tcp_manager.h"
#include "pip_tcp_packet.h"

#include "../pip_opt.h"
#include "../pip_checksum.h"
#include "../pip_netif.h"


// 判断seq <= ack
bool is_before_seq(pip_uint32 seq, pip_uint32 ack) {
    return (pip_int32)(seq - ack) <= 0;
}

pip_uint32 increase_seq(pip_uint32 seq, pip_uint8 flags, pip_uint32 datalen) {
    pip_uint32 n = seq + datalen;

    if ((flags & TH_SYN) || (flags & TH_FIN)) {
        n += 1;
    }
    return n;
}

pip_uint32 pip_tcp_generate_isn() {
    thread_local std::mt19937 engine(std::random_device{}());
    return (pip_uint32)engine();
}

pip_tcp_key::pip_tcp_key(std::shared_ptr<pip_ip_header> ip_header, pip_uint16 src_port, pip_uint16 dst_port) {
    this->version = ip_header->version();
    this->src_port = src_port;
    this->dst_port = dst_port;

    if (this->version == 4) {
        pip_in_addr src = ip_header->ip_src();
        pip_in_addr dst = ip_header->ip_dst();
        memcpy(this->src_addr, &src, sizeof(src));
        memcpy(this->dst_addr, &dst, sizeof(dst));
    } else {
        pip_in6_addr src = ip_header->ip6_src();
        pip_in6_addr dst = ip_header->ip6_dst();
        memcpy(this->src_addr, &src, sizeof(src));
        memcpy(this->dst_addr, &dst, sizeof(dst));
    }
}

bool pip_tcp_key::operator<(const pip_tcp_key & other) const {
    if (this->version != other.version) {
        return this->version < other.version;
    }
    if (this->src_port != other.src_port) {
        return this->src_port < other.src_port;
    }
    if (this->dst_port != other.dst_port) {
        return this->dst_port < other.dst_port;
    }
    int cmp = memcmp(this->src_addr, other.src_addr, sizeof(this->src_addr));
    if (cmp != 0) {
        return cmp < 0;
    }
    return memcmp(this->dst_addr, other.dst_addr, sizeof(this->dst_addr)) < 0;
}

pip_tcp::pip_tcp() {
    this->_packet_queue = std::make_shared<std::queue<std::shared_ptr<pip_tcp_packet>>>();
    
    this->_opp_seq = 0;
    this->_fin_time = 0;
    
    this->_ip_header = nullptr;
    this->_src_port = 0;
    this->_dst_port = 0;
    this->_status = pip_tcp_status_none;
    this->_seq = 0;
    this->_ack = 0;
    this->_mss = PIP_MTU - 40;
    this->_opp_mss = 0;
    this->_wind = PIP_TCP_WIND << PIP_TCP_WIND_SHIFT;
    this->_wind_shift = PIP_TCP_WIND_SHIFT;
    this->_opp_wind = 0;
    this->_opp_wind_shift = 0;
    this->_opp_adv_wind = 0;
    this->_dup_ack_count = 0;
    this->_in_recovery = false;
    this->_recover = 0;
    this->_arg = nullptr;
    
    this->_connected_callback = nullptr;
    this->_closed_callback = nullptr;
    this->_received_callback = nullptr;
    this->_written_callback = nullptr;
}

pip_tcp::~pip_tcp() {
    
}

void pip_tcp::release() {
    if (this->_status == pip_tcp_status_released) {
        return;
    }
    this->_status = pip_tcp_status_released;

    if (this->_connected_callback != nullptr) {
        this->_connected_callback = nullptr;
    }
    
    if (this->_received_callback != nullptr) {
        this->_received_callback = nullptr;
    }
    
    if (this->_written_callback != nullptr) {
        this->_written_callback = nullptr;
    }
    
    if (this->_arg != nullptr) {
        this->_events.push_back(pip_tcp_closed_event(this->_arg));
        this->_arg = nullptr;
    }
    
}
