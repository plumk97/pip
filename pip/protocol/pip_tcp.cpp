//
//  pip_tcp.cpp
//
//  Created by Plumk on 2021/3/11.
//

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

pip_tcp::pip_tcp() {
    this->_packet_queue = std::make_shared<std::queue<std::shared_ptr<pip_tcp_packet>>>();
    
    this->_iden = 0;
    this->_opp_seq = 0;
    this->_is_wait_push_ack = false;
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
