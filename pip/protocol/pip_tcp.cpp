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
#include "../pip_debug.h"


// 判断seq <= ack
bool is_before_seq(pip_uint32 seq, pip_uint32 ack) {
    return (pip_int32)(seq - ack) <= 0;
}

pip_uint32 increase_seq(pip_uint32 seq, pip_uint8 flags, pip_uint32 datalen) {
    
    if (datalen > 0) {
        return seq + datalen;
    }
    
    if ((flags & TH_SYN) || (flags & TH_FIN)) {
        return seq + 1;
    }
    return seq;
}

pip_tcp::pip_tcp() {
    this->_packet_queue = std::make_shared<std::queue<std::shared_ptr<pip_tcp_packet>>>();
    
    this->set_iden(0);
    this->set_opp_seq(0);
    this->set_is_wait_push_ack(false);
    this->set_fin_time(0);
    
    this->set_ip_header(nullptr);
    this->set_src_port(0);
    this->set_dst_port(0);
    this->set_status(pip_tcp_status_none);
    this->set_seq(0);
    this->set_ack(0);
    this->set_mss(PIP_MTU - 40);
    this->set_opp_mss(0);
    this->set_wind(PIP_TCP_WIND);
    this->set_opp_wind(0);
    this->set_opp_wind_shift(0);
    this->set_arg(nullptr);
    
    this->connected_callback = nullptr;
    this->closed_callback = nullptr;
    this->received_callback = nullptr;
    this->written_callback = nullptr;
}

pip_tcp::~pip_tcp() {
    
}

void pip_tcp::release() {
    if (this->status() == pip_tcp_status_released) {
        return;
    }
    this->set_status(pip_tcp_status_released);

    if (this->connected_callback != nullptr) {
        this->connected_callback = nullptr;
    }
    
    if (this->received_callback != nullptr) {
        this->received_callback = nullptr;
    }
    
    if (this->written_callback != nullptr) {
        this->written_callback = nullptr;
    }
    
    this->_events.push_back(pip_tcp_closed_event(this->arg()));
    this->set_arg(nullptr);
}
