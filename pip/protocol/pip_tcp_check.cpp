//
//  pip_tcp_check.cpp
//
//  Created by Plumk on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "pip_tcp_manager.h"

void pip_tcp::_timer_tick(pip_uint64 now) {
    auto & manager = pip_tcp_manager::shared();
    if (this->status() == pip_tcp_status_released) {
        manager.remove_tcp(this->iden());
        return;
    }
    
    if ((this->status() == pip_tcp_status_fin_wait_1 || this->status() == pip_tcp_status_fin_wait_2 || this->status() == pip_tcp_status_close_wait) &&
        now - this->fin_time() >= 20000) {
        /// 处于等待关闭状态 并且等待时间已经大于20秒 直接关闭
        this->release();
        return;
    }

    if (this->packet_queue()->empty()) {
        return;
    }
    
    auto packet = this->packet_queue()->front();
    if (now - packet->send_time() < 1000) {
        return;
    }
    
    /// 数据超过5次没有确认断开连接
    if (packet->send_count() > 5) {
        this->_reset();
    } else {
        this->resend_packet(packet);
    }
    
}


void pip_tcp::timer_tick() {
    pip_uint64 cur_time = get_current_time();
    auto & manager = pip_tcp_manager::shared();
    if (manager.size() <= 0) {
        return;
    }
    
    auto tcps = manager.tcps();
    for (auto iter = tcps.begin(); iter != tcps.end(); ) {
        
        auto tcp = iter->second;
        iter++;
        
        tcp->_mutex.lock();
        tcp->_timer_tick(cur_time);
        tcp->_mutex.unlock();
    }
}
