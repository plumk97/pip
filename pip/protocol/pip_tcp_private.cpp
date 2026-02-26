//
//  pip_tcp_private.cpp
//
//  Created by Plumk on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "../pip_netif.h"



void pip_tcp::_connected(const void * handshake_data) {
    if (this->status() != pip_tcp_status_wait_establishing) {
        return;
    }
    
    if (handshake_data == nullptr) {
        this->handle_syn(nullptr, 0);
        return;
    }
    
    struct tcphdr *hdr = (struct tcphdr *)handshake_data;
    
    // 判断是否有选项 无选项头部为4 * 5 = 20个字节
    if (hdr->th_off > 5) {
        this->handle_syn((pip_uint8 *)hdr + sizeof(struct tcphdr), ((hdr->th_off - 5) * 4));
    } else {
        this->handle_syn(nullptr, 0);
    }
}

void pip_tcp::_close() {
    pip_tcp_status status = this->status();
    switch (status) {
        case pip_tcp_status_none: {
            this->release();
            break;
        }
            
        case pip_tcp_status_wait_establishing:
        case pip_tcp_status_establishing: {
            this->_reset();
            break;
        }
            
        case pip_tcp_status_established: {
            this->set_status(pip_tcp_status_fin_wait_1);
            this->set_fin_time(get_current_time());

            auto packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_FIN | TH_ACK, nullptr, nullptr);
            this->packet_queue()->push(packet);
            this->send_packet(packet);
            break;
        }
            
        default:
            break;
    }
}

pip_uint32 pip_tcp::_write(const void *bytes, pip_uint32 len, bool is_copy) {
    if (_maximum_write_length() <= 0) {
        return 0;
    }
    
    pip_uint32 offset = 0;
    while (offset < len && this->opp_wind() > 0) {
        
        pip_uint16 write_len = this->opp_mss();
        
        /// 获取小于等于mss的数据长度
        if (offset + write_len > len) {
            write_len = len - offset;
        }
        
        /// 获取小于等于对方的窗口长度
        if (write_len > this->opp_wind()) {
            write_len = this->opp_wind();
        }
        
        if (write_len <= 0) {
            break;
        }
        
        /// 如果当前发送数据大于等于总数据长度 或者 对方窗口为0 则发送PUSH标签
        pip_uint8 is_push = offset + write_len >= len || write_len >= this->opp_wind();
        
        auto payload_buf = std::make_shared<pip_buf>((pip_uint8 *)bytes + offset, write_len, is_copy);
        std::shared_ptr<pip_tcp_packet> packet;
        
        if (is_push) {
            packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_PUSH | TH_ACK, nullptr, payload_buf);
            this->set_is_wait_push_ack(true);
            
        } else {
            packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_ACK, nullptr, payload_buf);
        }
        
        this->packet_queue()->push(packet);
        this->send_packet(packet);
        
        offset += write_len;
        this->set_opp_wind(this->opp_wind() - write_len);
    }
    
    return offset;
}

pip_uint32 pip_tcp::_maximum_write_length() {
    if (_is_wait_push_ack || _status != pip_tcp_status_established) {
        return 0;
    }
    
    return _opp_wind;
}

void pip_tcp::_received(pip_uint16 len) {
    if (this->status() != pip_tcp_status_established) {
        return;
    }
    
    this->set_wind(PIP_MIN(this->wind() + len, PIP_TCP_WIND));
    
    // 判断当前是否是最后一次接受的包 如果是直接回复 否等待其它包一起回复
    if (this->ack() - len == this->opp_seq() || this->wind() - len <= 0) {
        this->send_ack();
    }
}

void pip_tcp::_reset() {
    auto packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_RST | TH_ACK, nullptr, nullptr);
    this->send_packet(packet);
    this->release();
}

// MARK: - Send
void pip_tcp::send_packet(std::shared_ptr<pip_tcp_packet> packet) {
    
    packet->sended();
    tcphdr * hdr = packet->hdr();
    pip_uint16 datalen = packet->payload_len();
    
    if (this->ip_header()->version() == 4) {
        pip_netif::shared().output4(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip_dst(), this->ip_header()->ip_src());
    } else {
        pip_netif::shared().output6(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip6_dst(), this->ip_header()->ip6_src());
    }
    
    this->set_seq(increase_seq(this->seq(), hdr->th_flags, datalen));
    
#if PIP_DEBUG
    pip_debug_output_tcp(shared_from_this(), packet, "tcp_send");
#endif
}
    
void
pip_tcp::resend_packet(std::shared_ptr<pip_tcp_packet> packet) {
    packet->sended();
    if (this->ip_header()->version() == 4) {
        pip_netif::shared().output4(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip_dst(), this->ip_header()->ip_src());
    } else {
        pip_netif::shared().output6(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip6_dst(), this->ip_header()->ip6_src());
    }
    
#if PIP_DEBUG
    pip_debug_output_tcp(shared_from_this(), packet, "tcp_resend");
#endif
}

void pip_tcp::send_ack() {
    auto packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_ACK, nullptr, nullptr);
    this->send_packet(packet);
}


// MARK: - Handle
void pip_tcp::handle_ack(pip_uint32 ack, bool is_update_wind) {
    
    bool has_syn = false;
    bool has_fin = false;
    bool has_push = false;
    pip_uint32 written_length = 0;
    
    while (!this->packet_queue()->empty()) {
        auto pkt = this->packet_queue()->front();
        struct tcphdr * hdr = pkt->hdr();

        if (hdr == nullptr) {
            break;
        }

        pip_uint32 seq = increase_seq(ntohl(hdr->th_seq), hdr->th_flags, pkt->payload_len());

        if (is_before_seq(seq, ack) == false) {
#if PIP_DEBUG
            printf("break seq: %d ack: %d\n", ntohl(hdr->th_seq), ack);
#endif
            break;
        }
        this->packet_queue()->pop();
        
        if (hdr->th_flags & TH_SYN) {
            has_syn = true;
        }
        
        if (pkt->payload_len() > 0) {
            written_length += pkt->payload_len();
            
            if (hdr->th_flags & TH_PUSH) {
                has_push = true;
                this->set_is_wait_push_ack(false);
            }
        }
        
        if (hdr->th_flags & TH_FIN) {
            has_fin = true;
        }
        
    }
    
#if PIP_DEBUG
    printf("remain packet num: %d\n", this->_packet_queue->size());
    printf("\n\n");
#endif
    
    if (has_syn) {
        this->set_status(pip_tcp_status_established);
        this->_events.push_back(pip_tcp_connected_event());
    }
    
    if (written_length > 0 || is_update_wind) {
        this->_events.push_back(pip_tcp_written_event(written_length, has_push, false));
    }
    
    if (has_fin) {
        if (this->status() == pip_tcp_status_fin_wait_1) {
            /// 主动关闭 改变状态
            this->set_status(pip_tcp_status_fin_wait_2);
            this->set_fin_time(get_current_time());
            
        } else if (this->status() == pip_tcp_status_close_wait) {
            /// 被动关闭 清理资源
            this->release();
        }
    }
}

void pip_tcp::handle_syn(const void * options, pip_uint16 optionlen) {
    this->set_status(pip_tcp_status_establishing);
    
#if PIP_DEBUG
    printf("[tcp_handle_syn]:\n");
    printf("parse option:\n");
    printf("option len: %d\n", optionlen);
    printf("\n");
#endif
    if (optionlen > 0) {
        pip_uint8 * bytes = (pip_uint8 *)options;
        pip_uint16 offset = 0;
        while (offset < optionlen) {
            pip_uint8 kind = bytes[offset];
            offset += 1;
#if PIP_DEBUG
            printf("kind: %d\n", kind);
#endif
            if (kind == 0) {
                break;
            }

            if (kind == 1) {
                continue;
            }

            if (offset >= optionlen) {
                break;
            }
            
            pip_uint8 len = bytes[offset];
            if (len < 2) {
                break;
            }
            offset += 1;

            if (offset + (len - 2) > optionlen) {
                break;
            }
            
            pip_uint8 value_len = 0;
            if (len > 2) {
                value_len = len - 2;
            }
            
            
            switch (kind) {
                    
                case 2: {
                    // mss
                    pip_uint16 mss = 0;
                    if (value_len >= sizeof(pip_uint16)) {
                        memcpy(&mss, bytes + offset, sizeof(pip_uint16));
                        this->set_opp_mss(ntohs(mss));
                    }
#if PIP_DEBUG
                    printf("mss: %d\n", ntohs(mss));
#endif
                    break;
                }
                    
                case 3: {
                    pip_uint8 shift = 0;
                    if (value_len >= sizeof(pip_uint8)) {
                        memcpy(&shift, bytes + offset, sizeof(pip_uint8));
                        this->set_opp_wind_shift(shift);
                    }
                    break;
                }
                    
                default: {
                    break;
                }
            }
            
            offset += value_len;
        }
    }
    
#if PIP_DEBUG
    printf("\n\n");
#endif
    auto option_buf = std::make_shared<pip_buf>(8);
    pip_uint8 * optionBuffer = (pip_uint8 *)option_buf->payload();
    memset(optionBuffer, 0, 4);
    pip_uint8 offset = 0;
    if (true) {
        // mss
        pip_uint8 kind = 2;
        pip_uint8 len = 4;
        pip_uint16 value = htons(PIP_MIN(this->mss(), this->opp_mss()));

        memcpy(optionBuffer, &kind, 1);
        memcpy(optionBuffer + 1, &len, 1);
        memcpy(optionBuffer + 2, &value, 2);
        
        offset += len;
    }
    
    if (true) {
        // window scale
        pip_uint8 kind = 3;
        pip_uint8 len = 3;
        pip_uint8 value = 0;

        memcpy(optionBuffer + offset, &kind, 1);
        memcpy(optionBuffer + offset + 1, &len, 1);
        memcpy(optionBuffer + offset + 2, &value, 1);
        
        offset += len;
    }
    
    auto packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_SYN | TH_ACK, option_buf, nullptr);
    this->packet_queue()->push(packet);
    this->send_packet(packet);
}

void pip_tcp::handle_fin() {
    switch (this->status()) {
        case pip_tcp_status_fin_wait_2: {
            /// 主动关闭 回复ack 清理资源
            auto packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_ACK, nullptr, nullptr);
            this->send_packet(packet);
            this->release();
            break;
        }
            
        case pip_tcp_status_established: {
            /// 被动关闭回复
            this->set_status(pip_tcp_status_close_wait);
            
//        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, nullptr, nullptr, "pip_tcp::handle_fin2");
//        this->send_packet(packet);
//        delete packet;
//
            auto packet = std::make_shared<pip_tcp_packet>(shared_from_this(), TH_FIN | TH_ACK, nullptr, nullptr);
            this->packet_queue()->push(packet);
            this->send_packet(packet);
            break;
        }
            
        default:
            break;
    }
}


void pip_tcp::handle_receive(const void *data, pip_uint16 datalen) {
    
#if PIP_DEBUG
    printf("[tcp_handle_receive]:\n");
    printf("receive data: %d\n", datalen);
    printf("\n\n");
#endif
    
    this->set_wind(this->wind() - datalen);
    this->_events.push_back(pip_tcp_received_event(data, datalen));
}

/// 处理Input
void pip_tcp::handle_input(std::shared_ptr<pip_ip_header> ip_header, struct tcphdr *hdr, const void *bytes, pip_uint16 datalen) {
    if (this->status() == pip_tcp_status_released) {
        return;
    }
    
    if (hdr->th_flags & TH_RST) {
        // RST 标志直接释放
        this->release();
        return;
    }
    
    if (hdr->th_flags == TH_ACK && ntohl(hdr->th_seq) == this->ack() - 1) {
        // keep-alive 包 直接回复
        this->send_ack();
        return;
    }
    
    if (this->ack() > 0) {
        if (ntohl(hdr->th_seq) != this->ack()) {
            /// 当前数据包seq与之前的ack对不上 产生了丢包 回复之前的ack 等待重传
            this->send_ack();
            return;
        }
    }
    
    this->set_opp_seq(ntohl(hdr->th_seq));
    this->set_ack(increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen));
    
    bool is_update_wind = false;
    if (this->opp_wind() <= 0 && this->is_wait_push_ack() == false) {
        is_update_wind = true;
    }
    this->set_opp_wind(pip_uint32(ntohs(hdr->th_win)) << this->opp_wind_shift());
    
    if (hdr->th_flags & TH_PUSH || datalen > 0) {
        this->handle_receive((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
    }
    
    if (hdr->th_flags & TH_ACK) {
        this->handle_ack(ntohl(hdr->th_ack), is_update_wind);
    }
    
    if (this->status() == pip_tcp_status_released) {
        /// 在handle_ack里已经释放
        return;
    }
    
    if (hdr->th_flags & TH_SYN) {
        
        switch (this->status()) {
            case pip_tcp_status_none: {
                // 建立连接
                this->set_status(pip_tcp_status_wait_establishing);
                this->_events.push_back(pip_tcp_connect_event(bytes, hdr->th_off * 4));
                break;
            }
                
            case pip_tcp_status_wait_establishing:
            case pip_tcp_status_establishing:
                // 重复忽略
                break;
                
            case pip_tcp_status_established: {
                // 已连接 重新回复ack
                this->handle_syn(nullptr, 0);
                break;
            }

            default: {
                // 其他状态reset
                this->_reset();
                break;
            }
        }
        
        
    }
    
    if (hdr->th_flags & TH_FIN) {
        this->handle_fin();
    }
}
