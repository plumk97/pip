//
//  pip_tcp_private.cpp
//
//  Created by Plumk on 2026/1/9.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "pip_tcp.h"
#include "../pip_netif.h"


std::shared_ptr<pip_tcp_packet> pip_tcp::create_tcp_packet(pip_uint8 flags, std::shared_ptr<pip_buf> option_buf, std::shared_ptr<pip_buf> payload_buf) {
    // SYN 包的窗口不做缩放 (RFC 7323)
    pip_uint32 wind = (flags & TH_SYN) ? PIP_MIN(this->_wind, (pip_uint32)0xFFFF) : this->_wind >> this->_wind_shift;
    return std::make_shared<pip_tcp_packet>(this->_ip_header,
                                            this->_dst_port,
                                            this->_src_port,
                                            this->_seq,
                                            this->_ack,
                                            wind,
                                            flags,
                                            option_buf,
                                            payload_buf);
}


void pip_tcp::_connected(const void * handshake_data) {
    if (this->_status != pip_tcp_status_wait_establishing) {
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
    pip_tcp_status status = this->_status;
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
            this->_status = pip_tcp_status_fin_wait_1;
            this->_fin_time = get_current_time();

            auto packet = this->create_tcp_packet(TH_FIN | TH_ACK, nullptr, nullptr);
            this->_packet_queue->push(packet);
            this->send_packet(packet);
            break;
        }
            
        default:
            break;
    }
}

pip_uint32 pip_tcp::_write(const void *bytes, pip_uint32 len, bool is_copy) {
    if (_maximum_write_length() <= 0 || len <= 0) {
        return 0;
    }
    
    pip_uint32 offset = 0;
    while (offset < len && this->_opp_wind > 0) {
        
        pip_uint16 write_len = PIP_MIN(this->_mss, this->_opp_mss);
        
        /// 获取小于等于mss的数据长度
        if (offset + write_len > len) {
            write_len = len - offset;
        }
        
        /// 获取小于等于对方的窗口长度
        if (write_len > this->_opp_wind) {
            write_len = this->_opp_wind;
        }
        
        if (write_len <= 0) {
            break;
        }
        
        /// 如果当前发送数据大于等于总数据长度 或者 对方窗口为0 则发送PUSH标签
        pip_uint8 is_push = offset + write_len >= len || write_len >= this->_opp_wind;
        
        auto payload_buf = std::make_shared<pip_buf>((pip_uint8 *)bytes + offset, write_len, is_copy);
        std::shared_ptr<pip_tcp_packet> packet;
        
        if (is_push) {
            packet = this->create_tcp_packet(TH_PUSH | TH_ACK, nullptr, payload_buf);
            this->_is_wait_push_ack = true;
            
        } else {
            packet = this->create_tcp_packet(TH_ACK, nullptr, payload_buf);
        }
        
        this->_packet_queue->push(packet);
        this->send_packet(packet);
        
        offset += write_len;
        this->_opp_wind = this->_opp_wind - write_len;
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
    if (this->_status != pip_tcp_status_established) {
        return;
    }
    pip_uint32 old_wind = this->_wind;
    pip_uint32 max_wind = (pip_uint32)PIP_TCP_WIND << this->_wind_shift;
    this->_wind = PIP_MIN(this->_wind + len, max_wind);
    
    // 判断当前是否是最后一次接受的包 如果是直接回复 否等待其它包一起回复
    // 之前窗口不足一个 mss 时对方可能已被阻塞, 需要立即通告新窗口
    if (this->_ack - len == this->_opp_seq || old_wind < this->_mss) {
        this->send_ack();
    }
}

void pip_tcp::_reset() {
    auto packet = this->create_tcp_packet(TH_RST | TH_ACK, nullptr, nullptr);
    this->send_packet(packet);
    this->release();
}

// MARK: - Send
void pip_tcp::send_packet(std::shared_ptr<pip_tcp_packet> packet) {
    
    packet->sended();
    tcphdr * hdr = packet->hdr();
    pip_uint16 datalen = packet->payload_len();
    
    this->_outputs.push_back(packet);
    
    this->_seq = increase_seq(this->_seq, hdr->th_flags, datalen);
    
#if PIP_DEBUG
    pip_debug_output_tcp(shared_from_this(), packet, "tcp_send");
#endif
}
    
void
pip_tcp::resend_packet(std::shared_ptr<pip_tcp_packet> packet) {
    packet->sended();
    this->_outputs.push_back(packet);
    
#if PIP_DEBUG
    pip_debug_output_tcp(shared_from_this(), packet, "tcp_resend");
#endif
}

void pip_tcp::retransmit_front() {
    if (this->_packet_queue->empty()) {
        return;
    }
    
    this->resend_packet(this->_packet_queue->front());
    this->_in_recovery = true;
    this->_recover = this->_seq;
    this->_dup_ack_count = 0;
}

pip_uint32 pip_tcp::snd_una() {
    if (this->_packet_queue->empty()) {
        return this->_seq;
    }
    return ntohl(this->_packet_queue->front()->hdr()->th_seq);
}

void pip_tcp::send_ack() {
    auto packet = this->create_tcp_packet(TH_ACK, nullptr, nullptr);
    this->send_packet(packet);
}


// MARK: - Handle
void pip_tcp::handle_ack(pip_uint32 ack, bool is_update_wind) {
    
    bool has_syn = false;
    bool has_fin = false;
    bool has_push = false;
    bool has_popped = false;
    pip_uint32 written_length = 0;
    
    while (!this->_packet_queue->empty()) {
        auto pkt = this->_packet_queue->front();
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
        this->_packet_queue->pop();
        has_popped = true;
        
        if (hdr->th_flags & TH_SYN) {
            has_syn = true;
        }
        
        if (pkt->payload_len() > 0) {
            written_length += pkt->payload_len();
            
            if (hdr->th_flags & TH_PUSH) {
                has_push = true;
                this->_is_wait_push_ack = false;
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
    
    if (has_popped) {
        this->_dup_ack_count = 0;
        
        if (this->_in_recovery) {
            if (is_before_seq(this->_recover, ack)) {
                this->_in_recovery = false;
            } else if (!this->_packet_queue->empty()) {
                // 部分确认: 下一个包大概率也已丢失, 立即重传而不是等待超时
                this->resend_packet(this->_packet_queue->front());
            }
        }
    }
    
    if (has_syn) {
        this->_status = pip_tcp_status_established;
        this->_events.push_back(pip_tcp_connected_event());
    }
    
    if (written_length > 0 || is_update_wind) {
        this->_events.push_back(pip_tcp_written_event(written_length, has_push));
    }
    
    if (has_fin) {
        if (this->_status == pip_tcp_status_fin_wait_1) {
            /// 主动关闭 改变状态
            this->_status = pip_tcp_status_fin_wait_2;
            this->_fin_time = get_current_time();
            
        } else if (this->_status == pip_tcp_status_close_wait) {
            /// 被动关闭 清理资源
            this->release();
        }
    }
}

void pip_tcp::handle_syn(const void * options, pip_uint16 optionlen) {
    this->_status = pip_tcp_status_establishing;
    
    // IP头 + TCP头
    bool is_ipv4 = this->_ip_header->version() == 4;
    this->_mss = PIP_MTU - (is_ipv4 ? 40 : 60);
    
    // 对方未携带 MSS 选项时的默认值 (RFC 9293)
    this->_opp_mss = is_ipv4 ? 536 : 1220;
    
    bool has_wind_shift = false;
    
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
                        this->_opp_mss = ntohs(mss);
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
                        this->_opp_wind_shift = PIP_MIN(shift, (pip_uint8)14);
                        has_wind_shift = true;
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
    // 双方都携带 window scale 选项才启用缩放 (RFC 7323)
    if (!has_wind_shift) {
        this->_opp_wind_shift = 0;
        this->_wind_shift = 0;
        this->_wind = PIP_TCP_WIND;
    }
    
    auto option_buf = std::make_shared<pip_buf>(has_wind_shift ? 8 : 4);
    pip_uint8 * optionBuffer = (pip_uint8 *)option_buf->payload();
    pip_uint8 offset = 0;
    if (true) {
        // mss
        pip_uint8 kind = 2;
        pip_uint8 len = 4;
        pip_uint16 value = htons(this->_mss);

        memcpy(optionBuffer, &kind, 1);
        memcpy(optionBuffer + 1, &len, 1);
        memcpy(optionBuffer + 2, &value, 2);
        
        offset += len;
    }
    
    if (has_wind_shift) {
        // nop + window scale
        pip_uint8 nop = 1;
        pip_uint8 kind = 3;
        pip_uint8 len = 3;
        pip_uint8 value = this->_wind_shift;

        memcpy(optionBuffer + offset, &nop, 1);
        memcpy(optionBuffer + offset + 1, &kind, 1);
        memcpy(optionBuffer + offset + 2, &len, 1);
        memcpy(optionBuffer + offset + 3, &value, 1);
        
        offset += len + 1;
    }
    
    auto packet = this->create_tcp_packet(TH_SYN | TH_ACK, option_buf, nullptr);
    this->_packet_queue->push(packet);
    this->send_packet(packet);
}

void pip_tcp::handle_fin() {
    switch (this->_status) {
        case pip_tcp_status_fin_wait_2: {
            /// 主动关闭 回复ack 清理资源
            auto packet = this->create_tcp_packet(TH_ACK, nullptr, nullptr);
            this->send_packet(packet);
            this->release();
            break;
        }
            
        case pip_tcp_status_established: {
            /// 被动关闭回复
            this->_status = pip_tcp_status_close_wait;
            this->_fin_time = get_current_time();
            
//        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, nullptr, nullptr, "pip_tcp::handle_fin2");
//        this->send_packet(packet);
//        delete packet;
//
            auto packet = this->create_tcp_packet(TH_FIN | TH_ACK, nullptr, nullptr);
            this->_packet_queue->push(packet);
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
    
    this->_wind = this->_wind - datalen;
    this->_events.push_back(pip_tcp_received_event(data, datalen));
}

/// 处理Input
void pip_tcp::handle_input(std::shared_ptr<pip_ip_header> ip_header, struct tcphdr *hdr, const void *bytes, pip_uint16 datalen) {
    if (this->_status == pip_tcp_status_released) {
        return;
    }
    
    if (hdr->th_flags & TH_RST) {
        // RST 标志直接释放
        this->release();
        return;
    }
    
    pip_uint32 seg_seq = ntohl(hdr->th_seq);
    pip_uint32 seg_ack = ntohl(hdr->th_ack);
    
    if ((hdr->th_flags & TH_SYN) && this->_status != pip_tcp_status_none) {
        if (this->_status != pip_tcp_status_wait_establishing && this->_status != pip_tcp_status_establishing) {
            // 已同步状态下收到 SYN, 回复 challenge ACK (RFC 5961)
            this->send_ack();
        }
        // 握手阶段的重复 SYN 忽略, SYN-ACK 由定时器重传
        return;
    }
    
    if (hdr->th_flags == TH_ACK && seg_seq == this->_ack - 1) {
        // keep-alive 包 直接回复
        this->send_ack();
        return;
    }
    
    if (this->_status != pip_tcp_status_none && seg_seq != this->_ack) {
        /// 当前数据包seq与之前的ack对不上 产生了丢包 回复之前的ack 等待重传
        this->send_ack();
        return;
    }
    
    if (datalen > this->_wind) {
        /// 超出接收窗口 (包括零窗口探测) 回复当前窗口
        this->send_ack();
        return;
    }
    
    if ((hdr->th_flags & TH_ACK) && !is_before_seq(seg_ack, this->_seq)) {
        /// 确认了尚未发送的数据
        this->send_ack();
        return;
    }
    
    this->_opp_seq = seg_seq;
    this->_ack = increase_seq(seg_seq, hdr->th_flags, datalen);
    
    bool is_update_wind = false;
    if (hdr->th_flags & TH_ACK) {
        pip_uint32 una = this->snd_una();
        
        // 过期的 ACK 不更新窗口
        if (is_before_seq(una, seg_ack)) {
            pip_uint32 old_wind = this->_opp_wind;
            
            // 对方通告的窗口从 seg_ack 开始计算, 需要扣除在途数据
            pip_uint32 wnd = pip_uint32(ntohs(hdr->th_win)) << this->_opp_wind_shift;
            pip_uint32 in_flight = this->_seq - seg_ack;
            this->_opp_wind = wnd > in_flight ? wnd - in_flight : 0;
            
            is_update_wind = old_wind == 0 && this->_opp_wind > 0 && this->_is_wait_push_ack == false;
            
            bool is_dup_ack = seg_ack == una &&
                              datalen == 0 &&
                              !(hdr->th_flags & (TH_SYN | TH_FIN)) &&
                              !this->_packet_queue->empty() &&
                              this->_opp_wind == old_wind;
            if (is_dup_ack) {
                this->_dup_ack_count += 1;
                if (this->_dup_ack_count == 3 && !this->_in_recovery) {
                    // 快速重传
                    this->retransmit_front();
                }
            }
        }
    } else if (hdr->th_flags & TH_SYN) {
        // SYN 包的窗口不缩放
        this->_opp_wind = ntohs(hdr->th_win);
    }
    
    if (hdr->th_flags & TH_PUSH || datalen > 0) {
        this->handle_receive((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
    }
    
    if (hdr->th_flags & TH_ACK) {
        this->handle_ack(seg_ack, is_update_wind);
    }
    
    if (this->_status == pip_tcp_status_released) {
        /// 在handle_ack里已经释放
        return;
    }
    
    if ((hdr->th_flags & TH_SYN) && this->_status == pip_tcp_status_none) {
        // 建立连接
        this->_status = pip_tcp_status_wait_establishing;
        this->_events.push_back(pip_tcp_connect_event(bytes, hdr->th_off * 4));
    }
    
    if (hdr->th_flags & TH_FIN) {
        this->handle_fin();
    }
}
