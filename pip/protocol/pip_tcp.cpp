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


static pip_tcp_manager * tcp_manager = new pip_tcp_manager();
static std::mutex tcp_manager_mutex;
#define TCP_MANAGER_LOCK std::lock_guard<std::mutex> tcp_manager_lock(tcp_manager_mutex);

/// 判断seq <= ack
bool is_before_seq(pip_uint32 seq, pip_uint32 ack) {
    return (pip_int32)(seq - ack) <= 0;
}

pip_uint32 increase_seq(pip_uint32 seq, pip_uint8 flags, pip_uint32 datalen) {
    
    if (datalen > 0) {
        return seq + datalen;
    }
    
    if (flags & TH_SYN || flags & TH_FIN) {
        return seq + 1;
    }
    return seq;
}

pip_tcp::pip_tcp() {
    
    this->set_iden(0);
    this->set_packet_queue(new pip_queue<pip_tcp_packet *>());
    this->set_opp_seq(0);
    this->set_is_wait_push_ack(false);
    this->set_fin_time(0);
    
    this->set_ip_header(nullptr);
    this->set_src_port(0);
    this->set_dst_port(0);
    this->set_status(pip_tcp_status_closed);
    this->set_seq(pip_netif::shared()->get_isn());
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
    
    if (this->packet_queue()) {
        while (!this->packet_queue()->empty()) {
            delete this->packet_queue()->front();
            this->packet_queue()->pop();
        }
        delete this->packet_queue();
        this->set_packet_queue(nullptr);
    }


    if (this->ip_header() != nullptr) {
        delete this->ip_header();
        this->set_ip_header(nullptr);
    }

    if (this->connected_callback != nullptr) {
        this->connected_callback = nullptr;
    }
    
    if (this->received_callback != nullptr) {
        this->received_callback = nullptr;
    }
    
    if (this->written_callback != nullptr) {
        this->written_callback = nullptr;
    }
    
    void* arg = this->arg();
    this->set_arg(nullptr);

    if (this->closed_callback != nullptr) {
        this->closed_callback(this, arg);
        this->closed_callback = nullptr;
    }
}

void pip_tcp::timer_tick() {
    TCP_MANAGER_LOCK
    
    pip_uint64 cur_time = get_current_time();
    if (tcp_manager->size() <= 0) {
        return;
    }
    
    auto tcps = tcp_manager->tcps();
    for (auto iter = tcps.begin(); iter != tcps.end(); ) {
        
        pip_tcp * tcp = iter->second;
        iter++;
        
        bool is_remove = tcp->withLock<bool>([&tcp, cur_time] {
            
            if (tcp->status() == pip_tcp_status_released) {
                return true;
            }
            
            if ((tcp->status() == pip_tcp_status_fin_wait_1 || tcp->status() == pip_tcp_status_fin_wait_2 || tcp->status() == pip_tcp_status_close_wait) &&
                cur_time - tcp->fin_time() >= 20000) {
                /// 处于等待关闭状态 并且等待时间已经大于20秒 直接关闭
                tcp->release();
                return true;
            }
            
            if (tcp->packet_queue()->empty()) {
                return false;
            }
            
            pip_tcp_packet * packet = tcp->packet_queue()->front();
            if (packet) {
                if (cur_time - packet->send_time() >= 2000) {
                    /// 数据超过2秒没有确认

                    if (packet->send_count() > 2) {
                        /// 已经发送过2次的直接丢弃
                        tcp->packet_queue()->pop();
                        
                        
                        if (packet->payload_len() > 0) {
                            bool has_push = packet->hdr()->th_flags & TH_PUSH;
                            if (has_push) {
                                tcp->set_is_wait_push_ack(false);
                            }

                            if (tcp->written_callback) {
                                tcp->written_callback(tcp, packet->payload_len(), has_push, true);
                            }
                        }
                        

                        delete packet;


                    } else {
                        /// 小于2次的重发
                        tcp->resend_packet(packet);
                    }
                }
            }
            return false;
        });
        
        if (is_remove) {
            tcp_manager->remove_tcp(tcp->iden());
            delete tcp;
        }
    }
}

// MARK: - Lock
template <typename T>
T pip_tcp::withLock(std::function<T()> execute) {
    std::lock_guard<std::recursive_mutex> lock(this->_mutex);
    return execute();
}

template <>
void pip_tcp::withLock(std::function<void()> execute) {
    std::lock_guard<std::recursive_mutex> lock(this->_mutex);
    execute();
}

// MARK: - -
pip_uint32 pip_tcp::current_connections() {
    return tcp_manager->size();
}

void pip_tcp::connected(const void *bytes) {
    this->withLock<void>([&] {
        if (this->status() != pip_tcp_status_wait_establishing) {
            return;
        }
        
        if (bytes == nullptr) {
            this->handle_syn(nullptr, 0);
            return;
        }
        
        struct tcphdr *hdr = (struct tcphdr *)bytes;
        
        // 判断是否有选项 无选项头部为4 * 5 = 20个字节
        if (hdr->th_off > 5) {
            this->handle_syn((pip_uint8 *)hdr + sizeof(struct tcphdr), ((hdr->th_off - 5) * 4));
        } else {
            this->handle_syn(nullptr, 0);
        }
    });
}

void pip_tcp::close() {
    this->withLock<void>([&] {
        pip_tcp_status status = this->status();
        switch (status) {
            case pip_tcp_status_closed: {
                this->release();
                break;
            }
                
            case pip_tcp_status_wait_establishing:
            case pip_tcp_status_establishing: {
                this->reset();
                break;
            }
                
            case pip_tcp_status_established: {
                this->set_status(pip_tcp_status_fin_wait_1);
                this->set_fin_time(get_current_time());

                pip_tcp_packet *packet = new pip_tcp_packet(this, TH_FIN | TH_ACK, nullptr, nullptr);
                this->packet_queue()->push(packet);
                this->send_packet(packet);
                break;
            }
                
            default:
                break;
        }
    });
}

void pip_tcp::reset() {
    this->withLock<void>([&] {
        switch (this->status()) {
        case pip_tcp_status_wait_establishing:
        case pip_tcp_status_establishing:
        case pip_tcp_status_established: {
            pip_tcp_packet* packet = new pip_tcp_packet(this, TH_RST | TH_ACK, nullptr, nullptr);
            this->send_packet(packet);
            delete packet;
            break;
        }

        default:
            break;
        }
        
        this->release();
    });
}

pip_uint32 pip_tcp::write(const void *bytes, pip_uint32 len, bool is_copy) {
    return this->withLock<pip_uint32>([&] {
        if (this->status() != pip_tcp_status_established || !this->can_write()) {
            return pip_uint32(0);
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
            
            pip_buf * payload_buf = new pip_buf((pip_uint8 *)bytes + offset, write_len, is_copy);
            pip_tcp_packet * packet;
            
            if (is_push) {
                packet = new pip_tcp_packet(this, TH_PUSH | TH_ACK, nullptr, payload_buf);
                this->set_is_wait_push_ack(true);
                
            } else {
                packet = new pip_tcp_packet(this, TH_ACK, nullptr, payload_buf);
            }
            
            this->packet_queue()->push(packet);
            this->send_packet(packet);
            
            offset += write_len;
            this->set_opp_wind(this->opp_wind() - write_len);
        }
        
        return offset;
    });
}

void pip_tcp::received(pip_uint16 len) {
    this->withLock<void>([&] {
        if (this->status() != pip_tcp_status_established) {
            return;
        }
        
        this->set_wind(PIP_MIN(this->wind() + len, PIP_TCP_WIND));
        
        // 判断当前是否是最后一次接受的包 如果是直接回复 否等待其它包一起回复
        if (this->ack() - len == this->opp_seq() || this->wind() - len <= 0) {
            this->send_ack();
        }
    });
}

void pip_tcp::debug_status() {
    this->withLock<void>([this] {
        printf("source %s port %d\n", this->ip_header()->src_str(), this->src_port());
        printf("destination %s port %d\n", this->ip_header()->dst_str(), this->dst_port());
        printf("wind %hu \n", this->wind());
        printf("wait ack pkts %d \n", this->packet_queue()->size());
        printf("current tcp connections %u \n", tcp_manager->size());
        printf("\n\n");
    });
}


bool pip_tcp::can_write() {
    return this->withLock<bool>([this] {
        return this->is_wait_push_ack() == false;
    });
}

// MARK: - Send
void pip_tcp::send_packet(pip_tcp_packet *packet) {
    
    packet->sended();
    tcphdr * hdr = packet->hdr();
    pip_uint16 datalen = packet->payload_len();
    
    if (this->ip_header()->version() == 4) {
        pip_netif::shared()->output4(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip_dst(), this->ip_header()->ip_src());
    } else {
        pip_netif::shared()->output6(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip6_dst(), this->ip_header()->ip6_src());
    }
    
    this->set_seq(increase_seq(this->seq(), hdr->th_flags, datalen));
    
#if PIP_DEBUG
    pip_debug_output_tcp(this, packet, "tcp_send");
#endif
}
    
void
pip_tcp::resend_packet(pip_tcp_packet *packet) {
    packet->sended();
    if (this->ip_header()->version() == 4) {
        pip_netif::shared()->output4(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip_dst(), this->ip_header()->ip_src());
    } else {
        pip_netif::shared()->output6(packet->head_buf(), IPPROTO_TCP, this->ip_header()->ip6_dst(), this->ip_header()->ip6_src());
    }
    
#if PIP_DEBUG
    pip_debug_output_tcp(this, packet, "tcp_resend");
#endif
}

void pip_tcp::send_ack() {
    pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, nullptr, nullptr);
    this->send_packet(packet);
    delete packet;
}

// MARK: - Handle
void pip_tcp::handle_ack(pip_uint32 ack, bool is_update_wind) {
    
#if PIP_DEBUG
    printf("[tcp_handle_ack]:\n");
#endif
    
    bool has_syn = false;
    bool has_fin = false;
    bool has_push = false;
    pip_uint32 written_length = 0;
    
    while (!this->packet_queue()->empty()) {
        pip_tcp_packet * pkt = this->packet_queue()->front();
        struct tcphdr * hdr = pkt->hdr();
        
        pip_uint32 seq = ntohl(hdr->th_seq) + pkt->payload_len();
        
        if (hdr == nullptr || is_before_seq(seq, ack) == false) {
#if PIP_DEBUG
            if (hdr)
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
        
        delete pkt;
    }
    
#if PIP_DEBUG
    printf("remain packet num: %d\n", this->_packet_queue->size());
    printf("\n\n");
#endif
    
    if (has_syn) {
        this->set_status(pip_tcp_status_established);
        if (this->connected_callback) {
            this->connected_callback(this);
        }
    }
    
    if (written_length > 0 || is_update_wind) {
        if (this->written_callback) {
            this->written_callback(this, written_length, has_push, false);
        }
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
            if (kind == 0 || kind == 1) {
                continue;
            }
            
            pip_uint8 len = bytes[offset];
            offset += 1;
            
            pip_uint8 value_len = 0;
            if (len > 2) {
                value_len = len - 2;
            }
            
            
            switch (kind) {
                    
                case 2: {
                    // mss
                    pip_uint16 mss = 0;
                    memcpy(&mss, bytes + offset, value_len);
                    this->set_opp_mss(ntohs(mss));
#if PIP_DEBUG
                    printf("mss: %d\n", ntohs(mss));
#endif
                    break;
                }
                    
                case 3: {
                    pip_uint8 shift = 0;
                    memcpy(&shift, bytes + offset, value_len);
                    this->set_opp_wind_shift(shift);
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
    pip_buf * option_buf = new pip_buf(8);
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
    
    pip_tcp_packet * packet = new pip_tcp_packet(this, TH_SYN | TH_ACK, option_buf, nullptr);
    this->packet_queue()->push(packet);
    this->send_packet(packet);
}

void pip_tcp::handle_fin() {
    switch (this->status()) {
        case pip_tcp_status_fin_wait_2: {
            /// 主动关闭 回复ack 清理资源
            pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, nullptr, nullptr);
            this->send_packet(packet);
            
            delete packet;
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
            pip_tcp_packet * packet = new pip_tcp_packet(this, TH_FIN | TH_ACK, nullptr, nullptr);
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
    if (this->received_callback) {
        this->received_callback(this, data, datalen);
    }
}

// MARK: - Input
void pip_tcp::input(const void * bytes, pip_ip_header * ip_header) {
    struct tcphdr *hdr = (struct tcphdr *)bytes;
    
    pip_uint16 datalen = ip_header->datalen() - hdr->th_off * 4;
    pip_uint16 dport = ntohs(hdr->th_dport);
    pip_uint16 sport = ntohs(hdr->th_sport);
    
    if (!(dport >= 1 && dport <= 65535)) {
        delete ip_header;
        return;
    }
    
    TCP_MANAGER_LOCK
    pip_uint32 iden = ip_header->generate_iden() ^ dport ^ sport;
    pip_tcp * tcp = tcp_manager->fetch_tcp(iden, [=] () -> pip_tcp* {
        if (!(hdr->th_flags & TH_SYN)) {
            return nullptr;
        }
        
        pip_tcp * tcp = new pip_tcp();
        tcp->set_iden(iden);

        tcp->set_ip_header(ip_header);

        tcp->set_src_port(sport);
        tcp->set_dst_port(dport);
        return tcp;
    });
    
#if PIP_DEBUG
    pip_debug_output_tcp(tcp, hdr, datalen, "tcp_input");
#endif
    
    if (tcp == nullptr) {
        
        if (hdr->th_flags & TH_RST) {
            delete ip_header;
        } else {
            // 不存在的连接 直接返回RST
            tcp = new pip_tcp();
            tcp->set_iden(iden);
            
            tcp->set_ip_header(ip_header);
            
            tcp->set_src_port(ntohs(hdr->th_sport));
            tcp->set_dst_port(dport);
            
            tcp->set_seq(ntohl(hdr->th_ack));
            tcp->set_ack(increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen));
            
            pip_tcp_packet *packet = new pip_tcp_packet(tcp, TH_RST | TH_ACK, nullptr, nullptr);
            tcp->send_packet(packet);
            delete packet;
            tcp->release();
        }
        
#if PIP_DEBUG
        printf("未获取到TCP连接\n");
#endif
        return;
    }
    
    tcp->withLock<void>([&tcp, ip_header, hdr, datalen, iden, bytes] {
        
        if (tcp->ip_header() != ip_header) {
            delete ip_header;
        }
        
        if (tcp->status() == pip_tcp_status_released) {
            return;
        }
        
        if (hdr->th_flags & TH_RST) {
            // RST 标志直接释放
            tcp->release();
            return;
        }
        
        if (hdr->th_flags == TH_ACK && ntohl(hdr->th_seq) == tcp->ack() - 1) {
            // keep-alive 包 直接回复
            tcp->send_ack();
            return;
        }
        
        if (tcp->ack() > 0) {
            if (ntohl(hdr->th_seq) != tcp->ack()) {
                /// 当前数据包seq与之前的ack对不上 产生了丢包 回复之前的ack 等待重传
                tcp->send_ack();
                return;
            }
        }
        
        tcp->set_opp_seq(ntohl(hdr->th_seq));
        tcp->set_ack(increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen));
        
        bool is_update_wind = false;
        if (tcp->opp_wind() <= 0 && tcp->is_wait_push_ack() == false) {
            is_update_wind = true;
        }
        tcp->set_opp_wind(pip_uint32(ntohs(hdr->th_win)) << tcp->opp_wind_shift());
        
        if (hdr->th_flags & TH_PUSH || datalen > 0) {
            tcp->handle_receive((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
        }
        
        if (hdr->th_flags & TH_ACK) {
            tcp->handle_ack(ntohl(hdr->th_ack), is_update_wind);
        }
        
        if (tcp->status() == pip_tcp_status_released) {
            /// 在handle_ack里已经释放
            return;
        }
        
        if (hdr->th_flags & TH_SYN) {
            tcp->set_status(pip_tcp_status_wait_establishing);
            
            if (pip_netif::shared()->new_tcp_connect_callback) {
                pip_netif::shared()->new_tcp_connect_callback(pip_netif::shared(), tcp, bytes, hdr->th_off * 4);
            }
        }
        
        if (hdr->th_flags & TH_FIN) {
            tcp->handle_fin();
        }
    });
}
