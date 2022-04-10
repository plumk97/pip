//
//  pip_tcp.cpp
//
//  Created by Plumk on 2021/3/11.
//

#include "pip_tcp.hpp"
#include "pip_opt.hpp"
#include "pip_checksum.hpp"
#include "pip_netif.hpp"
#include "pip_debug.hpp"
#include <map>
#include <unistd.h>
#include <arpa/inet.h>
#include <mutex>


/// 判断seq <= ack
int is_before_seq(pip_uint32 seq, pip_uint32 ack) {
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

/// 当前连接
static std::map<pip_uint32, pip_tcp *> tcp_connections;

/// 根据标识提取连接
/// @param iden 连接标识
pip_tcp * fetch_tcp_connection(pip_uint32 iden) {
    if (tcp_connections.find(iden) != tcp_connections.end()) {
        return tcp_connections[iden];
    }
    return NULL;
}

pip_tcp::pip_tcp() {
    this->status = pip_tcp_status_closed;
    this->ack = 0;
    this->seq = pip_netif::shared()->get_isn();
    
    this->wind = PIP_TCP_WIND;
    this->mss = PIP_TCP_MSS;
    
    this->opp_wind = 0;
    this->opp_mss = 0;
    
    this->_last_ack = 0;
    this->_is_wait_push_ack = false;
    
    this->connected_callback = NULL;
    this->closed_callback = NULL;
    this->received_callback = NULL;
    this->written_callback = NULL;
    
    this->ip_header = NULL;
    
    this->arg = NULL;
    
    this->_packet_queue = new pip_queue<pip_tcp_packet *>();
    this->_fin_time = 0;
}

pip_tcp::~pip_tcp() {
    
}

void pip_tcp::release(const char * debug_info) {
    if (this->status == pip_tcp_status_released) {
        return;
    }
    
    
#if PIP_DEBUG
    printf("[tcp_release]:\n");
    printf("release iden %d\n", this->_iden);
    if (debug_info) {
        printf("debug_info: %s\n", debug_info);
    }
    printf("\n\n");
#endif
    tcp_connections.erase(this->_iden);
    this->status = pip_tcp_status_released;
    this->_fin_time = 0;
    
    if (this->_packet_queue != NULL) {
        
        auto queue = this->_packet_queue;
        this->_packet_queue = NULL;
        
        while (!queue->empty()) {
            delete queue->front();
            queue->pop();
        }
        delete queue;
    }
    
    if (this->connected_callback != NULL) {
        this->connected_callback = NULL;
    }
    
    if (this->received_callback != NULL) {
        this->received_callback = NULL;
    }
    
    if (this->written_callback != NULL) {
        this->written_callback = NULL;
    }
    
    if (this->ip_header != NULL) {
        free(this->ip_header);
        this->ip_header = NULL;
    }
    
    void * arg = this->arg;
    this->arg = NULL;
    
    if (this->closed_callback != NULL) {
        this->closed_callback(this, arg);
        this->closed_callback = NULL;
    }
    
    
}

void pip_tcp::timer_tick() {
    
    pip_uint64 cur_time = get_current_time();
    if (tcp_connections.size() <= 0) {
        return;
    }
    
    std::map<pip_uint32, pip_tcp *>::iterator iter;
    for (iter = tcp_connections.begin(); iter != tcp_connections.end();) {

        pip_tcp * tcp = iter->second;
        iter ++;
        
        if ((tcp->status == pip_tcp_status_fin_wait_1 || tcp->status == pip_tcp_status_fin_wait_2) &&
            cur_time - tcp->_fin_time >= 20000) {
            /// 处于等待关闭状态 并且等待时间已经大于20秒 直接关闭
            
            tcp->release("timer_tick");
            delete tcp;
            
        } else {

            pip_tcp_packet * packet = tcp->_packet_queue->front();

            if (packet) {
                if (cur_time - packet->get_send_time() >= 2000) {
                    /// 数据超过2秒没有确认

                    if (packet->get_send_count() > 2) {
                        /// 已经发送过2次的直接丢弃
                        tcp->_packet_queue->pop();

                        if (packet->get_hdr()->th_flags & TH_PUSH) {
                            tcp->_is_wait_push_ack = false;
                        }

                        if (tcp->written_callback) {
                            tcp->written_callback(tcp, packet->get_payload_len());
                        }

                        delete packet;


                    } else {
                        /// 小于2次的重发
                        tcp->resend_packet(packet);
                    }

                }

            }
        }
    }
}

// MARK: - -
pip_uint32 pip_tcp::current_connections() {
    return (pip_uint32)tcp_connections.size();
}

void pip_tcp::connected(const void *bytes) {
    if (this->status != pip_tcp_status_wait_establishing) {
        return;
    }
    
    if (bytes == NULL) {
        this->handle_syn(NULL, 0);
        return;
    }
    
    struct tcphdr *hdr = (struct tcphdr *)bytes;
    
    // 判断是否有选项 无选项头部为4 * 5 = 20个字节
    if (hdr->th_off > 5) {
        this->handle_syn((pip_uint8 *)hdr + sizeof(struct tcphdr), ((hdr->th_off - 5) * 4));
    } else {
        this->handle_syn(NULL, 0);
    }
}

void pip_tcp::close() {
    
    switch (this->status) {
        case pip_tcp_status_closed: {
            this->release("close");
            delete this;
            break;
        }
            
        case pip_tcp_status_wait_establishing:
        case pip_tcp_status_establishing: {
            this->reset();
            break;
        }
            
        case pip_tcp_status_established: {
            this->status = pip_tcp_status_fin_wait_1;
            this->_fin_time = get_current_time();

            pip_tcp_packet *packet = new pip_tcp_packet(this, TH_FIN | TH_ACK, NULL, NULL, "pip_tcp::close");
            this->_packet_queue->push(packet);
            this->send_packet(packet);
            break;
        }
            
        default:
            break;
    }
}

void pip_tcp::reset() {
    
    switch (this->status) {
        case pip_tcp_status_wait_establishing:
        case pip_tcp_status_establishing:
        case pip_tcp_status_established: {
            pip_tcp_packet *packet = new pip_tcp_packet(this, TH_RST | TH_ACK, NULL, NULL, "pip_tcp::reset");
            this->send_packet(packet);
            delete packet;
        }
            break;
            
        default:
            break;
    }
    
    if (this->status == pip_tcp_status_released) {
        return;
    }

    this->release("reset");
    delete this;
}

pip_uint32 pip_tcp::write(const void *bytes, pip_uint32 len) {
    if (this->status != pip_tcp_status_established || !this->can_write()) {
        return 0;
    }
    
    pip_uint32 offset = 0;
    while (offset < len && this->opp_wind > 0) {
        
        pip_uint16 write_len = this->opp_mss;
        
        /// 获取小于等于mss的数据长度
        if (offset + write_len > len) {
            write_len = len - offset;
        }
        
        /// 获取小于等于对方的窗口长度
        if (write_len > this->opp_wind) {
            write_len = this->opp_wind;
        }
        
        if (write_len <= 0) {
            break;
        }
        
        /// 如果当前发送数据大于等于总数据长度 或者 对方窗口为0 则发送PUSH标签
        pip_uint8 is_push = offset + write_len >= len || write_len >= this->opp_wind;
        
        pip_buf * payload_buf = new pip_buf((pip_uint8 *)bytes + offset, write_len, 1);
        pip_tcp_packet * packet;
        if (is_push) {
            packet = new pip_tcp_packet(this, TH_PUSH | TH_ACK, NULL, payload_buf, "pip_tcp::write1");
            this->_is_wait_push_ack = true;
            
        } else {
            packet = new pip_tcp_packet(this, TH_ACK, NULL, payload_buf, "pip_tcp::write2");
        }
        
        this->_packet_queue->push(packet);
        this->send_packet(packet);
        
        offset += write_len;
        this->opp_wind -= write_len;
    }
    
    return offset;
}

void pip_tcp::received(pip_uint16 len) {
    if (this->status != pip_tcp_status_established) {
        return;
    }
    
    this->wind = PIP_MIN(this->wind + len, PIP_TCP_WIND);
    if (this->wind - len <= 0 && this->ack == this->_last_ack) {
        /// 当前窗口<=0，并且无等待发送的包 直接发送ack 更新窗口
        this->send_ack();
    }
}

void pip_tcp::debug_status() {
    printf("source %s port %d\n", this->ip_header->src_str, this->src_port);
    printf("destination %s port %d\n", this->ip_header->dest_str, this->dest_port);
    printf("wind %hu \n", this->wind);
    printf("wait ack pkts %d \n", this->_packet_queue->size());
    
    printf("current tcp connections %lu \n", tcp_connections.size());
    printf("\n\n");
}

pip_uint32 pip_tcp::get_iden() {
    return this->_iden;
}

bool pip_tcp::can_write() {
    return this->_is_wait_push_ack == false;
}

// MARK: - Send
void pip_tcp::send_packet(pip_tcp_packet *packet) {
    
    packet->sended();
    tcphdr * hdr = packet->get_hdr();
    pip_uint16 datalen = packet->get_payload_len();
    pip_netif::shared()->output(packet->get_head_buf(), IPPROTO_TCP, this->ip_header->dest, this->ip_header->src);
    
    this->_last_ack = ntohl(hdr->th_ack);
    
    this->seq = increase_seq(this->seq, hdr->th_flags, datalen);
    
#if PIP_DEBUG
    pip_debug_output_tcp(this, packet, "tcp_send");
#endif
}
    
void
pip_tcp::resend_packet(pip_tcp_packet *packet) {
    packet->sended();
    pip_netif::shared()->output(packet->get_head_buf(), IPPROTO_TCP, this->ip_header->dest, this->ip_header->src);
    
#if PIP_DEBUG
    pip_debug_output_tcp(this, packet, "tcp_resend");
#endif
}

void pip_tcp::send_ack() {
    pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, NULL, NULL, "pip_tcp::send_ack");
    this->send_packet(packet);
    delete packet;
}

// MARK: - Handle
void pip_tcp::handle_ack(pip_uint32 ack) {
    
#if PIP_DEBUG
    printf("[tcp_handle_ack]:\n");
#endif
    
    
    bool has_syn = false;
    bool has_fin = false;
    pip_uint32 written_length = 0;
    
    while (this->_packet_queue->size() > 0) {
        pip_tcp_packet * pkt = this->_packet_queue->front();
        struct tcphdr * hdr = pkt->get_hdr();
        
        pip_uint32 seq = ntohl(hdr->th_seq) + pkt->get_payload_len();
        
        if (hdr == NULL || is_before_seq(seq, ack) == false) {
#if PIP_DEBUG
            if (hdr)
                printf("break seq: %d ack: %d\n", ntohl(hdr->th_seq), ack);
#endif
            break;
        }
        this->_packet_queue->pop();
        
        if (hdr->th_flags & TH_SYN) {
            this->status = pip_tcp_status_established;
            has_syn = true;
        }
        
        if (pkt->get_payload_len() > 0) {
            if (hdr->th_flags & TH_PUSH) {
                this->_is_wait_push_ack = false;
            }
            
            written_length += pkt->get_payload_len();
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
        if (this->connected_callback) {
            this->connected_callback(this);
        }
    }
    
    if (written_length > 0) {
        if (this->written_callback) {
            this->written_callback(this, written_length);
        }
    }
    
    if (has_fin) {
        if (this->status == pip_tcp_status_fin_wait_1) {
            /// 主动关闭 改变状态
            this->status = pip_tcp_status_fin_wait_2;
            this->_fin_time = get_current_time();
            
        } else if (this->status == pip_tcp_status_close_wait) {
            /// 被动关闭 清理资源
            this->release("handle_ack");
            delete this;
        }
    }
}

void pip_tcp::handle_syn(void * options, pip_uint16 optionlen) {
    this->status = pip_tcp_status_establishing;
    
#if PIP_DEBUG
    printf("[tcp_handle_syn]:\n");
    printf("parse option:\n");
    printf("option len: %d\n", optionlen);
    printf("\n");
#endif
    if (optionlen > 0) {
        pip_uint8 * bytes = (pip_uint8 *)options;
        pip_uint16 offset = 0;
        pip_uint16 pre_offset = -1;
        /// pre_offset != offset 防止碰到无法解析的出现死循环
        while (offset < optionlen && pre_offset != offset) {
            
            pre_offset = offset;
            pip_uint8 kind = bytes[offset];
            
            if (kind == 0) {
                break;
            }
            
            switch (kind) {
                case 1: {
                    offset += 1;
                    break;
                }
                    
                case 2: {
                    // mss
                    pip_uint8 len = bytes[offset + 1];
                    pip_uint16 mss = 0;
                    memcpy(&mss, bytes + offset + 2, len - offset - 2);
                    this->opp_mss = ntohs(mss);
#if PIP_DEBUG
                    printf("mss: %d", ntohs(mss));
#endif
                    
                    offset += len;
                    break;
                }
                    
                default: {
                    pip_uint8 len = bytes[offset + 1];
                    offset += len;
                    break;
                }
            }
        }
    }
    
#if PIP_DEBUG
    printf("\n\n");
#endif
    pip_buf * option_buf = new pip_buf(4);
    pip_uint8 * optionBuffer = (pip_uint8 *)option_buf->payload;
    memset(optionBuffer, 0, 4);
    if (true) {
        // mss
        pip_uint8 kind = 2;
        pip_uint8 len = 4;
        pip_uint16 value = htons(PIP_MIN(this->mss, this->opp_mss));

        memcpy(optionBuffer, &kind, 1);
        memcpy(optionBuffer + 1, &len, 1);
        memcpy(optionBuffer + 2, &value, 2);
    }
    
    pip_tcp_packet * packet = new pip_tcp_packet(this, TH_SYN | TH_ACK, option_buf, NULL, "pip_tcp::handle_syn");
    this->_packet_queue->push(packet);
    this->send_packet(packet);
}

void pip_tcp::handle_fin() {
    if (this->status == pip_tcp_status_fin_wait_2) {
        /// 主动关闭 回复ack 清理资源
        
        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, NULL, NULL, "pip_tcp::handle_fin1");
        this->send_packet(packet);
        this->release("handle_fin");
        delete this;
        delete packet;
        
    } else {
        /// 被动关闭回复
        if (this->status != pip_tcp_status_established) {
            return;
        }
        
        this->status = pip_tcp_status_close_wait;
        
//        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_ACK, NULL, NULL, "pip_tcp::handle_fin2");
//        this->send_packet(packet);
//        delete packet;
//
        pip_tcp_packet * packet = new pip_tcp_packet(this, TH_FIN | TH_ACK, NULL, NULL, "pip_tcp::handle_fin2");
        this->_packet_queue->push(packet);
        this->send_packet(packet);
    }
}

void pip_tcp::handle_push(void *data, pip_uint16 datalen) {
    this->handle_receive(data, datalen);
    
}

void pip_tcp::handle_receive(void *data, pip_uint16 datalen) {

    
#if PIP_DEBUG
    printf("[tcp_handle_receive]:\n");
    printf("receive data: %d\n", datalen);
    printf("\n\n");
#endif
    this->wind -= datalen;
    if (this->received_callback) {
        this->received_callback(this, data, datalen);
    }
    
    if (datalen > 0) {
        this->send_ack();
    }
}

// MARK: - Input
void pip_tcp::input(const void * bytes, pip_ip_header * ip_header) {
    struct tcphdr *hdr = (struct tcphdr *)bytes;
    
    pip_uint16 datalen = ip_header->datalen - hdr->th_off * 4 - ip_header->headerlen;
    pip_uint16 dport = ntohs(hdr->th_dport);
    pip_uint16 sport = ntohs(hdr->th_sport);
    
    if (!(dport >= 1 && dport <= 65535)) {
        delete ip_header;
        return;
    }
    
    pip_uint32 iden = ip_header->src ^ ip_header->dest ^ dport ^ sport;
    pip_tcp * tcp = fetch_tcp_connection(iden);
    
    if (tcp == NULL && hdr->th_flags & TH_SYN && tcp_connections.size() < PIP_TCP_MAX_CONNS) {
        tcp = new pip_tcp;
        tcp->_iden = iden;
        
        tcp->ip_header = ip_header;
        
        tcp->src_port = sport;
        tcp->dest_port = dport;
        
        tcp_connections[iden] = tcp;
    }
    
    
#if PIP_DEBUG
    pip_debug_output_tcp(tcp, hdr, datalen, "tcp_input");
#endif
    
    if (tcp == NULL) {
        
        if (hdr->th_flags & TH_RST) {
            delete ip_header;
        } else {
            // 不存在的连接 直接返回RST
            tcp = new pip_tcp;
            tcp->_iden = iden;
            
            tcp->ip_header = ip_header;
            
            tcp->src_port = ntohs(hdr->th_sport);
            tcp->dest_port = dport;
            
            tcp->seq = ntohl(hdr->th_ack);
            tcp->ack = increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen);
            
            pip_tcp_packet *packet = new pip_tcp_packet(tcp, TH_RST | TH_ACK, NULL, NULL, "pip_tcp::input pip_tcp::reset");
            tcp->send_packet(packet);
            delete packet;
            
            tcp->release("pip_tcp::input no exist");
            delete tcp;
        }
        
#if PIP_DEBUG
        printf("未获取到TCP连接\n");
#endif
        return;
    }
    
    if (tcp->ip_header != ip_header) {
        delete ip_header;
    }
    
    if (hdr->th_flags == TH_ACK && ntohl(hdr->th_seq) == tcp->ack - 1) {
        // keep-alive 包 直接回复
        tcp->send_ack();
        return;
    }
    
    if (tcp->ack > 0) {
        if (ntohl(hdr->th_seq) != tcp->ack) {
            /// 当前数据包seq与之前的ack对不上 产生了丢包 回复之前的ack 等待重传
            tcp->send_ack();
            return;
        }
    }
    
    tcp->ack = increase_seq(ntohl(hdr->th_seq), hdr->th_flags, datalen);
    tcp->opp_wind = ntohs(hdr->th_win);
    
    
    if (hdr->th_flags & TH_PUSH) {
        tcp->handle_push((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
    } else if (datalen > 0) {
        tcp->handle_receive((pip_uint8 *)bytes + hdr->th_off * 4, datalen);
    }
    
    if (hdr->th_flags & TH_ACK) {
        tcp->handle_ack(ntohl(hdr->th_ack));
    }
    
    if (fetch_tcp_connection(iden) == NULL) {
        /// 防止 tcp 在handle_ack里释放了继续执行崩溃
        return;
    }
    
    if (hdr->th_flags & TH_RST) {
        // RST 标志直接释放
        tcp->release("pip_tcp::input");
        delete tcp;
        return;
    }
    
    if (hdr->th_flags & TH_SYN) {
        tcp->status = pip_tcp_status_wait_establishing;
        if (pip_netif::shared()->new_tcp_connect_callback) {
            pip_netif::shared()->new_tcp_connect_callback(pip_netif::shared(), tcp, bytes, hdr->th_off * 4);
        }
    }
    
    if (hdr->th_flags & TH_FIN) {
        tcp->handle_fin();
    }
}


// MARK: - pip_tcp_packet
pip_tcp_packet::
pip_tcp_packet(pip_tcp *tcp, pip_uint8 flags, pip_buf * option_buf, pip_buf * payload_buf, const char * debug_iden) {
    
    this->_send_time = 0;
    this->_send_count = 0;
    
    pip_uint8 * buffer = (pip_uint8 *)calloc(1, sizeof(struct tcphdr));
    this->_buffer = buffer;
    this->_debug_iden = debug_iden;
    
    // -- 赋值BUF
    pip_buf * head_buf = new pip_buf(buffer, sizeof(struct tcphdr), 0);
    if (option_buf != NULL) {
        option_buf->set_next(payload_buf);
        head_buf->set_next(option_buf);
    } else if (payload_buf != NULL) {
        head_buf->set_next(payload_buf);
    }
    
    
    this->_head_buf = head_buf;


    if (payload_buf) {
        this->_payload_len = payload_buf->total_len;
    } else {
        this->_payload_len = 0;
    }
    
    // - 填充头部
    int offset = 0;
    if (true) {
        // 源端口
        int len = sizeof(pip_uint16);
        pip_uint16 port = htons(tcp->dest_port);
        memcpy(buffer + offset, &port, len);
        
        offset += len;
    }
    
    if (true) {
        // 目标端口
        int len = sizeof(pip_uint16);
        pip_uint16 port = htons(tcp->src_port);
        memcpy(buffer + offset, &port, len);
        
        offset += len;
    }
    
    if (true) {
        // 序号
        int len = sizeof(pip_uint32);
        pip_uint32 seq = htonl(tcp->seq);
        memcpy(buffer + offset, &seq, len);
        
        offset += len;
    }
    
    if (true) {
        // 确认号
        int len = sizeof(pip_uint32);
        pip_uint32 ack = htonl(tcp->ack);
        memcpy(buffer + offset, &ack, len);
        
        offset += len;
    }
    
    
    if (true) {
        // 头部长度 保留 标识
        int len = sizeof(pip_uint16);
        pip_uint16 h_flags = 0;
        
        pip_uint16 headlen = head_buf->payload_len;
        if (option_buf != NULL) {
            headlen += option_buf->payload_len;
        }
        
        h_flags = (headlen / 4) << 12;
        h_flags = h_flags | flags;
        h_flags = htons(h_flags);
        memcpy(buffer + offset, &h_flags, len);
        
        offset += len;
    }
    
    
    if (true) {
        // 窗口大小
        int len = sizeof(pip_uint16);
        pip_uint16 wind = htons(tcp->wind);
        memcpy(buffer + offset, &wind, len);
        
        offset += len;
    }
    
    // 校验和偏移
    int checksum_offset = offset;
    offset += sizeof(pip_uint16);
    
    // 紧急指针
    offset += sizeof(pip_uint16);
    
    
    if (true) {
        // 计算校验和
        
        pip_uint16 checksum = pip_inet_checksum_buf(head_buf, IPPROTO_TCP, tcp->ip_header->dest, tcp->ip_header->src);
        checksum = htons(checksum);
        memcpy(buffer + checksum_offset, &checksum, sizeof(pip_uint16));
    }
    
    
}

pip_tcp_packet::
~pip_tcp_packet() {
    
    if (this->_head_buf) {
        delete this->_head_buf;
        this->_head_buf = NULL;
    }
    
    if (this->_buffer) {
        free(this->_buffer);
        this->_buffer = NULL;
    }
}


struct tcphdr *
pip_tcp_packet::get_hdr() {
    if (this->_buffer) {
        return (struct tcphdr *)this->_buffer;
    }
    return NULL;
}

pip_buf *
pip_tcp_packet::get_head_buf() {
    return this->_head_buf;
}

pip_uint32
pip_tcp_packet::get_payload_len() {
    return this->_payload_len;
}


pip_uint64
pip_tcp_packet::get_send_time() {
    return this->_send_time;
}


pip_uint8
pip_tcp_packet::get_send_count() {
    return this->_send_count;
}

void
pip_tcp_packet::sended() {
    this->_send_time = get_current_time();
    this->_send_count += 1;
}
