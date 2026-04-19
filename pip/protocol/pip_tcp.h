//
//  pip_tcp.hpp
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_tcp_hpp
#define pip_tcp_hpp

#include <thread>
#include <mutex>
#include <functional>
#include <queue>

#include "pip_tcp_event.h"
#include "pip_tcp_packet.h"

#include "../pip_type.h"
#include "../pip_buf.h"
#include "../pip_ip_header.h"

class pip_tcp_packet;
class pip_tcp;

/// 建立连接完成回调
typedef void (*pip_tcp_connected_callback) (std::shared_ptr<pip_tcp> tcp);

/// 关闭回调 在这个时候资源已经释放完成
typedef void (*pip_tcp_closed_callback) (std::shared_ptr<pip_tcp> tcp, void *arg);

/// 数据接收回调
typedef void (*pip_tcp_received_callback) (std::shared_ptr<pip_tcp> tcp, const void * buffer, pip_uint32 buffer_len);

/// 数据发送完成回调 writeen_len完成发送的字节
/// @param writeen_len 已经发送的字节长度 如果为0 则代表之前对方的wind为0 当前已经更新 可以继续写入
/// @param has_push 是否包含push包
typedef void (*pip_tcp_written_callback) (std::shared_ptr<pip_tcp> tcp, pip_uint32 writeen_len, bool has_push);


bool is_before_seq(pip_uint32 seq, pip_uint32 ack);
pip_uint32 increase_seq(pip_uint32 seq, pip_uint8 flags, pip_uint32 datalen);


class pip_tcp : public std::enable_shared_from_this<pip_tcp> {
    
    /// 连接标识
    pip_uint32 _iden;
    
    /// 包队列
    std::shared_ptr<std::queue<std::shared_ptr<pip_tcp_packet>>> _packet_queue;
    
    /// 对方当前的seq
    pip_uint32 _opp_seq;
    
    /// 当前是否等待确认PUSH包
    bool _is_wait_push_ack;
    
    /// 主动关闭时间 定期检查 防止客户端不响应ACK 导致资源占用
    pip_uint64 _fin_time;
    
    /// ip信息
    std::shared_ptr<pip_ip_header> _ip_header;
    
    /// 源端口
    pip_uint16 _src_port;
    
    /// 目标端口
    pip_uint16 _dst_port;
    
    /// 当前链接状态
    pip_tcp_status _status;
    
    /// 当前发送序号
    pip_uint32 _seq;
    
    /// 当前回复对方的ack
    pip_uint32 _ack;
    
    /// mss
    pip_uint16 _mss;
    
    /// 对方的mss
    pip_uint16 _opp_mss;
    
    /// 接收窗口大小
    pip_uint32 _wind;
    
    /// 窗口缩放位移位数
    pip_uint8 _wind_shift;
    
    /// 对方的窗口大小
    pip_uint32 _opp_wind;
    
    /// 对方窗口缩放位移位数
    pip_uint8 _opp_wind_shift;
    
    /// 外部使用-用于区分
    void * _arg;
    
    /// 连接建立回调
    pip_tcp_connected_callback _connected_callback;

    /// 连接关闭回调
    pip_tcp_closed_callback _closed_callback;

    /// 数据接收回调
    pip_tcp_received_callback _received_callback;

    /// 数据发送完成回调
    pip_tcp_written_callback _written_callback;

public:
    pip_uint32 iden() { 
        _mutex.lock();
        pip_uint32 iden = this->_iden;
        _mutex.unlock();
        return iden; 
    }

    std::shared_ptr<std::queue<std::shared_ptr<pip_tcp_packet>>> packet_queue() { 
        _mutex.lock();
        auto queue = this->_packet_queue;
        _mutex.unlock();
        return queue;
    }

    pip_uint32 opp_seq() { 
        _mutex.lock();
        pip_uint32 opp_seq = this->_opp_seq;
        _mutex.unlock();
        return opp_seq; 
    }
    
    bool is_wait_push_ack() { 
        _mutex.lock();
        bool is_wait = this->_is_wait_push_ack;
        _mutex.unlock();
        return is_wait; 
    }

    pip_uint64 fin_time() { 
        _mutex.lock();
        pip_uint64 fin_time = this->_fin_time;
        _mutex.unlock();
        return fin_time; 
    }

    std::shared_ptr<pip_ip_header> ip_header() { 
        _mutex.lock();
        auto ip_header = this->_ip_header;
        _mutex.unlock();
        return ip_header; 
    }

    pip_uint16 src_port() { 
        _mutex.lock();
        pip_uint16 src_port = this->_src_port;
        _mutex.unlock();
        return src_port; 
    }

    pip_uint16 dst_port() { 
        _mutex.lock();
        pip_uint16 dst_port = this->_dst_port;
        _mutex.unlock();
        return dst_port; 
    }

    pip_tcp_status status() { 
        _mutex.lock();
        pip_tcp_status status = this->_status;
        _mutex.unlock();
        return status; 
    }

    pip_uint32 seq() { 
        _mutex.lock();
        pip_uint32 seq = this->_seq;
        _mutex.unlock();
        return seq; 
    }

    pip_uint32 ack() { 
        _mutex.lock();
        pip_uint32 ack = this->_ack;
        _mutex.unlock();
        return ack; 
    }

    pip_uint16 mss() { 
        _mutex.lock();
        pip_uint16 mss = this->_mss;
        _mutex.unlock();
        return mss; 
    }

    pip_uint16 opp_mss() { 
        _mutex.lock();
        pip_uint16 opp_mss = this->_opp_mss;
        _mutex.unlock();
        return opp_mss; 
    }

    pip_uint16 wind() { 
        _mutex.lock();
        pip_uint16 wind = this->_wind;
        _mutex.unlock();
        return wind; 
    }

    pip_uint32 opp_wind() { 
        _mutex.lock();
        pip_uint32 opp_wind = this->_opp_wind;
        _mutex.unlock();
        return opp_wind; 
    }

    pip_uint8 opp_wind_shift() { 
        _mutex.lock();
        pip_uint8 opp_wind_shift = this->_opp_wind_shift;
        _mutex.unlock();
        return opp_wind_shift; 
    }

    void * arg() { 
        _mutex.lock();
        void * arg = this->_arg;
        _mutex.unlock();
        return arg; 
    }

    void set_arg(void *arg) { 
        _mutex.lock();
        this->_arg = arg;
        _mutex.unlock();
    }

    void set_connected_callback(pip_tcp_connected_callback callback) { 
        _mutex.lock();
        this->_connected_callback = callback;
        _mutex.unlock();
    }

    void set_closed_callback(pip_tcp_closed_callback callback) { 
        _mutex.lock();
        this->_closed_callback = callback;
        _mutex.unlock();
    }

    void set_received_callback(pip_tcp_received_callback callback) { 
        _mutex.lock();
        this->_received_callback = callback;
        _mutex.unlock();
    }

    void set_written_callback(pip_tcp_written_callback callback) { 
        _mutex.lock();
        this->_written_callback = callback;
        _mutex.unlock();
    }

private:
    
    std::mutex _mutex;
    
    ///
    std::vector<pip_tcp_event_variant> _events;
    
    /// 释放资源
    void release();
    
    std::shared_ptr<pip_tcp_packet> create_tcp_packet(pip_uint8 flags, std::shared_ptr<pip_buf> option_buf, std::shared_ptr<pip_buf> payload_buf);
    
public:
    pip_tcp();
    ~pip_tcp();
    
  

public:
    /// 建立连接
    /// @param handshake_data 发起连接时的握手数据
    void connected(const void * handshake_data);
    
    /// 关闭连接
    void close();
    
    /// 重置连接
    void reset();
    
    /// 发送数据 返回发送的长度
    /// @param bytes 待发送数据
    /// @param len 待发送数据长度
    /// @param is_copy 是否复制数据
    pip_uint32 write(const void *bytes, pip_uint32 len, bool is_copy);
    
    /// 当前最大可发送数据量
    pip_uint32 maximum_write_length();
    
    /// 接受数据之后调用更新窗口
    /// @param len 接受的数据大小
    void received(pip_uint16 len);
    
private:
    void _connected(const void * handshake_data);
    void _close();
    void _reset();
    pip_uint32 _write(const void *bytes, pip_uint32 len, bool is_copy);
    pip_uint32 _maximum_write_length();
    void _received(pip_uint16 len);
    void _timer_tick(pip_uint64 now);
    
private:
    /// 处理事件
    void process_events();
    
    /// 发送数据包
    void send_packet(std::shared_ptr<pip_tcp_packet> packet);
    
    /// 重新发送数据包
    void resend_packet(std::shared_ptr<pip_tcp_packet> packet);
    
    /// 发送确认ACK
    void send_ack();
    
    /// 处理建立连接
    void handle_syn(const void * options, pip_uint16 optionlen);
    
    /// 处理断开连接
    void handle_fin();
    
    /// 处理ACK确认
    void handle_ack(pip_uint32 ack, bool is_update_wind);
    
    /// 处理数据接收
    void handle_receive(const void * data, pip_uint16 datalen);
    
    /// 处理TCP数据包
    void handle_input(std::shared_ptr<pip_ip_header> ip_header, struct tcphdr *hdr, const void *bytes, pip_uint16 datalen);
    
public:
    
    /// 处理TCP数据包
    static void input(const void * bytes, std::shared_ptr<pip_ip_header> ip_header);
    
    /// 定时检查
    static void timer_tick();
    
    /// 获取当前连接数
    static pip_uint32 current_connections();
};

#endif /* pip_tcp_hpp */
