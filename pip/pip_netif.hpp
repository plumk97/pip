//
//  pip_netif.hpp
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_netif_hpp
#define pip_netif_hpp

#include "pip_type.hpp"
#include "pip_buf.hpp"

class pip_netif;
class pip_tcp;

/// 输出IP包数据
/// @param netif _
/// @param buf IP包数据
typedef void (*pip_netif_output_ip_data_callback) (pip_netif * netif, pip_buf * buf);

/// 接受到一个新的TCP连接
/// @param netif _
/// @param tcp TCP连接对象
/// @param take_data 建立连接携带的数据 连接成功调用 connected 方法需要传入
/// @param take_data_len 携带数据长度
typedef void (*pip_netif_new_tcp_connect_callback) (pip_netif * netif, pip_tcp * tcp, const void * take_data, pip_uint16 take_data_len);

/// 接受到UDP数据
/// @param netif _
/// @param buffer 数据
/// @param buffer_len 数据长度
/// @param src_ip 来源地址
/// @param src_port 来源端口
/// @param dest_ip 目的地址
/// @param dest_port 目的端口
/// @param version IP协议版本 4 || 6
typedef void (*pip_netif_received_udp_data_callback) (pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port, pip_uint8 version);

// 接受到ICMP数据
typedef void (*pip_netif_received_icmp_data_callback) (pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, const char * dest_ip);


class pip_netif {
    pip_netif();
    ~pip_netif();
    
public:
    static pip_netif * shared();
    
    /// 输入IP包
    /// @param buffer _
    void input(const void * buffer);
    
    /// 内部使用 外部通过 pip_netif_output_callback 获取输出的IP包
    /// @param buf _
    /// @param proto _
    /// @param src _
    /// @param dest _
    void output(pip_buf * buf, pip_uint8 proto, pip_uint32 src, pip_uint32 dest);
    
    
    /// 需要至少250ms调用一次该函数
    void timer_tick();
    
    pip_uint32 get_isn();
    
public:
    pip_netif_output_ip_data_callback output_ip_data_callback;
    pip_netif_new_tcp_connect_callback new_tcp_connect_callback;
    pip_netif_received_udp_data_callback received_udp_data_callback;
    pip_netif_received_icmp_data_callback received_icmp_data_callback;
    
private:
    pip_uint16 _identifer = 0;
    pip_uint32 _isn = 0;
};


#endif /* pip_netif_hpp */
