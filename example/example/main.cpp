//
//  main.cpp
//  example
//
//  Created by Plumk on 2021/10/28.
//

#include <iostream>
#include "pip.hpp"

/// 输出IP包
void _pip_netif_output_ip_data_callback (pip_netif * netif, pip_buf * buf) {
    std::cout << "_pip_netif_output_ip_data_callback" << std::endl;
    std::cout << std::endl;
}

/// 接受到TCP连接
void _pip_netif_new_tcp_connect_callback (pip_netif * netif, pip_tcp * tcp, const void * take_data, pip_uint16 take_data_len) {
    std::cout << "_pip_netif_new_tcp_connect_callback" << std::endl;
    std::cout << "tcp: " << tcp->ip_header->src_str << ":" << tcp->src_port << " <--> " << tcp->ip_header->dest_str << ":" << tcp->dest_port << std::endl;
    std::cout << std::endl;
    /// 回应连接
    tcp->connected(take_data);
    
}

/// 接受到UDP包
void _pip_netif_received_udp_data_callback(pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dest_ip, pip_uint16 dest_port, pip_uint8 version) {
    
    std::cout << "_pip_netif_received_udp_data_callback" << std::endl;
    std::cout << "udp: " << src_ip << ":" << src_port << " <--> " << dest_ip << ":" << dest_port << std::endl;
    
    char * str = (char *)malloc(buffer_len);
    memcpy(str, buffer, buffer_len);
    
    std::cout << "data: " << str << std::endl;
    std::cout << std::endl;
    
    free(str);
    
    
    pip_udp::output(buffer, buffer_len, src_ip, src_port, dest_ip, dest_port);
}


int main(int argc, const char * argv[]) {
    // insert code here...
    
    /**
     PIP 工作在IP层，七层模型中的第三层，主要处理IP包得到TCP、UDP连接
     该demo演示了一个TCP连接和UDP收发数据, 这个TCP连接只完成了握手的前2次
     */
    pip_netif::shared()->output_ip_data_callback = _pip_netif_output_ip_data_callback;
    pip_netif::shared()->new_tcp_connect_callback = _pip_netif_new_tcp_connect_callback;
    pip_netif::shared()->received_udp_data_callback = _pip_netif_received_udp_data_callback;
    
    
    if (true) {
        /// TCP 连接测试
        const uint8_t bufer[] = {0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x7F, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0xCA, 0x4F, 0x22, 0xB1, 0xC1, 0x27, 0x45, 0x91, 0x00, 0x00, 0x00, 0x00, 0xB0, 0x02, 0xFF, 0xFF, 0xFE, 0x34, 0x00, 0x00, 0x02, 0x04, 0x3F, 0xD8, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0A, 0xC7, 0x00, 0xF6, 0x58, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00};
        
        pip_netif::shared()->input(bufer);
    }
    
    
    if (true) {
        /// UDP 测试
        const uint8_t buffer[] = {0x45, 0x00, 0x00, 0x20, 0xc9, 0x04, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x22, 0xb1, 0x15, 0xb3, 0x00, 0x0c, 0xfe, 0x1f, 0x31, 0x31, 0x31, 0x31};
        pip_netif::shared()->input(buffer);
    }
    
    return 0;
}
