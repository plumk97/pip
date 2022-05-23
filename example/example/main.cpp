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
    std::cout << "tcp: " << tcp->ip_header->src_str << ":" << tcp->src_port << " <--> " << tcp->ip_header->dst_str << ":" << tcp->dst_port << std::endl;
    std::cout << std::endl;
    /// 回应连接
    tcp->connected(take_data);
    
}

/// 接受到UDP包
void _pip_netif_received_udp_data_callback(pip_netif * netif, void * buffer, pip_uint16 buffer_len, const char * src_ip, pip_uint16 src_port, const char * dst_ip, pip_uint16 dst_port, pip_uint8 version) {
    
    std::cout << "_pip_netif_received_udp_data_callback" << std::endl;
    std::cout << "udp: " << src_ip << ":" << src_port << " <--> " << dst_ip << ":" << dst_port << std::endl;
    
    char * str = (char *)malloc(buffer_len);
    memcpy(str, buffer, buffer_len);
    
    std::cout << "data: " << str << std::endl;
    std::cout << std::endl;
    
    free(str);
    
    
    pip_udp::output(buffer, buffer_len, src_ip, src_port, dst_ip, dst_port);
}

uint8_t char_to_uint8(char ch)
{
    int num = 0;
    if (ch >= '0' && ch <= '9') {
        num = ch - 0x30;
    }
    else {
        switch (ch) {
        case 'A':
        case 'a':
            num = 10;
            break;
        case 'B':
        case 'b':
            num = 11;
            break;
        case 'C':
        case 'c':
            num = 12;
            break;
        case 'D':
        case 'd':
            num = 13;
            break;
        case 'E':
        case 'e':
            num = 14;
            break;
        case 'F':
        case 'f':
            num = 15;
            break;
        default:
            num = 0;
        }
    }
    return num;
}

uint8_t * hexstr_to_bytes(const char * hexstr, size_t *len) {
    
    size_t slen = strlen(hexstr);
    uint8_t *bytes = (uint8_t *)calloc((slen+1)/2, sizeof(uint8_t));
    
    if (len != NULL) {
        *len = (slen+1)/2;
    }
    
    size_t i = 0;
    size_t j = 0;
    while (i < slen) {
        if (i + 1 >= slen) {
            break;
        }
        
        uint16_t byte = char_to_uint8(hexstr[i]) << 4 | char_to_uint8(hexstr[i + 1]);
        bytes[j] = byte;
        i += 2;
        j += 1;
    }
    
    if (i < slen) {
        bytes[j] = char_to_uint8(hexstr[i]) << 4;
    }
    return bytes;
}


void test_ipv4() {
    if (true) {
        /// TCP 连接测试
        uint8_t * bytes = hexstr_to_bytes("45000040000040004006af7ac0a80a970ed7b127e935005058956fea00000000b0c2ffff523d0000020405b4010303060101080a0021a69a0000000004020000", NULL);
        pip_netif::shared()->input(bytes);
    }
    
    if (true) {
        /// UDP 测试
        const uint8_t buffer[] = {0x45, 0x00, 0x00, 0x20, 0xc9, 0x04, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x22, 0xb1, 0x15, 0xb3, 0x00, 0x0c, 0xfe, 0x1f, 0x31, 0x31, 0x31, 0x31};
        pip_netif::shared()->input(buffer);
    }
}

void test_ipv6() {
    /// - 计算checksum 使用
    uint8_t * bytes = hexstr_to_bytes("6000090000200640fe800000000000001cf09906557f6696fe800000000000001ca68fd2c002024de365c3c8cf526361df778640801000b31c5500000101080a6f8d10e542f278df", NULL);
    pip_netif::shared()->input(bytes);
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
    
    test_ipv4();
//    test_ipv6();
    
    return 0;
}
