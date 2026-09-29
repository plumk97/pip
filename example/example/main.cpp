//
//  main.cpp
//
//  Created by Plumk on 2021/10/28.
//

/**
 pip 工作在 IP 层: 从 utun 读取 IP 包交给 pip, pip 解析出 TCP/UDP/ICMP 后通过回调交给上层.

 数据流向 (默认参数, 即 README 中的 iperf3 测试):
   iperf3 -c 192.168.33.2
     -> 系统协议栈 -> utun -> pip (本进程)
     -> tcp_proxy / udp_proxy 通过绑定 lo0 的 socket 连接 127.0.0.1 同端口
     -> iperf3 -s

 模块:
   utun       创建虚拟网卡, 读写 IP 包
   tcp_proxy  TCP 连接转发
   udp_proxy  UDP 会话转发
   icmp_echo  直接应答 ping
 */

#include <atomic>
#include <csignal>
#include <vector>

#include "pip.h"
#include "log.hpp"
#include "options.hpp"
#include "utun.hpp"
#include "tcp_proxy.hpp"
#include "udp_proxy.hpp"
#include "icmp_echo.hpp"

namespace {

std::atomic<bool> g_stop{false};

/// 不析构: pip 的定时器线程在进程退出期间仍可能输出数据包
utun * g_utun = new utun();

void on_signal(int) {
    g_stop = true;
}

void on_output_ip_data(pip_netif & netif, std::shared_ptr<pip_buf> buf) {
    (void)netif;
    g_utun->write(buf);
}

} // namespace

int main(int argc, const char * argv[]) {
    static options opts;
    if (!parse_options(argc, argv, opts)) {
        return 1;
    }
    logger::verbose() = opts.verbose;
    
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    
    if (!g_utun->open(opts.local_ip, opts.peer_ip, PIP_MTU)) {
        return 1;
    }
    for (auto & route : opts.routes) {
        if (!g_utun->add_route(route)) {
            return 1;
        }
    }
    
    pip_netif & netif = pip_netif::shared();
    netif.output_ip_data_callback = on_output_ip_data;
    tcp_proxy::start(opts);
    udp_proxy::start(opts);
    icmp_echo::start();
    
    LOG("%s: %s <-> %s (pip), mtu %d", g_utun->name().c_str(), opts.local_ip.c_str(), opts.peer_ip.c_str(), PIP_MTU);
    for (auto & route : opts.routes) {
        LOG("route %s -> %s", route.c_str(), g_utun->name().c_str());
    }
    LOG("forward to %s via %s", opts.redirect_ip.empty() ? "original destination" : opts.redirect_ip.c_str(), opts.out_iface.c_str());
    LOG("Ctrl-C 退出");
    
    std::vector<uint8_t> buffer(PIP_MTU + utun::header_size);
    while (!g_stop) {
        int len = g_utun->read(buffer, 500);
        if (len < 0) {
            LOG("读取 utun 失败, 退出");
            break;
        }
        if (len > 0) {
            netif.input(buffer.data() + utun::header_size, (pip_uint32)len);
        }
    }
    
    LOG("退出: %zu 个 TCP 连接, %zu 个 UDP 会话", tcp_proxy::active_sessions(), udp_proxy::active_flows());
    return 0;
}
