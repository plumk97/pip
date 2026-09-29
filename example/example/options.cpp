//
//  options.cpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "options.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <net/if.h>

static void print_usage(const char * prog) {
    fprintf(stderr,
            "用法: %s [选项]\n"
            "\n"
            "创建 utun 虚拟网卡, 由 pip 处理发往 utun 的 IP 包, 并把 TCP/UDP 连接转发到本机 socket.\n"
            "需要 root 权限运行.\n"
            "\n"
            "选项:\n"
            "  --local <ip>       utun 本端地址 (默认 192.168.33.1)\n"
            "  --peer <ip>        utun 对端地址, 即 pip 所在地址 (默认 192.168.33.2)\n"
            "  --route <cidr>     额外路由到 utun 的网段, 可多次指定, 例如 1.1.1.1/32\n"
            "  --redirect <ip>    所有连接转发到该地址, 端口不变 (默认 127.0.0.1)\n"
            "                     指定 none 则连接原目标地址, 此时需要配合 --iface 指定物理网卡\n"
            "  --iface <name>     出站 socket 绑定的网卡 (默认 lo0)\n"
            "  -v                 打印每个连接\n"
            "  -h                 显示帮助\n"
            "\n"
            "示例:\n"
            "  # iperf3 测试: 连接 192.168.33.2 的流量被转发到 127.0.0.1\n"
            "  sudo %s\n"
            "  iperf3 -c 192.168.33.2\n"
            "\n"
            "  # 透明代理 1.1.1.1: 经 pip 处理后从 en0 连接原目标\n"
            "  sudo %s --route 1.1.1.1/32 --redirect none --iface en0 -v\n"
            "  curl https://1.1.1.1\n",
            prog, prog, prog);
}

static bool is_ipv4(const std::string & ip) {
    struct in_addr addr;
    return inet_pton(AF_INET, ip.c_str(), &addr) == 1;
}

static bool is_ip(const std::string & ip) {
    struct in6_addr addr6;
    return is_ipv4(ip) || inet_pton(AF_INET6, ip.c_str(), &addr6) == 1;
}

bool parse_options(int argc, const char * argv[], options & opts) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        auto next = [&](std::string & out) -> bool {
            if (i + 1 >= argc) {
                fprintf(stderr, "%s 缺少参数\n", arg.c_str());
                return false;
            }
            out = argv[++i];
            return true;
        };
        
        if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return false;
        } else if (arg == "-v") {
            opts.verbose = true;
        } else if (arg == "--local") {
            if (!next(opts.local_ip)) return false;
        } else if (arg == "--peer") {
            if (!next(opts.peer_ip)) return false;
        } else if (arg == "--route") {
            std::string route;
            if (!next(route)) return false;
            opts.routes.push_back(route);
        } else if (arg == "--redirect") {
            if (!next(opts.redirect_ip)) return false;
            if (opts.redirect_ip == "none") {
                opts.redirect_ip.clear();
            }
        } else if (arg == "--iface") {
            if (!next(opts.out_iface)) return false;
        } else {
            fprintf(stderr, "未知参数: %s\n\n", arg.c_str());
            print_usage(argv[0]);
            return false;
        }
    }
    
    if (!is_ipv4(opts.local_ip) || !is_ipv4(opts.peer_ip)) {
        fprintf(stderr, "--local / --peer 需要是 IPv4 地址\n");
        return false;
    }
    
    if (!opts.redirect_ip.empty() && !is_ip(opts.redirect_ip)) {
        fprintf(stderr, "--redirect 地址无效: %s\n", opts.redirect_ip.c_str());
        return false;
    }
    
    if (opts.redirect_ip.empty() && opts.out_iface == "lo0") {
        fprintf(stderr, "--redirect none 时需要用 --iface 指定物理网卡, 例如 en0\n");
        return false;
    }
    
    opts.out_ifindex = if_nametoindex(opts.out_iface.c_str());
    if (opts.out_ifindex == 0) {
        fprintf(stderr, "网卡不存在: %s\n", opts.out_iface.c_str());
        return false;
    }
    
    return true;
}
