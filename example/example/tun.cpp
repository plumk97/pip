//
//  tun.cpp
//
//  Created by Plumk on 2023/3/25.
//  Copyright © 2023 Plumk. All rights reserved.
//

#include "tun.hpp"

#include <iostream>
#include <string>
#include <sstream>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/kern_event.h>
#include <net/if_utun.h>
#include <net/if.h>

#include "pip_tcp.h"

int open_tun_socket () {
    
    int err = 0;
    
    int fd = socket (PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) return fd;
    
    // 创建 UTUN
    struct ctl_info info;
    bzero(&info, sizeof (info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);

    err = ioctl(fd, CTLIOCGINFO, &info);
    if (err != 0) {
        perror(nullptr);
        close(fd);
        return err;
    };

    struct sockaddr_ctl addr;
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0; // 设置 UTUN 接口编号 0自动分配
    
    err = connect(fd, (struct sockaddr *)&addr, sizeof (addr));
    if (err != 0) {
        perror(nullptr);
        close(fd);
        return err;
    };
    
    // 获取 UTUN 接口名称
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    
    char ifname[IF_NAMESIZE];
    socklen_t ifname_len = sizeof(ifname);
    err = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len);
    if (err == -1) {
        perror(nullptr);
        close(fd);
        return err;
    }
    
    // 设置 UTUN 网关地址
    std::stringstream cmd;
    cmd << "ifconfig " << ifname << " 192.168.33.1 192.168.33.1 netmask 255.255.255.255 mtu " << PIP_MTU << " up";
    err = std::system(cmd.str().c_str());
    if (err != 0) {
        perror(nullptr);
        close(fd);
        return err;
    }
    
    // 设置路由
    err = std::system("route -n add -net 1.1.1.1/32 192.168.33.1");
    if (err != 0) {
        perror(nullptr);
        close(fd);
        return err;
    }
    
    return fd;
}
