//
//  utun.cpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "utun.hpp"

#include <cerrno>
#include <cstring>
#include <net/if.h>
#include <net/if_utun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/uio.h>
#include <unistd.h>

#include "log.hpp"

static bool run_command(const std::string & cmd) {
    VLOG("$ %s", cmd.c_str());
    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        LOG("命令执行失败 (%d): %s", ret, cmd.c_str());
        return false;
    }
    return true;
}

utun::~utun() {
    if (_fd >= 0) {
        ::close(_fd);
    }
}

bool utun::open(const std::string & local_ip, const std::string & peer_ip, int mtu) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        LOG("创建 utun socket 失败: %s", strerror(errno));
        return false;
    }
    
    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &info) != 0) {
        LOG("CTLIOCGINFO 失败: %s", strerror(errno));
        ::close(fd);
        return false;
    }
    
    struct sockaddr_ctl addr;
    memset(&addr, 0, sizeof(addr));
    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = 0; // 0 自动分配 utun 编号
    
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        LOG("创建 utun 失败 (需要 root 权限): %s", strerror(errno));
        ::close(fd);
        return false;
    }
    
    char ifname[IF_NAMESIZE] = {};
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) != 0) {
        LOG("获取 utun 名称失败: %s", strerror(errno));
        ::close(fd);
        return false;
    }
    
    _fd = fd;
    _name = ifname;
    
    return run_command("ifconfig " + _name + " " + local_ip + " " + peer_ip +
                       " netmask 255.255.255.255 mtu " + std::to_string(mtu) + " up");
}

bool utun::add_route(const std::string & cidr) {
    return run_command("route -q -n add -net " + cidr + " -interface " + _name);
}

int utun::read(std::vector<uint8_t> & buffer, int timeout_ms) {
    struct pollfd pfd = {_fd, POLLIN, 0};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret == 0 || (ret < 0 && errno == EINTR)) {
        return 0;
    }
    if (ret < 0) {
        return -1;
    }
    
    ssize_t len = ::read(_fd, buffer.data(), buffer.size());
    if (len < 0) {
        return errno == EINTR || errno == EAGAIN ? 0 : -1;
    }
    if (len <= header_size) {
        return 0;
    }
    
    return (int)(len - header_size);
}

bool utun::write(const std::shared_ptr<pip_buf> & buf) {
    if (_fd < 0 || buf == nullptr || buf->payload_len() == 0) {
        return false;
    }
    
    pip_uint8 version = ((const pip_uint8 *)buf->payload())[0] >> 4;
    uint32_t family = htonl(version == 6 ? AF_INET6 : AF_INET);
    
    // 地址族头部 + IP头 + TCP/UDP头 + 选项 + 数据
    struct iovec iov[8];
    int count = 0;
    iov[count++] = {&family, sizeof(family)};
    for (auto p = buf; p != nullptr && count < 8; p = p->next()) {
        if (p->payload_len() > 0) {
            iov[count++] = {p->payload(), p->payload_len()};
        }
    }
    
    return writev(_fd, iov, count) >= 0;
}
