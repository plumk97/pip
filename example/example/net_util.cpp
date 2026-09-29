//
//  net_util.cpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#include "net_util.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

std::string endpoint::str() const {
    char ip[INET6_ADDRSTRLEN] = {};
    unsigned short port = 0;
    if (addr.ss_family == AF_INET) {
        auto sin = (const struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        port = ntohs(sin->sin_port);
        return std::string(ip) + ":" + std::to_string(port);
    }
    
    auto sin6 = (const struct sockaddr_in6 *)&addr;
    inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
    port = ntohs(sin6->sin6_port);
    return "[" + std::string(ip) + "]:" + std::to_string(port);
}

bool resolve_target(const options & opts, const char * dst_ip, unsigned short dst_port, endpoint & out) {
    const char * ip = opts.redirect_ip.empty() ? dst_ip : opts.redirect_ip.c_str();
    
    out = endpoint();
    auto sin = (struct sockaddr_in *)&out.addr;
    if (inet_pton(AF_INET, ip, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(dst_port);
        sin->sin_len = sizeof(struct sockaddr_in);
        out.len = sizeof(struct sockaddr_in);
        return true;
    }
    
    auto sin6 = (struct sockaddr_in6 *)&out.addr;
    if (inet_pton(AF_INET6, ip, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(dst_port);
        sin6->sin6_len = sizeof(struct sockaddr_in6);
        out.len = sizeof(struct sockaddr_in6);
        return true;
    }
    
    return false;
}

int create_outbound_socket(const options & opts, int family, int type) {
    int fd = socket(family, type, 0);
    if (fd < 0) {
        return -1;
    }
    
    unsigned int index = opts.out_ifindex;
    int ret = family == AF_INET
        ? setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, sizeof(index))
        : setsockopt(fd, IPPROTO_IPV6, IPV6_BOUND_IF, &index, sizeof(index));
    if (ret != 0) {
        close(fd);
        return -1;
    }
    
    int on = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    return fd;
}

bool connect_with_timeout(int fd, const endpoint & ep, int timeout_ms) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    int ret = connect(fd, (const struct sockaddr *)&ep.addr, ep.len);
    if (ret != 0 && errno != EINPROGRESS) {
        return false;
    }
    
    if (ret != 0) {
        struct pollfd pfd = {fd, POLLOUT, 0};
        do {
            ret = poll(&pfd, 1, timeout_ms);
        } while (ret < 0 && errno == EINTR);
        
        if (ret <= 0) {
            errno = ret == 0 ? ETIMEDOUT : errno;
            return false;
        }
        
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err != 0) {
            errno = err;
            return false;
        }
    }
    
    fcntl(fd, F_SETFL, flags);
    return true;
}
