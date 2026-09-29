//
//  log.hpp
//
//  Created by Plumk on 2026/9/30.
//  Copyright © 2026 Plumk. All rights reserved.
//

#ifndef log_hpp
#define log_hpp

#include <atomic>
#include <cstdio>
#include <ctime>

namespace logger {

inline std::atomic<bool> & verbose() {
    static std::atomic<bool> value{false};
    return value;
}

inline void timestamp(char * buf, size_t len) {
    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    strftime(buf, len, "%H:%M:%S", &tm_now);
}

} // namespace logger

#define LOG(fmt, ...) do { \
    char _ts[16]; logger::timestamp(_ts, sizeof(_ts)); \
    fprintf(stderr, "[%s] " fmt "\n", _ts, ##__VA_ARGS__); \
} while (0)

/// 仅在 -v 时输出
#define VLOG(fmt, ...) do { \
    if (logger::verbose().load()) { LOG(fmt, ##__VA_ARGS__); } \
} while (0)

#endif /* log_hpp */
