//
//  pip_tcp_manager.h
//
//  Created by Plumk on 2023/5/19.
//  Copyright © 2023 Plumk. All rights reserved.
//

#ifndef pip_tcp_manager_h
#define pip_tcp_manager_h

#include <map>
#include <shared_mutex>
#include <functional>
#include <vector>

#include "../pip_type.h"
#include "pip_tcp.h"

class pip_tcp_manager {
    pip_tcp_manager() {}
    ~pip_tcp_manager() {}
    
    pip_tcp_manager(const pip_tcp_manager&) = delete;
    pip_tcp_manager operator=(const pip_tcp_manager&) = delete;
    
private:
    std::map<pip_tcp_key, std::shared_ptr<pip_tcp>> _tcps;
    std::mutex _lock;
    
public:
    static pip_tcp_manager & shared() {
        static pip_tcp_manager manager;
        return manager;
    }
    
    /// 不存在时加入并返回 tcp, 已存在 (并发创建) 时返回已有的连接
    std::shared_ptr<pip_tcp> add_tcp_if_absent(const pip_tcp_key & key, std::shared_ptr<pip_tcp> tcp) {
        std::lock_guard<std::mutex> guard(_lock);
        auto result = _tcps.emplace(key, tcp);
        return result.first->second;
    }
    
    std::shared_ptr<pip_tcp> fetch_tcp(const pip_tcp_key & key) {
        std::lock_guard<std::mutex> guard(_lock);
        auto it = _tcps.find(key);
        if (it != _tcps.end()) {
            return it->second;
        }
        
        return nullptr;
    }
    
    /// 只有当前登记的对象就是 tcp 时才移除, 避免误删同一四元组上的新连接
    void remove_tcp(const pip_tcp_key & key, const pip_tcp * tcp) {
        std::lock_guard<std::mutex> guard(_lock);
        auto it = _tcps.find(key);
        if (it != _tcps.end() && it->second.get() == tcp) {
            _tcps.erase(it);
        }
    }
    
    pip_uint32 size() {
        std::lock_guard<std::mutex> guard(_lock);
        return (pip_uint32)this->_tcps.size();
    }
    
    std::vector<std::shared_ptr<pip_tcp>> tcp_snapshot() {
        std::lock_guard<std::mutex> guard(_lock);
        std::vector<std::shared_ptr<pip_tcp>> snapshot;
        snapshot.reserve(_tcps.size());
        for (auto & kv : _tcps) {
            snapshot.push_back(kv.second);
        }
        return snapshot;
    }
};

#endif /* pip_tcp_manager_h */
