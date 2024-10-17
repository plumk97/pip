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

#include "../pip_type.h"

class pip_tcp;
class pip_tcp_manager {
    pip_tcp_manager() {}
    ~pip_tcp_manager() {}
    
    pip_tcp_manager(const pip_tcp_manager&) = delete;
    pip_tcp_manager operator=(const pip_tcp_manager&) = delete;
    
private:
    std::map<pip_uint32, std::shared_ptr<pip_tcp>> _tcps;
    std::mutex _lock;
    
public:
    static pip_tcp_manager & shared() {
        static pip_tcp_manager manager;
        return manager;
    }
    
    void add_tcp(pip_uint32 iden, std::shared_ptr<pip_tcp> tcp) {
        std::lock_guard<std::mutex> guard(_lock);
        _tcps[iden] = tcp;
    }
    
    std::shared_ptr<pip_tcp> fetch_tcp(pip_uint32 iden) {
        std::lock_guard<std::mutex> guard(_lock);
        if (_tcps.find(iden) != _tcps.end()) {
            return _tcps[iden];
        }
        
        return nullptr;
    }
    
    void remove_tcp(pip_uint32 iden) {
        std::lock_guard<std::mutex> guard(_lock);
        _tcps.erase(iden);
    }
    
    pip_uint32 size() {
        std::lock_guard<std::mutex> guard(_lock);
        return (pip_uint32)this->_tcps.size();
    }
    
    const std::map<pip_uint32, std::shared_ptr<pip_tcp>> & tcps() {
        std::lock_guard<std::mutex> guard(_lock);
        return _tcps;
    }
};

#endif /* pip_tcp_manager_h */
