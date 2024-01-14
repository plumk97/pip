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
    
private:
    std::map<pip_uint32, pip_tcp *> _tcps;
    
public:
    
    pip_tcp * fetch_tcp(pip_uint32 iden, std::function<pip_tcp * ()> create) {
        if (_tcps.find(iden) != _tcps.end()) {
            return _tcps[iden];
        }
        
        if (this->_tcps.size() >= PIP_TCP_MAX_CONNS) {
            return nullptr;
        }
        
        pip_tcp * tcp = create();
        if (tcp) {
            _tcps[iden] = tcp;
        }
        return tcp;
    }
    
    void remove_tcp(pip_uint32 iden) {
        _tcps.erase(iden);
    }
    
    pip_uint32 size() {
        return (pip_uint32)this->_tcps.size();
    }
    
    std::map<pip_uint32, pip_tcp *> tcps() {
        return this->_tcps;
    }
};

#endif /* pip_tcp_manager_h */
