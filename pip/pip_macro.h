//
//  pip_concurrency.hpp
//
//  Created by Plumk on 2023/5/21.
//  Copyright © 2023 Plumk. All rights reserved.
//

#ifndef pip_concurrency_hpp
#define pip_concurrency_hpp

// MARK: - PROPERTY
#define PIP_PROPERTY(type, name) \
private: \
type _##name; \
public: \
void set_##name(type value) { \
    this->_##name = value; \
} \
type name() { \
    return this->_##name; \
}

#define PIP_READONLY_PROPERTY(type, name) \
private: \
type _##name; \
void set_##name(type value) { \
    this->_##name = value; \
} \
public: \
type name() { \
    return this->_##name; \
}

#define PIP_PRIVATE_PROPERTY(type, name) \
private: \
type _##name; \
void set_##name(type value) { \
    this->_##name = value; \
} \
type name() { \
    return this->_##name; \
}


#endif /* pip_concurrency_hpp */
