//
//  pip_queue.hpp
//
//  Created by Plumk on 2021/3/17.
//

#ifndef pip_queue_hpp
#define pip_queue_hpp

#include <stdio.h>

template <class T>
class pip_queue_node {
    
public:
    T value;
    pip_queue_node *next;
};

template <class T>
class pip_queue {
    
public:
    pip_queue() {
        this->_size = 0;
        this->_head = NULL;
        this->_foot = NULL;
    };
    
    ~pip_queue() {
    };
    
    
    T front() {
        if (this->_size > 0) {
            return this->_head->value;
        }
        
        return NULL;
    };
    
    void push(T obj) {
        pip_queue_node<T> * node = new pip_queue_node<T>;
        node->value = obj;
        node->next = NULL;
        
        if (this->_head == NULL) {
            this->_head = node;
        }
        
        if (this->_foot == NULL) {
            this->_foot = node;
        } else {
            this->_foot->next = node;
            this->_foot = node;
        }
        
        this->_size += 1;
    };
    
    void pop() {
        if (this->_size > 0) {
            pip_queue_node<T> * node = this->_head->next;
            
            if (this->_head == this->_foot) {
                
                delete this->_head;
                this->_head = NULL;
                this->_foot = NULL;
                
            } else {
                
                delete this->_head;
                this->_head = NULL;
            }
            
            this->_head = node;
            this->_size -= 1;

            if (this->_size <= 0) {
                this->_head = NULL;
                this->_foot = NULL;
            }
        }
    };
    
    bool empty() {
        return this->size() <= 0;
    };
    
    int size() {
        return this->_size;
    }
    
private:
    int _size;
    pip_queue_node<T> * _head;
    pip_queue_node<T> * _foot;
};

#endif /* pip_queue_hpp */
