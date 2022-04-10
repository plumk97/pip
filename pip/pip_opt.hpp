//
//  pip_define.h
//
//  Created by Plumk on 2021/3/11.
//

#ifndef pip_define_h
#define pip_define_h

#if DEBUG

#if PIP_IS_REMOTE_DEBUG
    #define PIP_DEBUG           1
#else
    #define PIP_DEBUG           0
#endif


#else
#define PIP_DEBUG           0
#endif

#define PIP_TCP_MSS         1460
#define PIP_TCP_WIND        65535
#define PIP_TCP_MAX_CONNS   65535

#endif /* pip_define_h */
