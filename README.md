# pip

一个内存使用极少的轻量级的线程安全的TCP/IP协议栈, 当前支持IP, IPv6, ICMP, TCP, UDP.

支持macOS、iOS、Windows平台

## 注意
1. MTU默认为9000
2. TCP每个数据包超时时间为2秒, 重传2次
3. 自身window固定为65535, 对方window兼容 window scaling

## 性能测试

**测试平台**

- OS: macOS 13.5.1
- CPU: Apple M2

**测试流程**

1. 开启iperf3服务端
2. 建立utun network interface, 设置MTU为9000
3. 路由1.1.1.1到该utun interface
4. 开启iperf3客户端并指定地址为1.1.1.1
5. 重定向1.1.1.1到127.0.0.1以连接到iperf3服务端

**数据流向示意**

`本机iperf3客户端<->pip<->tcp socket<->本机iperf3服务端`

**上传测试**
```
~ iperf3 -c 1.1.1.1
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  8.82 GBytes  7.58 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  8.82 GBytes  7.58 Gbits/sec                  receiver
```

**下载测试**
```
~ iperf3 -c 1.1.1.1 -R
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  7.52 GBytes  6.46 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  7.45 GBytes  6.40 Gbits/sec                  receiver
```

## Example

example工程使用xcode打开运行. 该工程展示了以下操作
1. tcp连接转发
2. udp连接转发

注意转发需要根据地址指定对应的`network interface`否则将无法连接, 例如127.0.0.1对应的lo0.
