# pip

一个内存使用极少的轻量级的线程安全的TCP/IP协议栈, 当前支持IP, IPv6, ICMP, TCP, UDP.

支持macOS、iOS、Windows平台

## 注意
1. MTU默认为9000
2. TCP重传超时从1秒开始每次翻倍(最大4秒), 重传5次仍未确认则发送RST断开; 收到3个重复ACK时快速重传
3. 自身`window`固定为65535; 对方SYN携带window scale选项时`wind_shift`为8, 否则不缩放
4. TCP不支持半关闭: 收到对方FIN后会立即回复FIN, 此后`write`始终返回0, 尚未写入协议栈的数据将无法发送(已写入的数据会继续发送直到被确认). 上层不会收到单独的EOF通知, 只会在对方确认FIN后(或20秒超时后)收到`closed`回调. 因此先`shutdown(SHUT_WR)`再等待响应的客户端会丢失响应数据
5. `closed`回调只有在调用过`set_arg`且`arg`不为空时才会触发; 主动调用`close()`/`reset()`不会触发`closed`回调
6. 回调线程: 同一个TCP连接的回调按顺序串行执行, 不会并发, 但可能运行在调用`input`的线程或内部定时器线程上. 回调中可以调用该连接的接口(`write`/`received`/`close`等). 其它线程调用`close()`时, 正在执行中的回调仍会执行完, 之后不再触发新的回调
7. `received`回调的数据、`output_ip_data_callback`的buf都只在回调期间有效, 需要异步使用时请在回调内复制
8. TCP发送按对方通告窗口连续发送, `write`返回0表示对方窗口已满, 等待`written`回调后继续写入. 未实现拥塞控制, 适用于对端为本机协议栈(如utun/wintun)的场景, 不适合直接用于有丢包的真实链路

## 性能测试

**测试平台**

- OS: macOS 27.0
- CPU: Apple M2

**测试流程**

1. 开启iperf3服务端
2. 建立utun network interface, 设置MTU为9000
4. 开启iperf3客户端并指定地址为192.168.33.2
5. 重定向192.168.33.2到127.0.0.1以连接到iperf3服务端

**数据流向示意**

`本机iperf3客户端<->pip<->tcp socket<->本机iperf3服务端`

**上传测试**
```
~ iperf3 -c 192.168.33.2
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  6.15 GBytes  5.28 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  6.13 GBytes  5.27 Gbits/sec                  receiver
```

**下载测试**
```
~ iperf3 -c 192.168.33.2 -R
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  14.1 GBytes  12.1 Gbits/sec    1             sender
[  5]   0.00-10.00  sec  14.1 GBytes  12.1 Gbits/sec                  receiver

~ iperf3 -c 192.168.33.2 -R -P 5
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-10.00  sec  3.97 GBytes  3.41 Gbits/sec    0             sender
[  5]   0.00-10.00  sec  3.97 GBytes  3.41 Gbits/sec                  receiver
[  7]   0.00-10.00  sec  3.99 GBytes  3.43 Gbits/sec    0             sender
[  7]   0.00-10.00  sec  3.98 GBytes  3.42 Gbits/sec                  receiver
[  9]   0.00-10.00  sec  3.99 GBytes  3.43 Gbits/sec    0             sender
[  9]   0.00-10.00  sec  3.98 GBytes  3.42 Gbits/sec                  receiver
[ 11]   0.00-10.00  sec  3.93 GBytes  3.37 Gbits/sec    0             sender
[ 11]   0.00-10.00  sec  3.92 GBytes  3.36 Gbits/sec                  receiver
[ 13]   0.00-10.00  sec  3.91 GBytes  3.36 Gbits/sec    0             sender
[ 13]   0.00-10.00  sec  3.90 GBytes  3.35 Gbits/sec                  receiver
[SUM]   0.00-10.00  sec  19.8 GBytes  17.0 Gbits/sec    0             sender
[SUM]   0.00-10.00  sec  19.7 GBytes  17.0 Gbits/sec                  receiver
```

## Example

example 为 macOS 命令行程序, 使用 Xcode 打开 `example/example.xcodeproj` 编译, 需要 root 权限运行.

| 文件 | 说明 |
| --- | --- |
| `utun` | 创建 utun 网卡, 读写 IP 包 |
| `tcp_proxy` | TCP 连接转发, 异步连接远端, 支持背压 |
| `udp_proxy` | UDP 会话转发, 空闲 60 秒回收 |
| `icmp_echo` | 直接应答 ping |
| `options` | 命令行参数 |

```
# iperf3 测试: 连接 192.168.33.2 的流量被转发到 127.0.0.1 同端口
iperf3 -s
sudo ./example
iperf3 -c 192.168.33.2
ping 192.168.33.2

# 透明代理: 发往 1.1.1.1 的流量经 pip 处理后从 en0 连接原目标
sudo ./example --route 1.1.1.1/32 --redirect none --iface en0 -v
```

`./example -h` 查看全部参数. 出站 socket 会绑定 `--iface` 指定的网卡, 否则流量会被路由回 utun 形成环路, 例如转发到 127.0.0.1 需要绑定 lo0.
