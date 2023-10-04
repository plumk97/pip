#include <iostream>
#include <thread>
#include "wintun.h"
#include "bridge_wintun.h"
#include "../../pip/pip.h"

#pragma comment(lib, "ws2_32.lib")

static HANDLE QuitEvent;
static bool IsRunning;

void read_thread(_In_ pip_tcp* tcp) {
    
    int fd = *((int*)tcp->arg());
    int maxlen = 65535 << tcp->opp_wind_shift();
    while (true)
    {
        uint8_t* buffer = (uint8_t*)malloc(maxlen);
        int len = recv(fd, (char *)buffer, maxlen, 0);
        std::cout << len << std::endl;
        if (len <= 0) {
            free(tcp->arg());
            tcp->set_arg(nullptr);
            free(buffer);
            tcp->close();
            break;
        }
        else {
            tcp->write(buffer, len, 0);
        }
        free(buffer);
    }
    
}


void _pip_tcp_connected_callback(pip_tcp* tcp) {
    std::thread thread(read_thread, tcp);
    thread.detach();

}

/// tcp���ܵ�����
void _pip_tcp_received_callback(pip_tcp* tcp, const void* buffer, pip_uint32 buffer_len) {

    if (tcp->arg()) {
        int fd = *((int*)tcp->arg());
        send(fd, (const char*)buffer, buffer_len, 0);
    }
    std::cout << "recv" << buffer_len << std::endl;
    /// ���ø÷������´���
    tcp->received(buffer_len);
}

void _pip_tcp_written_callback(pip_tcp* tcp, pip_uint32 writeen_len, bool has_push, bool is_drop) {
    if (tcp->arg() && (has_push || writeen_len == 0)) {

    }
}

void _pip_tcp_closed_callback(pip_tcp* tcp, void* arg) {
    if (arg) {
        int fd = *((int*)arg);
        closesocket(fd);
        free(arg);
    }
}

/// ���IP��
void _pip_netif_output_ip_data_callback(pip_netif* netif, pip_buf* buf) {
    bridge_wintun::send_packet(buf);
}

/// ���ܵ�TCP����
void _pip_netif_new_tcp_connect_callback(pip_netif* netif, pip_tcp* tcp, const void* take_data, pip_uint16 take_data_len) {
    std::cout << "tcp " << tcp->ip_header()->src_str << ":" << tcp->src_port() << "<->" << tcp->ip_header()->dst_str << ":" << tcp->dst_port() << std::endl;
    if (strcmp(tcp->ip_header()->dst_str, "1.1.1.1") != 0) {
        return;
    }

    /// ע��ص�
    tcp->connected_callback = _pip_tcp_connected_callback;
    tcp->received_callback = _pip_tcp_received_callback;
    tcp->written_callback = _pip_tcp_written_callback;
    tcp->closed_callback = _pip_tcp_closed_callback;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;

    int ret = 0;
    // - �� interface
    /*struct sockaddr_in bindAddr;
    bindAddr.sin_family = AF_INET;
    if (!inet_pton(AF_INET, "192.168.18.2", &bindAddr.sin_addr)) {
        closesocket(fd);
        return;
    }

    ret = bind(fd, (struct sockaddr*)&bindAddr, sizeof(bindAddr));
    if (ret != 0) {
        std::cout << "Failed to bind interface\n";
        closesocket(fd);
        return;
    }*/

    struct sockaddr_in servaddr;
    memset((char*)&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(tcp->dst_port());
    if (!inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr)) {
        closesocket(fd);
        return;
    }

    ret = connect(fd, (const struct sockaddr*)&servaddr, sizeof(struct sockaddr_in));
    if (ret == -1) {
        std::cout << GetLastError() << std::endl;
        tcp->close();
        closesocket(fd);
        return;
    }
    std::cout << ret << std::endl;
    void* arg = malloc(sizeof(int));
    memcpy(arg, &fd, sizeof(int));
    tcp->set_arg(arg);

    /// ֱ�ӻ�Ӧ����, ��û�����ӵ�Զ�˷�����
    tcp->connected(take_data);
}

/// ���ܵ�UDP��
void _pip_netif_received_udp_data_callback(pip_netif* netif, void* buffer, pip_uint16 buffer_len, const char* src_ip, pip_uint16 src_port, const char* dst_ip, pip_uint16 dst_port, pip_uint8 version) {

    if (strcmp(dst_ip, "1.1.1.1") != 0) {
        return;
    }
    std::cout << "udp " << dst_ip << std::endl;

    int ret = 0;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) return;

    // - ��interface
    struct sockaddr_in bindAddr;
    bindAddr.sin_family = AF_INET;
    if (!inet_pton(AF_INET, "192.168.18.2", &bindAddr.sin_addr)) {
        closesocket(fd);
        return;
    }

    ret = bind(fd, (struct sockaddr*)&bindAddr, sizeof(bindAddr));
    if (ret != 0) {
        std::cout << "Failed to bind interface\n";
        closesocket(fd);
        return;
    }

    // - ��Զ�˷�������
    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(dst_port);
    if (!inet_pton(AF_INET, "223.5.5.5", &servaddr.sin_addr)) {
        closesocket(fd);
        return;
    }
    

    ret = sendto(fd, (const char *)buffer, buffer_len, 0, (struct sockaddr*)&servaddr, sizeof(sockaddr_in));
    if (ret <= 0) {
        closesocket(fd);
        return;
    }

    // - ��������
    uint8_t* recv_buffer = (uint8_t*)malloc(65535);
    ret = recvfrom(fd, (char *)recv_buffer, 65535, 0, nullptr, nullptr);
    if (ret <= 0) {
        free(recv_buffer);
        closesocket(fd);
        return;
    }

    // - �����������pip���д��� ע���ַ��Դ����
    pip_udp::output(recv_buffer, ret, dst_ip, dst_port, src_ip, src_port);
    free(recv_buffer);
    closesocket(fd);
}

void printByteArray(const BYTE* data, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        std::cout << std::hex << static_cast<int>(data[i]) << " ";
    }
    std::cout << std::endl;
}


static void receive_packet_callback(BYTE * packet, DWORD packet_size, bool is_stoped) {
    if (is_stoped) {
        IsRunning = false;
        return;
    }
    
    if (packet[0] >> 4 == 6) {
        return;
    }
    //printByteArray(packet, packet_size);
    pip_netif::shared()->input(packet);
}


static BOOL WINAPI
CtrlHandler(_In_ DWORD CtrlType)
{
    switch (CtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        IsRunning = false;
        SetEvent(QuitEvent);
        return TRUE;
    }
    return FALSE;
}

DWORD main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        // ��ʼ��ʧ��
        return -1;
    }

    GUID ExampleGuid = { 0xdeadbabe, 0xcafe, 0xbeef, { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } };

    // ���ûص�
    pip_netif::shared()->received_udp_data_callback = _pip_netif_received_udp_data_callback;
    pip_netif::shared()->new_tcp_connect_callback = _pip_netif_new_tcp_connect_callback;
    pip_netif::shared()->output_ip_data_callback = _pip_netif_output_ip_data_callback;

    bridge_wintun::set_received_packet_callback(receive_packet_callback);

    // ��ʼ�� wintun
    if (!bridge_wintun::init())
    {
        std::cout << "Failed to initialize Wintun. " << GetLastError() << std::endl;
        return -1;
    }

    // ����ctrl-c�˳�
    DWORD LastError;
    HANDLE QuitEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!QuitEvent)
    {
        std::cout << "Failed to create event" << std::endl;
        LastError = GetLastError();
        goto quit;
    }

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        std::cout << "Failed to set console handler" << std::endl;
        LastError = GetLastError();
        goto quit;
    }

    // ���� tun
    if (!bridge_wintun::create_tun_interface(L"PIP", L"PIP", &ExampleGuid, "192.168.100.2", 24))
    {
        std::cout << "Failed to create adapter" << std::endl;
        LastError = GetLastError();
        goto quit;
    }

    
    IsRunning = true;

    // ���·��
    std::cout << "route add 1.1.1.1 mask 255.255.255.255 192.168.100.1 metric 1" << std::endl;
    WinExec("route add 1.1.1.1 mask 255.255.255.255 192.168.100.1 metric 1", 0);

    std::cout << "start" << std::endl;
    
    while (IsRunning)
    {
        pip_netif::shared()->timer_tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    LastError = ERROR_SUCCESS;
    std::cout << "end" << std::endl;


quit:
    // ɾ��·��
    std::cout << "route delete 1.1.1.1 mask 255.255.255.255 192.168.100.1" << std::endl;
    WinExec("route delete 1.1.1.1 mask 255.255.255.255 192.168.100.1", 0);

    // �����ݼ�
    if (QuitEvent) {
        SetConsoleCtrlHandler(CtrlHandler, FALSE);
        CloseHandle(QuitEvent);
    }

    // ����wintun
    bridge_wintun::destroy_tun_interface();
    bridge_wintun::deinit();

    // - 
    WSACleanup();

    

	return LastError;
}