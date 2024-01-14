
#include "bridge_wintun.h"
#include <winsock2.h>
#include <Windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <thread>
#include <WS2tcpip.h>

static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
static WINTUN_START_SESSION_FUNC* WintunStartSession;
static WINTUN_END_SESSION_FUNC* WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;

static bool IsRunning = false;

static HMODULE Wintun = nullptr;
static WINTUN_ADAPTER_HANDLE Adapter = nullptr;
static WINTUN_SESSION_HANDLE Session = nullptr;

static std::thread ReceivedThread;
static std::function<void(BYTE* packet, DWORD packet_size, bool is_stoped)> ReceivedPacketCallback = nullptr;


void func_received_thread()  {
    
    HANDLE WaitHandles[] = { WintunGetReadWaitEvent(Session) };
    
    while (IsRunning)
    {
        DWORD PacketSize;
        BYTE* Packet = WintunReceivePacket(Session, &PacketSize);

        if (Packet)
        {

            if (ReceivedPacketCallback) {
                ReceivedPacketCallback(Packet, PacketSize, false);
            }
            WintunReleaseReceivePacket(Session, Packet);
        }
        else
        {
            /**
            ERROR_HANDLE_EOF     Wintun adapter is terminating;
            ERROR_NO_MORE_ITEMS  Wintun buffer is exhausted;
            ERROR_INVALID_DATA   Wintun buffer is corrupt
             */

            DWORD LastError = GetLastError();
            switch (LastError) {
            case ERROR_NO_MORE_ITEMS: {
                WaitForMultipleObjects(_countof(WaitHandles), WaitHandles, FALSE, INFINITE);
                continue;
            }

            default:
                if (ReceivedPacketCallback) {
                    ReceivedPacketCallback(nullptr, 0, true);
                }
                break;
            }
        }
    }
}

bool bridge_wintun::init()
{

    Wintun =
        LoadLibraryExW(L"wintun.dll", NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun)
        return false;
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X(WintunCreateAdapter) || X(WintunCloseAdapter) || X(WintunOpenAdapter) || X(WintunGetAdapterLUID) ||
        X(WintunGetRunningDriverVersion) || X(WintunDeleteDriver) || X(WintunSetLogger) || X(WintunStartSession) ||
        X(WintunEndSession) || X(WintunGetReadWaitEvent) || X(WintunReceivePacket) || X(WintunReleaseReceivePacket) ||
        X(WintunAllocateSendPacket) || X(WintunSendPacket))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return false;
    }
    return true;
}

void bridge_wintun::deinit()
{
    FreeLibrary(Wintun);
}

bool bridge_wintun::create_tun_interface(_In_z_ LPCWSTR name, _In_z_ LPCWSTR tunnel_type, _In_opt_ const GUID* requested_guid, _In_z_ const char* addr, UINT8 prefix_length)
{
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    DWORD ret;

    Adapter = WintunCreateAdapter(name, tunnel_type, requested_guid);
    if (!Adapter) {
        goto failure;
    }

    

    
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(Adapter, &AddressRow.InterfaceLuid);
    
    AddressRow.DadState = IpDadStatePreferred;
    AddressRow.OnLinkPrefixLength = prefix_length;
    
    AddressRow.Address.Ipv4.sin_family = AF_INET;
    if (!inet_pton(AF_INET, addr, &AddressRow.Address.Ipv4.sin_addr)) {
        goto failure;
    }

   
    ret = CreateUnicastIpAddressEntry(&AddressRow);
    if (ret != ERROR_SUCCESS && ret != ERROR_OBJECT_ALREADY_EXISTS) {
        goto failure;
    }

    Session = WintunStartSession(Adapter, 0x400000);
    if (!Session) {
        goto failure;
    }

    IsRunning = true;
    ReceivedThread = std::thread(func_received_thread);

    return true;

failure:

    bridge_wintun::destroy_tun_interface();

    return false;
    
}

void bridge_wintun::destroy_tun_interface()
{
    IsRunning = false;

    if (ReceivedThread.joinable()) {
        ReceivedThread.join();
    }

    if (Session) {
        WintunEndSession(Session);
        Session = nullptr;
    }

    if (Adapter) {
        WintunCloseAdapter(Adapter);
        Adapter = nullptr;
    }

}

void bridge_wintun::set_received_packet_callback(std::function<void(BYTE* packet, DWORD packet_size, bool is_stoped)> callback)
{
    ReceivedPacketCallback = callback;
}

void bridge_wintun::send_packet(_In_ pip_buf* buf)
{
    BYTE* OutgoingPacket = WintunAllocateSendPacket(Session, buf->total_len());
    if (OutgoingPacket)
    {
        pip_buf* p = buf;
        int offset = 0;
        while (p) {
            memcpy(OutgoingPacket + offset, p->payload(), p->payload_len());
            offset += p->payload_len();
            p = p->next();
        }
       
        WintunSendPacket(Session, OutgoingPacket);
    }
}