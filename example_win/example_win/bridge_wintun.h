#pragma once
#include "wintun.h"
#include <functional>
#include "../../pip/pip_buf.h"

class bridge_wintun
{

public:
	static bool init();
	static void deinit();

	static bool create_tun_interface(_In_z_ LPCWSTR name, _In_z_ LPCWSTR tunnel_type, _In_opt_ const GUID* requested_guid, _In_z_ const char * addr, UINT8 prefix_length);
	static void destroy_tun_interface();

	static void set_received_packet_callback(std::function<void(BYTE* packet, DWORD packet_size, bool is_stoped)> callback);
	static void send_packet(_In_ pip_buf * buf);
};

