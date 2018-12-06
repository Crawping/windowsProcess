#include "NATService.h"
#include "protocolHeader.h"
#include <windows.h>
#include <algorithm>
#pragma comment(lib, "ws2_32.lib")


uint16_t GetChecksum(void* pseudo_header, uint16_t pseudo_header_len, void* packet_data, uint16_t packet_len) {
  register const uint16_t *data16 = reinterpret_cast<const uint16_t*>(pseudo_header);
  register size_t len16 = pseudo_header_len >> 1;
  register uint32_t sum = 0;

  // Pseudo header:
  for (size_t i = 0; i < len16; i++) {
    sum += static_cast<uint32_t>(data16[i]);
  }

  // Main data:
  data16 = reinterpret_cast<const uint16_t*>(packet_data);
  len16 = packet_len >> 1;
  for (size_t i = 0; i < len16; i++) {
    sum += static_cast<uint32_t>(data16[i]);
  }

  if (packet_len & 0x1) {
    const uint8_t *data8 = reinterpret_cast<const uint8_t*>(packet_data);
    sum += static_cast<uint16_t>(data8[packet_len - 1]);
  }

  sum = (sum & 0xFFFF) + (sum >> 16);
  sum += (sum >> 16);
  sum = ~sum;

  return static_cast<uint16_t>(sum);
}

NATAddressInfo NATService::updateDnLoadMapInfo(const NatKeyInfo &keyInfo, const NATAddressInfo &dnatInfo, PPACKET_S packageInfo, bool isFind)
{
	std::lock_guard<std::mutex> lock(dnLoadMutex);
	
	NATAddressInfo defaultdnatAddressInfo;

	NATAddressInfo dnatAddressInfo = dnatInfo;

	auto iter = dnatMap.find(keyInfo);
	if (dnatMap.end() == iter)
	{
		if (!isFind)
		{
			dnatAddressInfo.packageInfo = *packageInfo;
			dnatMap[keyInfo] = dnatAddressInfo;
		}
	}
	else
	{
		dnatMap[keyInfo].updateTime();

		defaultdnatAddressInfo = dnatMap[keyInfo];

		if (isFind)
		{
			*packageInfo = defaultdnatAddressInfo.packageInfo;
		}
	}

	return defaultdnatAddressInfo;
}

NATAddressInfo NATService::updateUpLoadMapInfo(const NatKeyInfo &keyInfo, PPACKET_S packageInfo, uint32_t newSrcAddress, bool isIcmp)
{
	std::lock_guard<std::mutex> lock(upLoadMutex);

	NatKeyInfo dnatKeyInfo = reverseNatKeyInfo(keyInfo, isIcmp);
	dnatKeyInfo.dst_address = newSrcAddress;

	NATAddressInfo snatAddressInfo(keyInfo);
	snatAddressInfo.src_address = newSrcAddress;
	snatAddressInfo.packageInfo = *packageInfo;

	NATAddressInfo dnatAddressInfo = reverseNatKeyInfo(keyInfo, isIcmp);

	auto iter = snatMap.find(keyInfo);
	if (snatMap.end() == iter)
	{
		snatMap[keyInfo] = snatAddressInfo;

		updateDnLoadMapInfo(dnatKeyInfo, dnatAddressInfo, packageInfo);
	}
	else
	{
		snatAddressInfo = snatMap[keyInfo];

		updateDnLoadMapInfo(dnatKeyInfo, dnatAddressInfo, packageInfo);
	}

	return snatAddressInfo;
}

NatKeyInfo NATService::reverseNatKeyInfo(const NatKeyInfo &keyInfo, bool isIcmp)
{
	NatKeyInfo newKeyInfo = keyInfo;

	newKeyInfo.src_address = keyInfo.dst_address;
	newKeyInfo.dst_address = keyInfo.src_address;

	if (!isIcmp)
	{
		newKeyInfo.dst_port = keyInfo.src_port;
		newKeyInfo.src_port = keyInfo.dst_port;
	}

	return newKeyInfo;
}

bool NATService::ModifyDnloadPacket(uint8_t* ip_packet, uint32_t length, PPACKET_S packageInfo)
{
	bool result = false;

	if (nullptr == ip_packet || 0 == length || nullptr == packageInfo)
	{
		printf("ip package is %p or length %u", ip_packet, length);

		return result;
	}

	NATAddressInfo dnatAddressInfo;

	IPV4Header* ip_v4_header = reinterpret_cast<IPV4Header*>(ip_packet);

	memset(packageInfo, 0, sizeof(PACKET_S));

	switch (ip_v4_header->protocol)
	{
		case IPPROTO_TCP:
		{
			TCPHeader* tcp_header = reinterpret_cast<TCPHeader*>(ip_v4_header->data());

			NatKeyInfo keyInfo = GetNatKeyFromIpTcpHeader(ip_v4_header, tcp_header);

			dnatAddressInfo = updateDnLoadMapInfo(keyInfo, dnatAddressInfo, packageInfo, true);
			if (dnatAddressInfo.src_address != 0)
			{
				ip_v4_header->src_address = dnatAddressInfo.src_address;
				ip_v4_header->dest_address = dnatAddressInfo.dst_address;
				tcp_header->src_port = dnatAddressInfo.src_port;
				tcp_header->dst_port = dnatAddressInfo.dst_port;

				caclCheckSum(ip_packet, length);

				result = true;
			}
			else
			{
				result = false;
			}

			break;
		}

		case IPPROTO_UDP:
		{
			UDPHeader* udp_header = reinterpret_cast<UDPHeader*>(ip_v4_header->data());

			NatKeyInfo keyInfo = GetNatKeyFromIpUdpHeader(ip_v4_header, udp_header);

			dnatAddressInfo = updateDnLoadMapInfo(keyInfo, dnatAddressInfo, packageInfo, true);
			if (dnatAddressInfo.src_address != 0)
			{
				ip_v4_header->src_address = dnatAddressInfo.src_address;
				ip_v4_header->dest_address = dnatAddressInfo.dst_address;
				udp_header->src_port = dnatAddressInfo.src_port;
				udp_header->dst_port = dnatAddressInfo.dst_port;

				caclCheckSum(ip_packet, length);

				result = true;
			}
			else
			{
				result = false;
			}

			break;
		}

		case IPPROTO_ICMP:
		{
			ICMPHeader* icmp_header = reinterpret_cast<ICMPHeader*>(ip_v4_header->data());

			NatKeyInfo keyInfo = GetNatKeyFromIpIcmpHeader(ip_v4_header, icmp_header);

			dnatAddressInfo = updateDnLoadMapInfo(keyInfo, dnatAddressInfo, packageInfo, true);
			if (dnatAddressInfo.src_address != 0)
			{
				ip_v4_header->src_address = dnatAddressInfo.src_address;
				ip_v4_header->dest_address = dnatAddressInfo.dst_address;
				icmp_header->identify = dnatAddressInfo.dst_port;

				caclCheckSum(ip_packet, length);

				result = true;
			}
			else
			{
				result = false;
			}

			break;
		}
	}

	return result;
}


VOID NATService::revertPackage(uint8_t* ip_packet, uint32_t length)
{
	if (nullptr == ip_packet || 0 == length)
	{
		printf("ip package is %p or length %u", ip_packet, length);

		return ;
	}

	IPV4Header* ip_v4_header = reinterpret_cast<IPV4Header*>(ip_packet);

	std::swap(ip_v4_header->src_address, ip_v4_header->dest_address);

	switch (ip_v4_header->protocol)
	{
		case IPPROTO_TCP:
		{
			TCPHeader* tcp_header = reinterpret_cast<TCPHeader*>(ip_v4_header->data());
			
			std::swap(tcp_header->dst_port, tcp_header->src_port);

			caclCheckSum(ip_packet, length);


			break;
		}

		case IPPROTO_UDP:
		{
			UDPHeader* udp_header = reinterpret_cast<UDPHeader*>(ip_v4_header->data());

			NatKeyInfo keyInfo = GetNatKeyFromIpUdpHeader(ip_v4_header, udp_header);

			std::swap(udp_header->dst_port, udp_header->src_port);

			caclCheckSum(ip_packet, length);


			break;
		}

		case IPPROTO_ICMP:
		{
			ICMPHeader* icmp_header = reinterpret_cast<ICMPHeader*>(ip_v4_header->data());

			caclCheckSum(ip_packet, length);


			break;
		}
	}

}

bool NATService::ModifyUploadPacket(uint8_t* ip_packet, uint32_t length, PPACKET_S packageInfo)
{
	bool result = false;

	if (nullptr == ip_packet || 0 == length || nullptr == packageInfo)
	{
		printf("ip package is %p or length %u", ip_packet, length);

		return false;
	}

	IPV4Header* ip_v4_header = reinterpret_cast<IPV4Header*>(ip_packet);

	switch (ip_v4_header->protocol)
	{
		case IPPROTO_TCP:
		{
			TCPHeader* tcp_header = reinterpret_cast<TCPHeader*>(ip_v4_header->data());
			
			NatKeyInfo keyInfo = GetNatKeyFromIpTcpHeader(ip_v4_header, tcp_header);

			updateUpLoadMapInfo(keyInfo, packageInfo, gateway_ip_);

			ip_v4_header->src_address = gateway_ip_;

			caclCheckSum(ip_packet, length);

			result = true;

			break;
		}

		case IPPROTO_UDP:
		{
			UDPHeader* udp_header = reinterpret_cast<UDPHeader*>(ip_v4_header->data());

			NatKeyInfo keyInfo = GetNatKeyFromIpUdpHeader(ip_v4_header, udp_header);

			updateUpLoadMapInfo(keyInfo, packageInfo, gateway_ip_);

			ip_v4_header->src_address = gateway_ip_;

			caclCheckSum(ip_packet, length);

			result = true;
			
			break;
		}

		case IPPROTO_ICMP:
		{
			ICMPHeader* icmp_header = reinterpret_cast<ICMPHeader*>(ip_v4_header->data());

			NatKeyInfo keyInfo = GetNatKeyFromIpIcmpHeader(ip_v4_header, icmp_header);

			updateUpLoadMapInfo(keyInfo, packageInfo, gateway_ip_, true);

			ip_v4_header->src_address = gateway_ip_;

			caclCheckSum(ip_packet, length);

			result = true;

			break;
		}
	}

	return result;
}

NatKeyInfo NATService::GetNatKeyFromIpTcpHeader(IPV4Header *ipHeader, TCPHeader *tcpHeader)
{
	NatKeyInfo natInfo = { 0 };

	natInfo.src_address = ipHeader->src_address;
	natInfo.dst_address = ipHeader->dest_address;
	natInfo.src_port = tcpHeader->src_port;
	natInfo.dst_port = tcpHeader->dst_port;

	return natInfo;
}

NatKeyInfo NATService::GetNatKeyFromIpUdpHeader(IPV4Header *ipHeader, UDPHeader *udpHeader)
{
	NatKeyInfo natInfo = { 0 };

	natInfo.src_address = ipHeader->src_address;
	natInfo.dst_address = ipHeader->dest_address;
	natInfo.src_port = udpHeader->src_port;
	natInfo.dst_port = udpHeader->dst_port;

	return natInfo;
}

NatKeyInfo NATService::GetNatKeyFromIpIcmpHeader(IPV4Header *ipHeader, ICMPHeader *icmpHeader)
{
	NatKeyInfo natInfo = { 0 };

	natInfo.src_address = ipHeader->src_address;
	natInfo.dst_address = ipHeader->dest_address;
	natInfo.src_port = 0;
	natInfo.dst_port = icmpHeader->identify;

	return natInfo;
}

void NATService::caclCheckSum(void* ip_packet, uint32_t length) {

  if (ip_packet == nullptr) {
    return;
  }

  IPV4Header* ip_v4_header = reinterpret_cast<IPV4Header *>(ip_packet);

  bool packet_altered = false;
  switch (ip_v4_header->protocol) {
  case IPPROTO_TCP: {
    packet_altered = true;
    TCPHeader* tcp_header = reinterpret_cast<TCPHeader*>(ip_v4_header->data());

    PseudoHeader pseudo_header = ip_v4_header->CreatePseuoHeader();

    tcp_header->checksum = 0;
    tcp_header->checksum = GetChecksum(&pseudo_header, sizeof(pseudo_header), tcp_header, ip_v4_header->data_length());
    break;
  }

  case IPPROTO_UDP: {
    packet_altered = true;
    UDPHeader* udp_header = reinterpret_cast<UDPHeader*>(ip_v4_header->data());
    PseudoHeader pseudo_header = ip_v4_header->CreatePseuoHeader();

    udp_header->checksum = 0;
    udp_header->checksum = GetChecksum(&pseudo_header, sizeof(pseudo_header), udp_header, ip_v4_header->data_length());
    break;
  }

  case IPPROTO_ICMP: {
    packet_altered = true;
    ICMPHeader* icmp_header = reinterpret_cast<ICMPHeader*>(ip_v4_header->data());

    icmp_header->checksum = 0;
    icmp_header->checksum = GetChecksum(NULL, 0, icmp_header, ip_v4_header->data_length());
    break;
  }
  default:
    break;
  }

  ip_v4_header->checksum = 0;
  ip_v4_header->checksum = GetChecksum(NULL, 0, ip_packet, ip_v4_header->header_length * sizeof(uint32_t));

}

void NATService::clearSnatMap()
{
	std::lock_guard<std::mutex> lock(upLoadMutex);

	snatMap.clear();
}

void NATService::clearDnatMap()
{
	std::lock_guard<std::mutex> lock(dnLoadMutex);

	dnatMap.clear();
}

void NATService::Clear() {
	clearSnatMap();
	clearDnatMap();
}

NATService::~NATService()
{
	Clear();
}
