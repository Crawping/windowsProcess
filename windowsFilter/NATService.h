#pragma once

#include <map>
#include <mutex>
#include <stdint.h>
#include "ProtocolHeader.h"


const uint16_t kMaxAllowedPort = 0xFFFF;

struct IPV4Header;
struct TCPHeader;
struct UDPHeader;
struct ICMPHeader;
struct PseudoHeader;

typedef struct natKeyInfo {

	bool operator()(const struct natKeyInfo& src, const struct natKeyInfo& dst) const
	{
		bool returnVal = false;
		int32_t result = memcmp(&src, &dst, sizeof(struct natKeyInfo));

		if (result < 0)
		{
			returnVal = true;
		}
		else
		{
			returnVal = false;
		}

		return returnVal;
	}

	uint32_t src_address;
	uint32_t dst_address;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t protocol;

}NatKeyInfo;

//just for nat open p2p
struct sNatMapCmp
{
	bool operator() (const struct natKeyInfo& src, const struct natKeyInfo& dst) const
	{
		bool returnVal = false;

		int32_t result = (src.src_address + src.src_port + src.protocol) - (dst.src_address + dst.src_port + dst.protocol);

		if (result < 0)
		{
			returnVal = true;
		}
		else
		{
			returnVal = false;
		}

		return returnVal;
	}
};

struct dNatMapCmp
{
	bool operator()(const struct natKeyInfo& src, const struct natKeyInfo& dst) const
	{
		bool returnVal = false;
		int32_t result = (src.dst_address + src.dst_port + src.protocol) - (dst.dst_address + dst.dst_port + dst.protocol);

		if (result < 0)
		{
			returnVal = true;
		}
		else
		{
			returnVal = false;
		}

		return returnVal;
	}
};

/* NAT table entry*/
typedef struct natAddressInfo {

	natAddressInfo()
	{
		this->src_address = 0;
		this->dst_address = 0;
		this->dst_port = 0;
		this->src_port = 0;
		this->isPrintFlag = false;

		this->timestamp = ::GetTickCount();

		memset(&packageInfo, 0, sizeof(PACKET_S));
	}

	natAddressInfo(const NatKeyInfo &keyInfo)
	{
		this->src_address = keyInfo.src_address;
		this->dst_address = keyInfo.dst_address;
		this->dst_port = keyInfo.dst_port;
		this->src_port = keyInfo.src_port;

		this->timestamp = ::GetTickCount();
		this->isPrintFlag = false;

		memset(&packageInfo, 0, sizeof(PACKET_S));
	}

	void updateTime()
	{
		this->timestamp = ::GetTickCount();
	}

  uint32_t src_address;
  uint16_t src_port;
  uint32_t dst_address;
  uint32_t dst_port;
  // timestamp
  unsigned long timestamp;
  bool isPrintFlag;
  PACKET_S packageInfo;
} NATAddressInfo;

uint16_t GetChecksum(void* pseudo_header, uint16_t pseudo_header_len, void* packet_data, uint16_t packet_len);

class NATService {
public:
  VOID revertPackage(uint8_t* ip_packet, uint32_t length);
  bool ModifyUploadPacket(uint8_t* ip_packet, uint32_t length, PPACKET_S packageInfo);
  bool ModifyDnloadPacket(uint8_t* ip_packet, uint32_t length, PPACKET_S packageInfo);

  bool checkIpInNatList(uint8_t* ip_packet, uint32_t length);

  void SetGatewayIP(uint32_t gateway_ip) { gateway_ip_ = gateway_ip; }

  void Clear();
  ~NATService();
protected:
	void clearSnatMap();
	void clearDnatMap();
	void caclCheckSum(void* ip_packet, uint32_t length);
	VOID printNatInfo(const NatKeyInfo &key, NATAddressInfo &natAddress, bool isUpload = true);
	NatKeyInfo reverseNatKeyInfo(const NatKeyInfo &keyInfo, bool isIcmp = false);
	NatKeyInfo GetNatKeyFromIpTcpHeader(IPV4Header *ipHeader, TCPHeader *tcpHeader);
	NatKeyInfo GetNatKeyFromIpUdpHeader(IPV4Header *ipHeader, UDPHeader *udpHeader);
	NatKeyInfo GetNatKeyFromIpIcmpHeader(IPV4Header *ipHeader, ICMPHeader *icmpHeader);
	NATAddressInfo updateDnLoadMapInfo(const NatKeyInfo &keyInfo, const NATAddressInfo &dnatInfo, PPACKET_S packageInfo, bool isFind = false);
	NATAddressInfo updateUpLoadMapInfo(const NatKeyInfo &keyInfo, PPACKET_S packageInfo, uint32_t newSrcAddress, bool isIcmp = false);
private:

  std::mutex upLoadMutex;
  std::map<NatKeyInfo, NATAddressInfo, sNatMapCmp> snatMap;
  
  std::mutex dnLoadMutex;
  std::map<NatKeyInfo, NATAddressInfo, dNatMapCmp> dnatMap;

  uint32_t gateway_ip_;
};