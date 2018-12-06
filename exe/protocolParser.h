#ifndef PROTOCOLPARSE_H
#define PROTOCOLPARSE_H

#include <string>
#include  "protocolHeader.h"

class protocolParse
{
public:
	protocolParse(PVOID buffer, UINT64 length);
	void parseProtocol();
	void printfProtocol();
	void resetBuffer(PVOID buffer, UINT64 length);
	void calcPackageCheckSum();
	PCHAR getPackageBuffer();
	UINT32 getPackageLength();
	~protocolParse();
protected:
	void parseIpHeader();
	void printIpHeader();
	void calcIpCheckSum();
	void parseTcpHeader();
	void printTcpHeader();
	void caclTcpCheckSum();
	void parseUdpHeader();
	void printUdpHeader();
	void caclUdpCheckSum();
	void parseIcmpHeader();
	void printIcmpHeader();
	void caclIcmpCheckSum();
	UINT32 getProtocolType();
	std::string ip2String(UINT32 ipAddress);
private:
	static PCHAR m_buffer;
	UINT64 m_length;
	UINT64 m_currentOffset;
	IPV4Header m_ipheader;
	TCPHeader m_tcpHeader;
	UDPHeader m_udpHeader;
	ICMPHeader m_icmpHeader;
};

#endif