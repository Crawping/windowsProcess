#include <iostream>
#include <windows.h>
#include "protocolParser.h"
#include "NATService.h"

PCHAR protocolParse::m_buffer = new CHAR[3000];

protocolParse::protocolParse(PVOID buffer, UINT64 length) : m_length(length), m_currentOffset(0)
{
	memcpy(m_buffer, buffer, length);
}

protocolParse::~protocolParse()
{
	;
}

void protocolParse::resetBuffer(PVOID buffer, UINT64 length)
{
	m_length = length;
	memcpy(m_buffer, buffer, length);
}

PCHAR protocolParse::getPackageBuffer()
{
	return m_buffer;
}

UINT32 protocolParse::getPackageLength()
{
	return m_length;
}

void protocolParse::parseProtocol()
{
	m_currentOffset = 0;

	parseIpHeader();
	
	switch (getProtocolType())
	{
		case IPPROTO_UDP:
		{
			parseUdpHeader();
			break;
		}

		case IPPROTO_TCP:
		{
			parseTcpHeader();

			break;
		}

		case IPPROTO_ICMP:
		{
			parseIcmpHeader();

			break;
		}
		default:
		{
			std::cerr << "unrecongnise protocol type" << getProtocolType() << std::endl;
		}
	};
}

void protocolParse::calcPackageCheckSum()
{
	calcIpCheckSum();

	switch (getProtocolType())
	{
		case IPPROTO_UDP:
		{
			caclUdpCheckSum();
			break;
		}

		case IPPROTO_TCP:
		{
			caclTcpCheckSum();

			break;
		}

		case IPPROTO_ICMP:
		{
			caclIcmpCheckSum();

			break;
		}
		default:
		{
			std::cerr << "unrecongnise protocol type" << getProtocolType() << std::endl;
		}
	};
}

void protocolParse::printfProtocol()
{
	printIpHeader();

	switch (getProtocolType())
	{
	case IPPROTO_UDP:
	{
		printUdpHeader();
		break;
	}

	case IPPROTO_TCP:
	{
		printTcpHeader();

		break;
	}

	case IPPROTO_ICMP:
	{
		printIcmpHeader();

		break;
	}
	default:
	{
		std::cerr << "unrecongnise protocol type" << getProtocolType() << std::endl;
	}
	};
}

UINT32 protocolParse::getProtocolType()
{
	return m_ipheader.protocol;
}

void protocolParse::calcIpCheckSum()
{
	if (m_length <= sizeof(IPV4Header))
	{
		std::cerr << "package length is not bigger than ip header length ,real length" << m_length << std::endl;
	}

	IPV4Header *ipv4Header = (IPV4Header *)(m_buffer);
	
	ipv4Header->checksum = 0;

	uint16_t checksum = GetChecksum(NULL, 0, ipv4Header, ipv4Header->header_length << 2);
	ipv4Header->checksum = checksum;

}

void protocolParse::caclTcpCheckSum()
{
	IPV4Header *ipv4Header = (IPV4Header *)(m_buffer);

	PseudoHeader pseudo_header = ipv4Header->CreatePseuoHeader();

	TCPHeader *tcpHeader = (TCPHeader *)(m_buffer + (ipv4Header->header_length << 2));

	tcpHeader->checksum = 0;

	uint16_t checksum = GetChecksum(&pseudo_header, sizeof(pseudo_header), tcpHeader, ipv4Header->data_length());

	tcpHeader->checksum = checksum;

	return;
}

void protocolParse::caclUdpCheckSum()
{
	IPV4Header *ipv4Header = (IPV4Header *)(m_buffer);

	PseudoHeader pseudo_header = ipv4Header->CreatePseuoHeader();

	UDPHeader *udpHeader = (UDPHeader *)(m_buffer + (ipv4Header->header_length << 2));

	udpHeader->checksum = 0;

	uint16_t checksum = GetChecksum(&pseudo_header, sizeof(pseudo_header), udpHeader, ipv4Header->data_length());

	udpHeader->checksum = checksum;

	return;
}

void protocolParse::caclIcmpCheckSum()
{
	IPV4Header *ipv4Header = (IPV4Header *)(m_buffer);

	PseudoHeader pseudo_header = ipv4Header->CreatePseuoHeader();

	ICMPHeader *icmpHeader = (ICMPHeader *)(m_buffer + (ipv4Header->header_length << 2));

	icmpHeader->checksum = 0;

	uint16_t checksum = GetChecksum(NULL, 0, icmpHeader, ipv4Header->data_length());
	
	icmpHeader->checksum = checksum;

	return;
}

void protocolParse::parseIpHeader()
{
	if (m_length <= sizeof(IPV4Header))
	{
		std::cerr << "package length is not bigger than ip header length ,real length" << m_length << std::endl;
	}

	m_ipheader = *((IPV4Header *)(m_buffer + m_currentOffset));

	m_ipheader.length = ntohs(m_ipheader.length);
	m_ipheader.id					= ntohs(m_ipheader.id);
	m_ipheader.frag_off0		= ntohs(m_ipheader.frag_off0);
	m_ipheader.checksum		= m_ipheader.checksum;
	m_currentOffset += m_ipheader.header_length * sizeof(UINT32);

}

void protocolParse::printIpHeader()
{
	std::cout << "===========ip protocol header begin============" << std::endl;
	std::cout << "src address :" << ip2String(m_ipheader.src_address) << std::endl;
	std::cout << "dst address :" << ip2String(m_ipheader.dest_address) << std::endl;
	std::cout << "header length:" << m_ipheader.header_length * sizeof(UINT32) << std::endl;
	std::cout << "payload length:" << m_ipheader.length - m_ipheader.header_length * sizeof(UINT32) << std::endl;
	std::cout << "ip protocol:" << (UINT32)m_ipheader.protocol << std::endl;
	std::cout << "ip version:" << (UINT32)m_ipheader.version << std::endl;
	std::cout << "ip ttl:" << (UINT32)m_ipheader.ttl << std::endl;
	std::cout << "ip tos:" << (UINT32)m_ipheader.tos << std::endl;
	std::cout << "ip fragement offset:" << m_ipheader.frag_off0 << std::endl;
	std::cout << "ip checksum:" << m_ipheader.checksum << std::endl;
	std::cout << "===================end=================" << std::endl;
}

void protocolParse::printTcpHeader()
{
	std::cout << "===========tcp protocol header begin============" << std::endl;
	std::cout << "tcp ack number:" << m_tcpHeader.ack_num << std::endl;
	std::cout << "tcp seq number:" << m_tcpHeader.seq_num<< std::endl;
	std::cout << "tcp dest port:" << m_tcpHeader.dst_port<< std::endl;
	std::cout << "tcp src port:" << m_tcpHeader.src_port << std::endl;
	std::cout << "tcp header length:" << m_tcpHeader.header_length * sizeof(UINT32)<< std::endl;
	std::cout << "tcp is fin:" << m_tcpHeader.fin << std::endl;
	std::cout << "tcp is syn:" << m_tcpHeader.syn << std::endl;
	std::cout << "tcp is rst:" << m_tcpHeader.rst << std::endl;
	std::cout << "tcp is psh:" << m_tcpHeader.psh << std::endl;
	std::cout << "tcp is ack:" << m_tcpHeader.ack << std::endl;
	std::cout << "tcp is urg:" << m_tcpHeader.urg << std::endl;
	std::cout << "tcp window length:" << m_tcpHeader.window << std::endl;
	std::cout << "tcp checksum:" << m_tcpHeader.checksum << std::endl;
	std::cout << "===================end=================" << std::endl;
}

void protocolParse::printUdpHeader()
{
	std::cout << "===========udp protocol header begin============" << std::endl;
	std::cout << "udp total length:" << m_udpHeader.length << std::endl;
	std::cout << "udp checksum:" << m_udpHeader.checksum << std::endl;
	std::cout << "udp src port:" << m_udpHeader.src_port << std::endl;
	std::cout << "udp dest port:" << m_udpHeader.dst_port << std::endl;
	std::cout << "===================end=================" << std::endl;
}

void protocolParse::printIcmpHeader()
{
	std::cout << "===========icmp protocol header begin============" << std::endl;
	std::cout << "icmp type:" << (UINT32)m_icmpHeader.icmp_type << std::endl;
	std::cout << "icmp code:" << (UINT32)m_icmpHeader.code << std::endl;
	std::cout << "icmp checksum:" << m_icmpHeader.checksum << std::endl;
	std::cout << "icmp identify:" << m_icmpHeader.identify << std::endl;
	std::cout << "icmp sequence_number:" << m_icmpHeader.sequence_number << std::endl;
	std::cout << "===================end=================" << std::endl;
}

std::string protocolParse::ip2String(UINT32 ipAddress)
{
	IN_ADDR address;
	
	address.s_addr = ipAddress;

	std::string strIpAddress = inet_ntoa(address);

	return strIpAddress;
}

void protocolParse::parseTcpHeader()
{
	if (m_length < (sizeof(TCPHeader) + m_currentOffset))
	{
		std::cerr << "package length is not bigger than tcp header length ,real length" << m_length << std::endl;

		return;
	}

	m_tcpHeader = *((TCPHeader *)(m_buffer + m_currentOffset));

	m_tcpHeader.ack				= ntohs(m_tcpHeader.ack);
	m_tcpHeader.ack_num		= ntohl(m_tcpHeader.ack_num);
	m_tcpHeader.dst_port		= ntohs(m_tcpHeader.dst_port);
	m_tcpHeader.src_port		= ntohs(m_tcpHeader.src_port);
	m_tcpHeader.urg_ptr		= ntohs(m_tcpHeader.urg_ptr);
	m_tcpHeader.window		= ntohs(m_tcpHeader.window);

	m_currentOffset += m_tcpHeader.header_length * sizeof(UINT32);
}

void protocolParse::parseUdpHeader()
{
	if (m_length < (sizeof(UDPHeader) + m_currentOffset))
	{
		std::cerr << "package length is not bigger than udp header length ,real length" << m_length << std::endl;

		return;
	}

	m_udpHeader = *((UDPHeader *)(m_buffer + m_currentOffset));

	m_udpHeader.dst_port = ntohs(m_udpHeader.dst_port);
	m_udpHeader.src_port = ntohs(m_udpHeader.src_port);
	m_udpHeader.length   = ntohs(m_udpHeader.length);

	m_currentOffset += sizeof(UDPHeader);
}

void protocolParse::parseIcmpHeader()
{
	if (m_length < (sizeof(ICMPHeader) + m_currentOffset))
	{
		std::cerr << "package length is not bigger than icmp header length ,real length" << m_length << std::endl;

		return;
	}

	m_icmpHeader = *((ICMPHeader *)(m_buffer + m_currentOffset));

	m_icmpHeader.identify = ntohs(m_icmpHeader.identify);
	m_icmpHeader.sequence_number = ntohs(m_icmpHeader.sequence_number);
}

