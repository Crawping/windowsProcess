#pragma once

#include <map>
#include <stdint.h>
#include <windows.h>

#ifndef QEEYOU_DIRECTION_INBOUND
#define QEEYOU_DIRECTION_INBOUND (0)
#endif

#ifndef QEEYOU_DIRECTION_OUTBOUND
#define QEEYOU_DIRECTION_OUTBOUND (1)
#endif

#pragma pack(1)
typedef struct PseudoHeader {
	uint32_t src_address;
	uint32_t dst_address;
	uint8_t zero;
	uint8_t protocol;
	// payload + header length.
	uint16_t length;
} PseudoHeader;

typedef struct IPV4Header {
	uint8_t  header_length : 4;
	uint8_t  version : 4;
	uint8_t  tos;
	uint16_t length;
	uint16_t id;
	uint16_t frag_off0;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t src_address;
	uint32_t dest_address;

	void* data() {
		// IP包除去包头，后面的就是数据
		uint8_t* ptr = reinterpret_cast<uint8_t*>(this);
		return ptr + this->header_length * sizeof(uint32_t);
	}

	uint16_t data_length() const {
		// IP包除去包头，后面的就是数据，length字段是包含了IP头和数据的网络字节序
		return ntohs(length) - header_length * sizeof(uint32_t);
	}

	// 创建一个伪头部，TCP/UDP一般会用到.
	PseudoHeader CreatePseuoHeader() const {
		PseudoHeader pseudo_header;
		pseudo_header.src_address = src_address;
		pseudo_header.dst_address = dest_address;
		pseudo_header.zero = 0;
		pseudo_header.protocol = protocol;
		// 包头里面的值，基本上都是网络字节序
		pseudo_header.length = htons(data_length());
		return pseudo_header;
	}

} IPV4Header;

typedef struct TCPHeader {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
#if defined(__BIG_ENDIAN_BITFIELD)
	uint16_t header_length : 4;
	uint16_t reserved1 : 4;
	uint16_t cwr : 1;
	uint16_t ece : 1;
	uint16_t urg : 1;
	uint16_t ack : 1;
	uint16_t psh : 1;
	uint16_t rst : 1;
	uint16_t syn : 1;
	uint16_t fin : 1;
#else
	uint16_t reserved1 : 4;
	uint16_t header_length : 4;
	uint16_t fin : 1;
	uint16_t syn : 1;
	uint16_t rst : 1;
	uint16_t psh : 1;
	uint16_t ack : 1;
	uint16_t urg : 1;
	uint16_t ece : 1;
	uint16_t cwr : 1;
#endif
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_ptr;
} TCPHeader;

typedef struct UDPHeader {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
} UDPHeader;

typedef struct ICMPHeader {
	uint8_t icmp_type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identify;
	uint16_t sequence_number;
} ICMPHeader;

typedef struct _INJECT_BUFF
{
	INT64  Timestamp;                   /* Packet's timestamp. */
	UINT32 IfIdx;                       /* Packet's interface index. */
	UINT32 SubIfIdx;                    /* Packet's sub-interface index. */
	UINT8  Direction : 1;                 /* Packet's direction. */
	UINT8  Loopback : 1;                  /* Packet is loopback? */
	UINT8  Impostor : 1;                  /* Packet is impostor? */
	UINT8  PseudoIPChecksum : 1;          /* Packet has pseudo IPv4 checksum? */
	UINT8  PseudoTCPChecksum : 1;         /* Packet has pseudo TCP checksum? */
	UINT8  PseudoUDPChecksum : 1;         /* Packet has pseudo UDP checksum? */
	UINT8  Reserved : 2;
	UINT32 Length;								/*buffer length*/
	CHAR buffer[0];								/*data section*/
}INJECT_BUFF, *PINJECT_BUFF;

typedef struct _PACKET_S
{
#ifdef DIRVER
	LIST_ENTRY entry;                       // Entry for queue.
#endif
	UINT32 direction;                        // Packet direction.
	UINT32 if_idx;                          // Interface index.
	UINT32 sub_if_idx;                      // Sub-interface index.
	UINT32 priority;                        // Packet priority.
	LONGLONG timestamp;                     // Packet timestamp.
	size_t data_len;                        // Length of `data'.
	CHAR buff[0];                             // Packet data.
}PACKET_S, *PPACKET_S;

#ifndef GET_PACK_PACKET_LENGTH
#define GET_PACK_PACKET_LENGTH(length, type) ((sizeof(type) + length))
#endif

#pragma pack()