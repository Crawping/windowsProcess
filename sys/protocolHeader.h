#ifndef PROTOCOLHEADER_H
#define PROTOCOLHEADER_H

#ifndef QEEYOU_DIRECTION_INBOUND
#define QEEYOU_DIRECTION_INBOUND (0)
#endif

#ifndef QEEYOU_DIRECTION_OUTBOUND
#define QEEYOU_DIRECTION_OUTBOUND (1)
#endif
#pragma pack(1)
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
	UINT32 data_len;                        // Length of `data'.
	CHAR buff[0];                             // Packet data.
}PACKET_S, *PPACKET_S;

#ifndef GET_PACK_PACKET_LENGTH
#define GET_PACK_PACKET_LENGTH(length, type) ((sizeof(type) + length))
#endif

typedef struct _QEEYOU_IPHDR
{
	UINT8  HdrLength : 4;
	UINT8  Version : 4;
	UINT8  TOS;
	UINT16 Length;
	UINT16 Id;
	UINT16 FragOff0;
	UINT8  TTL;
	UINT8  Protocol;
	UINT16 Checksum;
	UINT32 SrcAddr;
	UINT32 DstAddr;
} QEEYOU_IPHDR, *PQEEYOU_IPHDR;

typedef struct _QEEYOU_IO_CONTROLL_S
{
	UINT32 totalAllocSize;
	UINT64 pUserAddress;
} QEEYOU_IO_CONTROLL_S, *PQEEYOU_IO_CONTROLL_S;

typedef struct _QEEYOU_RW_S
{
	UINT32 index;
	UINT32 dataLength;
	UINT32 sectionSize;
} QEEYOU_RW_S, *PQEEYOU_RW_S;

#pragma pack()
#define QEEYOU_IPHDR_GET_FRAGOFF(hdr)                    \
    (((hdr)->FragOff0) & 0xFF1F)
#define QEEYOU_IPHDR_GET_MF(hdr)                         \
    ((((hdr)->FragOff0) & 0x0020) != 0)
#define QEEYOU_IPHDR_GET_DF(hdr)                         \
    ((((hdr)->FragOff0) & 0x0040) != 0)
#define QEEYOU_IPHDR_GET_RESERVED(hdr)                   \
    ((((hdr)->FragOff0) & 0x0080) != 0)

#define QEEYOU_IPHDR_SET_FRAGOFF(hdr, val)               \
    do                                                      \
	    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0x00E0) |    \
            ((val) & 0xFF1F);                               \
	    }                                                       \
		while (FALSE)
#define QEEYOU_IPHDR_SET_MF(hdr, val)                    \
    do                                                      \
	    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFFDF) |    \
            (((val) & 0x0001) << 5);                        \
	    }                                                       \
	    while (FALSE)
#define QEEYOU_IPHDR_SET_DF(hdr, val)                    \
    do                                                      \
	    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFFBF) |    \
            (((val) & 0x0001) << 6);                        \
	    }                                                       \
		while (FALSE)
#define QEEYOU_IPHDR_SET_RESERVED(hdr, val)              \
    do                                                      \
	    {                                                       \
        (hdr)->FragOff0 = (((hdr)->FragOff0) & 0xFF7F) |    \
            (((val) & 0x0001) << 7);                        \
	    }                                                       \
     while (FALSE)

#endif