
#include "macroDefine.h"

#include <ntddk.h>
#include <wdf.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include "common.h"
#include "protocolHeader.h"
#include "common.tmh"


#define DEBUG_BUFSIZE       1024

#define MAX_MAP_SIZE		(8192*10)

#define DEFAULT_PAGE_SIZE (8192)

PVOID malloc(SIZE_T size, BOOLEAN paged)
{
	POOL_TYPE type = (paged ? PagedPool : NonPagedPool);

	return ExAllocatePoolWithTag(type, size, PACKAGE_ALLOCATE_TAG);
}

VOID free(PVOID ptr)
{
	if (ptr != NULL)
	{
		ExFreePoolWithTag(ptr, PACKAGE_ALLOCATE_TAG);
	}
}

VOID wppInitial(_In_ DRIVER_OBJECT* driverObject, _In_ UNICODE_STRING* registryPath)
{
	WPP_INIT_TRACING(driverObject, registryPath);


}

VOID wppDeinit(_In_ DRIVER_OBJECT* driverObject)
{
	WPP_CLEANUP(driverObject);
}

VOID logMessage(PCCH format, NTSTATUS status, ...)
{
	va_list args;
	char buf[DEBUG_BUFSIZE + 1];
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
	{
		return;
	}
	va_start(args, status);
	RtlStringCbVPrintfA(buf, DEBUG_BUFSIZE, format, args);
	DbgPrint("WINDIVERT: *** ERROR ***: (status = %x): %s\n", status, buf);
	va_end(args);
}

PWCHAR convertIpAddress(UINT32 ipAddress, PWCHAR buffer, ULONG length)
{
	RtlStringCbPrintfW(buffer, length, L"%u.%u.%u.%u", (ipAddress >> 24) & 0x000000ff, (ipAddress >> 16) & 0x000000ff, (ipAddress >> 8) & 0x000000ff, ipAddress & 0x000000ff);

	return buffer;
}

LONGLONG getCurrentTimeMs()
{
	LARGE_INTEGER freq;
	LONGLONG countPerSeconds = 0;

	KeQueryPerformanceCounter(&freq);

	countPerSeconds = freq.QuadPart / 1000;
	
	countPerSeconds = (countPerSeconds == 0) ? 1 : countPerSeconds;

	return KeQueryPerformanceCounter(NULL).QuadPart / countPerSeconds;
}

USHORT CalcChecksum(PVOID data, UINT32 len)
{
	size_t len16 = 0;
	UINT32 sum = 0;
	size_t i;

	// Main data:
	USHORT *data16 = (USHORT *)data;
	len16 = len >> 1;
	for (i = 0; i < len16; i++)
	{
		sum += (UINT32)data16[i];
	}

	if (len & 0x1)
	{
		const UINT8 *data8 = (const UINT8 *)data;
		sum += (UINT16)data8[len - 1];
	}

	sum = (sum & 0xFFFF) + (sum >> 16);
	sum += (sum >> 16);
	sum = ~sum;
	return (UINT16)sum;
}

void composeIpv4Header(UINT32 srcAddress, UINT32 dstIpAddress, USHORT protocol, UINT32 length,PVOID header)
{
	PQEEYOU_IPHDR ipv4Header = (PQEEYOU_IPHDR)header;

	LONGLONG timeStamp = getCurrentTimeMs();

	USHORT identify = (timeStamp >> 48 & MAXUSHORT) | (timeStamp >> 32 & MAXUSHORT) | (timeStamp >> 16 & MAXUSHORT) | (timeStamp & MAXUSHORT);

	if (NULL == ipv4Header)
	{
		return;
	}

	ipv4Header->Version = 4;
	ipv4Header->Length = RtlUshortByteSwap(length);
	ipv4Header->DstAddr = RtlUlongByteSwap(dstIpAddress);
	ipv4Header->SrcAddr = RtlUlongByteSwap(srcAddress);
	ipv4Header->TOS = 0;
	ipv4Header->FragOff0 = 0;
	ipv4Header->Checksum = 0;
	ipv4Header->HdrLength = sizeof(QEEYOU_IPHDR) >> 2;
	ipv4Header->Protocol = (UINT8)protocol;
	ipv4Header->TTL = 255;
	ipv4Header->Id = RtlUshortByteSwap(identify);

	ipv4Header->Checksum = CalcChecksum(ipv4Header, ipv4Header->HdrLength << 2);
}

NTSTATUS createAndMapMemory(PMDL* PMemMdl, PVOID* UserVa, PUINT32 totalBytes)
{
	PMDL                mdl;
	PVOID               userVAToReturn;
	PHYSICAL_ADDRESS    lowAddress;
	PHYSICAL_ADDRESS    highAddress;

	lowAddress.QuadPart = 0;
	highAddress.QuadPart = 0xFFFFFFFFFFFFFFFF;
	//向上取整 pagesize

	*totalBytes = (*totalBytes &(~DEFAULT_PAGE_SIZE)) + (!!(*totalBytes % DEFAULT_PAGE_SIZE)) * DEFAULT_PAGE_SIZE;

	if (*totalBytes > MAX_MAP_SIZE)
	{
		DoTraceMessage(TRACE_ERROR, L"allocate page failed total bytes overhead %u", *totalBytes);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	mdl = MmAllocatePagesForMdl(lowAddress, highAddress, lowAddress, *totalBytes);

	if (!mdl)
	{
		DoTraceMessage(TRACE_ERROR, L"allocate page for mdl failed bytes %u", *totalBytes);

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	userVAToReturn =
		MmMapLockedPagesSpecifyCache(mdl,
		UserMode,
		MmCached,
		NULL,
		FALSE,
		NormalPagePriority); 

	if (!userVAToReturn)  {
		MmFreePagesFromMdl(mdl);
		IoFreeMdl(mdl);
		
		DoTraceMessage(TRACE_ERROR, L"map page to user space failed");

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	*UserVa = userVAToReturn;
	*PMemMdl = mdl;

	DoTraceMessage(TRACE_EVENT, L"map page to user address is %p", userVAToReturn);

	return STATUS_SUCCESS;
}

void UnMapAndFreeMemory(PMDL PMdl, PVOID UserVa)
{
	if (!PMdl)
	{
		DoTraceMessage(TRACE_ERROR, L"map mdl address is null, unmap failed");

		return;
	}

	MmUnmapLockedPages(UserVa, PMdl);

	MmFreePagesFromMdl(PMdl);

	IoFreeMdl(PMdl);
}
