#ifndef COMMON_H
#define COMMON_H

LONGLONG getCurrentTimeMs();


PVOID malloc(SIZE_T size, BOOLEAN paged);
VOID free(PVOID ptr);
/*
*  traceview log message
*/
VOID wppDeinit(_In_ DRIVER_OBJECT* driverObject);
VOID wppInitial(_In_ DRIVER_OBJECT* driverObject, _In_ UNICODE_STRING* registryPath);
/*
* dbgview debug message
* message length limit in 1024
*/
VOID logMessage(PCCH format, NTSTATUS status, ...);
/*
* convert ip to ip address
* must be copy buffer to another buffer
* the function is not the reentrant   function
*/
PWCHAR convertIpAddress(UINT32 ipAddress, PWCHAR buffer, ULONG length);


VOID composeIpv4Header(UINT32 srcAddress, UINT32 dstIpAddress, USHORT protocol, UINT32 length, PVOID header);


VOID UnMapAndFreeMemory(PMDL PMdl, PVOID UserVa);

NTSTATUS createAndMapMemory(PMDL* PMemMdl, PVOID* UserVa, PUINT32 totalBytes);

#endif