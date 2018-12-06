#ifndef FILTERDATATRANSTHREAD_H
#define FILTERDATATRANSTHREAD_H

typedef struct threadContext
{
	LIST_ENTRY entry;
	UINT32 if_idx;
	UINT8 direction;
	UINT32 sub_if_idx;
	UINT advance;
	//compose ip header
	ULONG       localAddressV4;
	USHORT      localPort;
	USHORT      ipProto;
	ULONG       remoteAddressV4;
	USHORT      remotePort;
	PNET_BUFFER_LIST netBuffers;
}ThreadContext_S, * PThreadContext_S;

VOID setThreadEvent();
VOID clearContextList();
BOOLEAN getTheadRunFlag();
ListQueue *getThreadDataList();
NTSTATUS waitThreadEventHandle();
VOID deInitialkenerlThread();
VOID freeThreadContext(PThreadContext_S context);
VOID initialKenerlThread(PKSTART_ROUTINE StartRoutine, PVOID StartContext);
PThreadContext_S allocThreadContext(UINT8 direction, UINT32 if_idx, UINT32 sub_if_idx, UINT advance, void *data, UINT64 flowcontext);
#endif