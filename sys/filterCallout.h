#ifndef FILTERCALLOUT_H
#define FILTERCALLOUT_H

#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <intsafe.h>

struct calloutInfo;

typedef BOOLEAN (*installFuncType) (void *deviceHandle, UINT32 index, HANDLE enginHandle);
typedef BOOLEAN(*uninstallFuncType) (UINT32 index, HANDLE enginHandle);
typedef struct calloutInfo
{
	//user
	WCHAR *calloutName;
	WCHAR *calloutDesc;
	const GUID* layerGuid;
	//kernel
	UINT32 flags;
	UINT16 layerId;
	UINT32 calloutId;
	const GUID* calloutKey;
	installFuncType installHook;
	uninstallFuncType uninstallHook;
	FWPS_CALLOUT_CLASSIFY_FN classfyFunc;
	FWPS_CALLOUT_NOTIFY_FN notifyFunc;
	FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN deleteFunc;
	/*
	* inbound inject handle
	* outbound inject handle
	*/
	HANDLE injectHandle;
}CalloutInfoStruct;

typedef struct _FLOW_DATA
{
	UINT64      flowHandle;
	UINT64      flowContext;
	ULONG       localAddressV4;
	USHORT      localPort;
	USHORT      ipProto;
	ULONG       remoteAddressV4;
	USHORT      remotePort;
	WCHAR*      processPath;
	LIST_ENTRY  listEntry;
	BOOLEAN     deleting;
	UINT32			calloutId;
	UINT16			layerId;
} FLOW_DATA;

VOID deInitCalloutLayer();
VOID initCalloutLayer(void *deviceHandle);


#endif