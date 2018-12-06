#include "macroDefine.h"

#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <intsafe.h>

#include "common.h"
#include "fileOperation.h"
#include "protocolHeader.h"
#include "packageInject.tmh"
#include "packageInject.h"

#include "requestOperation.h"

static HANDLE injectHandle = NULL;
static NDIS_HANDLE nblPoolHandle = NULL;

BOOLEAN injectBoundInstall(PHANDLE injectHandle)
{
	BOOLEAN result = TRUE;
	NTSTATUS status = STATUS_SUCCESS;

	status = FwpsInjectionHandleCreate(AF_INET, FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD, injectHandle);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"create inject handle failed %!STATUS!", status);

		*injectHandle = NULL;

		result = FALSE;
	}

	return result;
}

BOOLEAN injectBoundUninstall(PHANDLE injectHandle)
{
	BOOLEAN result = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	if (*injectHandle != NULL)
	{
		status = FwpsInjectionHandleDestroy(*injectHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"destroy inject handle failed %!STATUS!", status);

			result = FALSE;
		}

		*injectHandle = NULL;
	}
	else
	{
		result = FALSE;
	}

	return result;
}

PNET_BUFFER_LIST cloneNetBufferList(PNET_BUFFER_LIST netBuffList)
{
	PNET_BUFFER_LIST retNetBuffList = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	if (NULL != nblPoolHandle)
	{
		status = FwpsAllocateCloneNetBufferList(netBuffList, NULL, NULL, 0, &retNetBuffList);
		if (!NT_SUCCESS(status))
		{
			retNetBuffList = NULL;
			
			DoTraceMessage(TRACE_ERROR, L"clone netbufferlist failed  %!STATUS!", status);

		}
	}
	else
	{
		DoTraceMessage(TRACE_ERROR, L"net buffer allocate pool handle is null");
	}

	return retNetBuffList;
}

void NTAPI injectComplete(VOID *context, NET_BUFFER_LIST *buffers, BOOLEAN dispathLevel)
{
	PMDL mdl;
	PVOID data;
	PNET_BUFFER buffer;
	size_t length;
	WDFREQUEST request;
	NTSTATUS status;
	UNREFERENCED_PARAMETER(dispathLevel);

	buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
	request = (WDFREQUEST)context;

	if (NULL != request)
	{
		if (checkRequestIsCanceledEx(request))
		{
			DoTraceMessage(TRACE_ERROR, L"current inject request is cancelled");
		}
		else
		{
			status = NET_BUFFER_LIST_STATUS(buffers);
			length = 0;
			if (NT_SUCCESS(status))
			{
				length = NET_BUFFER_DATA_LENGTH(buffer);

				completeRequestWithInformation(request, status, length);
			}
			else
			{
				DoTraceMessage(TRACE_ERROR, L"async inject package failed result %!STATUS!", status);

				completeRequestWithInformation(request, status, 0);
			}
		}

		dereferenceRequestObject(request);
	}

	if (NULL != buffer)
	{
		mdl = NET_BUFFER_FIRST_MDL(buffer);
		if (NULL != mdl)
		{
			data = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
			if (NULL != data)
			{	
				free(data);
			}

			IoFreeMdl(mdl);
		}

		FwpsFreeNetBufferList0(buffers);
	}
}

/*
* 错误需要调用者自己 对请求进行处理
* 成功过后有异步调用过程处理请求
*/
NTSTATUS injectDataInStack(POBJECT_CONTEXT context, WDFREQUEST request)
{
	NTSTATUS status = STATUS_SUCCESS;
	UINT32 priority = 0;
	PMDL mdlCopy = NULL;
	PINJECT_BUFF injectDataBuffer = NULL;
	PNET_BUFFER_LIST netBuffers = NULL;


	status = CopyDataFormWriteRequest(request, (PVOID *)&injectDataBuffer);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"retrieve inject buffer failed %!STATUS!", status);

		return status;
	}
	//现目前只针对ipv4数据校验
	if (injectDataBuffer->Length < sizeof(QEEYOU_IPHDR))
	{
		DoTraceMessage(TRACE_ERROR, L"data length length %u illegal ip header length %u", injectDataBuffer->Length, sizeof(QEEYOU_IPHDR));

		status = STATUS_INVALID_PARAMETER;

		return status;
	}

	PQEEYOU_IPHDR ipHeader = (PQEEYOU_IPHDR)injectDataBuffer->buffer;
	if (ipHeader->Version != 4)
	{
		DoTraceMessage(TRACE_ERROR, L"ip version %u is not ipv4 protocol", ipHeader->Version);

		status = STATUS_INVALID_PARAMETER;

		return status;
	}

	mdlCopy = IoAllocateMdl(injectDataBuffer, GET_PACK_PACKET_LENGTH(injectDataBuffer->Length, INJECT_BUFF), FALSE, FALSE, NULL);
	if (NULL == mdlCopy)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		
		DoTraceMessage(TRACE_ERROR, L"failed to allocate MDL for injected packet %!STATUS!", status);

		goto inject_exit;
	}

	MmBuildMdlForNonPagedPool(mdlCopy);
	status = FwpsAllocateNetBufferAndNetBufferList0(nblPoolHandle, 0, 0, mdlCopy, sizeof(INJECT_BUFF), injectDataBuffer->Length, &netBuffers);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"allocate net buffer list failed %!STATUS!", status);

		goto inject_exit;
	}

	priority = context->priority;
	
	if (!checkRequestIsCanceledEx(request))
	{
		//inject into network
		if (QEEYOU_DIRECTION_OUTBOUND == injectDataBuffer->Direction)
		{
			status = FwpsInjectNetworkSendAsync(injectHandle, (HANDLE)priority, 0,
				UNSPECIFIED_COMPARTMENT_ID, netBuffers, injectComplete, (HANDLE)request);
		}
		else
		{
			status = FwpsInjectNetworkReceiveAsync(injectHandle, (HANDLE)priority, 0,
				UNSPECIFIED_COMPARTMENT_ID, injectDataBuffer->IfIdx, injectDataBuffer->SubIfIdx, netBuffers, injectComplete, (HANDLE)request);
		}
	}
	else
	{
		status = STATUS_CANCELLED;

		DoTraceMessage(TRACE_ERROR, "request is canceled don't inject into stack %!STATUS!", status);
	}

	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"inject data to the stack failed direction %u  %!STATUS!", injectDataBuffer->Direction, status);
	}

inject_exit:

	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"inject data into stack failed");

		if (NULL != netBuffers)
		{
			FwpsFreeNetBufferList(netBuffers);
		}

		if (NULL != mdlCopy)
		{
			IoFreeMdl(mdlCopy);
		}

		if (NULL != injectDataBuffer)
		{
			free(injectDataBuffer);
		}
	}

	return status;
}

VOID initNetBufferPool()
{
	NET_BUFFER_LIST_POOL_PARAMETERS nblPoolParams;

	RtlZeroMemory(&nblPoolParams, sizeof(nblPoolParams));
	nblPoolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
	nblPoolParams.Header.Revision =NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
	nblPoolParams.Header.Size = sizeof(NET_BUFFER_LIST_POOL_PARAMETERS);
	nblPoolParams.fAllocateNetBuffer = TRUE;
	nblPoolParams.PoolTag = PACKAGE_ALLOCATE_TAG;
	nblPoolParams.DataSize = 0;

	nblPoolHandle = NdisAllocateNetBufferListPool(NULL, &nblPoolParams);
	if (NULL == nblPoolHandle)
	{
		DoTraceMessage(TRACE_ERROR, L"alloc net buffer list pool failed");
	}

	return;
}

VOID deinitNetBufferPool()
{
	if (NULL == nblPoolHandle)
	{
		NdisFreeNetBufferListPool(nblPoolHandle);

		nblPoolHandle = NULL;
	}
	else
	{
		DoTraceMessage(TRACE_ERROR, L"net buffer deinitialize failed");
	}
}

FWPS_PACKET_INJECTION_STATE getPacketInjectState(PNET_BUFFER_LIST netBuffers, PHANDLE packetPriority)
{
	FWPS_PACKET_INJECTION_STATE state = FWPS_PACKET_INJECTION_STATE_MAX;
	
	state = FwpsQueryPacketInjectionState(injectHandle, netBuffers, packetPriority);

	return state;
}

VOID injectInitial()
{
	injectBoundInstall(&injectHandle);

	initNetBufferPool();
}

VOID injectDeinitial()
{
	injectBoundUninstall(&injectHandle);

	deinitNetBufferPool();
}