#include "macroDefine.h"

#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include <list.h>
#include <fwpsk.h>
#include <fwpmk.h>

#include "common.h"
#include "fileOperation.h"

#include "filterDataTransThread.tmh"

#include "filterDataTransThread.h"

#include "packageInject.h"
#include "filterCallout.h"

PETHREAD g_threadObject =NULL;
BOOLEAN g_ThreadExitFlag = FALSE;
KEVENT g_ThreadEvent;
HANDLE g_threadHandle = NULL;



static ListQueue g_threadListQueue;

VOID initTreadEvent(PKEVENT event)
{
	KeInitializeEvent(event, SynchronizationEvent, FALSE);
}

BOOLEAN getTheadRunFlag()
{
	return g_ThreadExitFlag;
}

VOID setThreadEvent()
{
	KeSetEvent(&g_ThreadEvent, IO_NO_INCREMENT, FALSE);
}

LONG resetThreadEvent()
{
	return KeResetEvent(&g_ThreadEvent);
}

VOID clearThreadEvent()
{
	KeClearEvent(&g_ThreadEvent);
}

NTSTATUS waitThreadEventHandle()
{
	NTSTATUS status = KeWaitForSingleObject(&g_ThreadEvent, Executive, KernelMode, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, "wait thread event failed %!STATUS!", status);
	}
	
	return status;
}

ListQueue *getThreadDataList()
{
	return &g_threadListQueue;
}

PThreadContext_S allocThreadContext(UINT8 direction,
				UINT32 if_idx,UINT32 sub_if_idx, UINT advance, 
				void *data, UINT64 flowContext)
{
	FLOW_DATA* currFlowContext = (FLOW_DATA *)flowContext;

	if (NULL == data || 0 == flowContext)
	{
		DoTraceMessage(TRACE_ERROR, "input paramater is null alloc thread context failed");

		return NULL;
	}

	PThreadContext_S  context = (PThreadContext_S )malloc(sizeof(ThreadContext_S), FALSE);
	if (NULL == context)
	{
		DoTraceMessage(TRACE_ERROR, "allocate thread context failed");

		return NULL;
	}

	context->netBuffers = cloneNetBufferList((PNET_BUFFER_LIST)data);
	if (NULL == context->netBuffers)
	{
		DoTraceMessage(TRACE_ERROR, "clone net buffer list failed");

		free(context);

		return NULL;
	}

	context->advance = advance;
	context->if_idx = if_idx;
	context->sub_if_idx = sub_if_idx;
	context->direction = direction;
	context->ipProto = currFlowContext->ipProto;
	context->localAddressV4 = currFlowContext->localAddressV4;
	context->localPort = currFlowContext->localPort;
	context->remoteAddressV4 = currFlowContext->remoteAddressV4;
	context->remotePort = currFlowContext->remotePort;

	return context;
}

VOID freeThreadContext(PThreadContext_S context)
{
	if (NULL != context)
	{
		if (context->netBuffers)
		{
			FwpsFreeCloneNetBufferList(context->netBuffers, 0);

			context->netBuffers = NULL;
		}

		free(context);
	}
}

VOID clearThreadDataList()
{
	PLIST_ENTRY entry = NULL;
	PThreadContext_S threadContext = NULL;

	while (!listQueueEmpty(&g_threadListQueue))
	{
		entry = listQueueEraseHeader(&g_threadListQueue);
		if (NULL == entry)
		{
			DoTraceMessage(TRACE_ERROR, L"get thread data list entry is null");

			continue;
		}

		threadContext = CONTAINING_RECORD(entry, ThreadContext_S, entry);


		free(threadContext);
	}

	return;
}


VOID initialKenerlThread(
							_In_ PKSTART_ROUTINE StartRoutine,
						_In_ _When_(return == 0, __drv_aliasesMem) PVOID StartContext)
{
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	HANDLE hWorkerThread = NULL;

	NTSTATUS status = PsCreateSystemThread(
		&g_threadHandle,
		THREAD_ALL_ACCESS,
		&ObjectAttributes,
		NULL,
		NULL,
		StartRoutine,
		StartContext);

	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, "create kenerl thread failed %!STATUS!", status);

		g_threadHandle = NULL;
	}
	else
	{
		initTreadEvent(&g_ThreadEvent);
		initListQueue(&g_threadListQueue);
		status = ObReferenceObjectByHandle(g_threadHandle,
			THREAD_ALL_ACCESS,
			NULL,
			KernelMode,
			&g_threadObject,
			NULL);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "reference thread handle object failed %!STATUS!", status);
		}

		ZwClose(g_threadHandle);

		g_threadHandle = NULL;
	}

}

VOID deInitialkenerlThread()
{
	if (NULL == g_threadObject)
	{
		DoTraceMessage(TRACE_ERROR, "thread handle is null");

		return;
	}

	g_ThreadExitFlag = TRUE;

	setThreadEvent();

	NTSTATUS status = KeWaitForSingleObject(g_threadObject, Executive, KernelMode, FALSE, NULL);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, "wait thread exit failed %!STATUS!", status);
	}

	ObDereferenceObject(g_threadObject);

	return ;
}