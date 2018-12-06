#include "macroDefine.h"

#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <intsafe.h>

#define INITGUID
#include "customGuiddef.h"
#include "userGuidDef.h"

#include "filterCallout.tmh"

#include "list.h"

#include "common.h"

#include "filterCallout.h"
#include "fileOperation.h"

#include "packageInject.h"
#include "protocolHeader.h"

#include "filterManager.h"

#include "filterDataTransThread.h"

extern PVOID getObjectContext();

#ifndef ASSOCIATE_CALLOUT_INDEX
#define ASSOCIATE_CALLOUT_INDEX 5
#endif 

#ifndef QEEYOU_PACKET_MAGIC
#define QEEYOU_PACKET_MAGIC 0x1314520b
#endif

#ifndef REGISTER_ARRAY_SIZE
#define REGISTER_ARRAY_SIZE 8
#endif

static ListQueue g_listQueue;

typedef struct {
	HANDLE sessionHandle;
	FWPM_SESSION session;
}calloutSession;

static calloutSession engineSession;

extern CalloutInfoStruct calloutRegisterArray[REGISTER_ARRAY_SIZE];


//LONGLONG g_currentTime = 0;
//LONGLONG g_bytesCount = 0;


VOID freeFlowContext(FLOW_DATA *flowContext)
{
	if (!flowContext)
	{
		return ;
	}

	if (flowContext->processPath)
	{
		free(flowContext->processPath);
	}

	free(flowContext);

	return ;
}

NTSTATUS allocateFlowContext( _In_ SIZE_T processPathSize, _Out_ FLOW_DATA** flowContextOut)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLOW_DATA* flowContext = NULL;

	*flowContextOut = NULL;
	do
	{
		flowContext = (FLOW_DATA*)malloc(sizeof(FLOW_DATA), FALSE);

		if (!flowContext)
		{
			DoTraceMessage(TRACE_ERROR, "allocate flow context failed");

			status = STATUS_NO_MEMORY;

			break;
		}

		RtlZeroMemory(flowContext, sizeof(FLOW_DATA));

		if (processPathSize)
		{
			flowContext->processPath = (WCHAR *)malloc(processPathSize, FALSE);
			if (!flowContext->processPath)
			{
				status = STATUS_NO_MEMORY;

				DoTraceMessage(TRACE_ERROR, "allocate process path failed");

				break;
			}
		}

		*flowContextOut = flowContext;
	} while (0);

	if (!NT_SUCCESS(status))
	{
		if (flowContext)
		{
			if (flowContext->processPath)
			{
				free(flowContext->processPath);
			}
			
			free(flowContext);
		}
	}

	return status;
}

UINT64 getConnectFlowContext(_In_ const FWPS_INCOMING_VALUES* inFixedValues,_In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues)
{
	FLOW_DATA*     flowContext = NULL;
	NTSTATUS       status;
	FWP_BYTE_BLOB* processPath;
	UINT32         index;

	do
	{
		if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
		{
			status = STATUS_NOT_FOUND;
			
			DoTraceMessage(TRACE_ERROR, "process path is not exit");
			
			break;
		}

		processPath = inMetaValues->processPath;

		status = allocateFlowContext(processPath->size, &flowContext);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "allocate flow context failed");

			break;
		}

		//  Flow context is always created at the Flow established layer.

		// flowContext gets deleted in MonitorCoCleanupFlowContext 

		flowContext->deleting = FALSE;
		flowContext->flowHandle = inMetaValues->flowHandle;

		index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS;
		flowContext->localAddressV4 = inFixedValues->incomingValue[index].value.uint32;


		index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT;
		flowContext->localPort = inFixedValues->incomingValue[index].value.uint16;

		index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS;
		flowContext->remoteAddressV4 = inFixedValues->incomingValue[index].value.uint32;

		index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT;
		flowContext->remotePort = inFixedValues->incomingValue[index].value.uint16;

		index = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL;
		flowContext->ipProto = inFixedValues->incomingValue[index].value.uint16;

		memcpy(flowContext->processPath, processPath->data, processPath->size);

	/*	WCHAR srcAddress[20] = { 0 };
		WCHAR dstAddress[20] = { 0 };

		convertIpAddress(flowContext->localAddressV4, srcAddress, sizeof(srcAddress));
		convertIpAddress(flowContext->remoteAddressV4, dstAddress, sizeof(dstAddress));
		DoTraceMessage(TRACE_EVENT, L"connect trace package local address %S local port %u remote address %S remote port %u, protocol %u", srcAddress, flowContext->localPort, dstAddress, flowContext->remotePort, flowContext->ipProto);
*/

	} while (0);

	if (!NT_SUCCESS(status))
	{
		flowContext = NULL;
	}

	return (UINT64)flowContext;
}

BOOLEAN queueWork(POBJECT_CONTEXT context, PNET_BUFFER buffer, UINT32 priority, PThreadContext_S threadContext)
{
	PVOID data = NULL;
	UINT32 dataLength = 0;
	PLIST_ENTRY oldEntry = NULL;
	PPACKET_S work = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;

	dataLength = NET_BUFFER_DATA_LENGTH(buffer);

	work = malloc(GET_PACK_PACKET_LENGTH(dataLength, PACKET_S), FALSE);
	if (NULL == work)
	{
		DoTraceMessage(TRACE_ERROR, L"allocate buffer length %u, struct length %u", dataLength, GET_PACK_PACKET_LENGTH(dataLength, PACKET_S));

		return FALSE;
	}

	work->data_len = dataLength;
	data = NdisGetDataBuffer(buffer, dataLength, NULL, 1, 0);
	if (NULL == data)
	{
		NdisGetDataBuffer(buffer, dataLength, work->buff, 1, 0);
	}
	else
	{
		RtlCopyMemory(work->buff, data, dataLength);
	}

	if (threadContext)
	{
		composeIpv4Header(threadContext->localAddressV4, threadContext->remoteAddressV4, threadContext->ipProto, dataLength, work->buff);
	}

	work->direction = threadContext->direction;
	work->if_idx = threadContext->if_idx;
	work->sub_if_idx = threadContext->sub_if_idx;
	work->priority = priority;
	work->timestamp = getCurrentTimeMs();

	KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);


	if (QEEYOU_CONTEXT_STATE_OPEN != context->state)
	{
		DoTraceMessage(TRACE_EVENT, L"current context is closing or closed");

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		free(work);

		return FALSE;
	}

	UINT32 length = listQueueLength(&context->DataQueue);
	
	if (length >= context->maxDataQueueLenth)
	{
		DoTraceMessage(TRACE_EVENT, L"erase oldest work , list size %u bigger than %llu", length, context->maxDataQueueLenth);

		oldEntry = listQueueEraseHeader(&context->DataQueue);
	}
	

	listQueuePushBack(&context->DataQueue, &work->entry);
	
	WdfWorkItemEnqueue(context->workers[context->workIndex]);
	context->workIndex = (context->workIndex + 1) % QEEYOU_MAXWORKERS;

	KeReleaseInStackQueuedSpinLock(&lockHandle);
	
	if (oldEntry != NULL)
	{

		work = CONTAINING_RECORD(oldEntry, PACKET_S, entry);

		free(work);
	}

	return TRUE;
}

VOID transportPreClassifyPacket( IN UINT8 direction,
	IN UINT32 if_idx, IN UINT32 sub_if_idx, IN BOOLEAN loopback,
	IN UINT advance, IN OUT void *data, IN UINT64 flowContext,
	OUT FWPS_CLASSIFY_OUT0 *result)
{
	result->actionType = FWP_ACTION_CONTINUE;

	if (!(result->rights & FWPS_RIGHT_ACTION_WRITE) || data == NULL)
	{
		DoTraceMessage(TRACE_ERROR, L"filter package right can't be modify %u, data %p", result->rights, data);

		return;
	}

	if (loopback)
	{
		DoTraceMessage(TRACE_ERROR, L"this package is loopback we don't need process");

		return;
	}

	//queue class context
	PThreadContext_S threadContext = allocThreadContext(direction, if_idx, sub_if_idx, advance, data, flowContext);
	if (NULL == threadContext)
	{
		DoTraceMessage(TRACE_ERROR, L"alloc thread context failed");

		return;
	}

	listQueuePushBack(getThreadDataList(), &threadContext->entry);

	setThreadEvent();

	result->actionType = FWP_ACTION_BLOCK;
	//slient drop the package
	result->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
	result->rights &= ~FWPS_RIGHT_ACTION_WRITE;

	return;
}

VOID classifyCallout(PThreadContext_S threadContext)
{
	PNET_BUFFER buffer;
	UINT32 packetPriority;
	WDFOBJECT object = NULL;
	PPACKET_S package = NULL;
	HANDLE packetContext = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	FWPS_PACKET_INJECTION_STATE packetState = FWPS_PACKET_INJECTION_STATE_MAX;

	buffer = NET_BUFFER_LIST_FIRST_NB(threadContext->netBuffers);

	POBJECT_CONTEXT context = getObjectContext();

	if (NULL == context)
	{
		return ;
	}

	KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

	if (QEEYOU_CONTEXT_STATE_OPEN != context->state)
	{
		KeReleaseInStackQueuedSpinLock(&lockHandle);
		
		DoTraceMessage(TRACE_ERROR, L"current context is close or closed");

		return;
	}

	object = context->object;
	packetPriority = context->priority;
	WdfObjectReference(object);

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	packetState = getPacketInjectState(threadContext->netBuffers, &packetContext);
	if (packetState == FWPS_PACKET_INJECTED_BY_SELF ||
		packetState == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
	{
		if (((UINT32)packetContext) >= packetPriority)
		{
			DoTraceMessage(TRACE_ERROR, L"context priority %u advance current priority %u", (UINT32)packetContext, packetPriority);

			WdfObjectDereference(object);
			
			return;
		}
	}

	/*
	* queue the all packet into the list
	*/
	do
	{

		if (threadContext->advance != 0)
		{
			status = NdisRetreatNetBufferDataStart(buffer, threadContext->advance, 0, NULL);
			if (!NT_SUCCESS(status))
			{
				DoTraceMessage(TRACE_ERROR, L"net buffer advance data start %u failed result %!STATUS!", (UINT32)threadContext->advance, status);

				break;
			}
		}

		if (!queueWork(context, buffer, packetPriority, threadContext))
		{
			
			DoTraceMessage(TRACE_ERROR, L"queue the buffer into buffer list failed");

		}

		if (threadContext->advance != 0)
		{
			NdisAdvanceNetBufferDataStart(buffer, threadContext->advance, TRUE, NULL);
		}

		buffer = NET_BUFFER_NEXT_NB(buffer);
	} while (buffer != NULL);

	WdfObjectDereference(object);
}

VOID classifyCalloutHook(_In_ PVOID StartContext)
{
	NTSTATUS status;
	ListQueue * listQueue = NULL;
	PThreadContext_S threadContext = NULL;
	PLIST_ENTRY entry = NULL;
	POBJECT_CONTEXT context = NULL;

	while (!getTheadRunFlag())
	{
		status = waitThreadEventHandle();
		if (!NT_SUCCESS(status))
		{
			continue;
		}

		listQueue = getThreadDataList();
		if (NULL == listQueue)
		{
			DoTraceMessage(TRACE_ERROR, L"list data header is null");

			break;
		}

		while (!listQueueEmpty(listQueue))
		{
			entry = listQueueEraseHeader(listQueue);
			if (NULL == entry)
			{
				break;
			}

			threadContext = CONTAINING_RECORD(entry, ThreadContext_S, entry);
			
			classifyCallout(threadContext);

			freeThreadContext(threadContext);
		}
	}

	clearContextList();

	PsTerminateSystemThread(STATUS_SUCCESS);
}

//connect layer
VOID NTAPI connectClassify(_In_ const FWPS_INCOMING_VALUES0* inFixedValues, _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, _Inout_opt_ void* layerData, _In_opt_ const void* classifyContext, _In_ const FWPS_FILTER1* filter, _In_ UINT64 flowContext, _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
	NTSTATUS status = STATUS_SUCCESS;

	do
	{

		UINT64   flowContextLocal = getConnectFlowContext(inFixedValues, inMetaValues);
		if (0 == flowContextLocal)
		{
			DoTraceMessage(TRACE_ERROR, "allocate connect flow context failed");

			classifyOut->actionType = FWP_ACTION_CONTINUE;

			break;
		}

		FLOW_DATA * flowData = (FLOW_DATA *)flowContextLocal;
		UINT64 flowHandle = inMetaValues->flowHandle;

		status = FwpsFlowAssociateContext(flowHandle,
			calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].layerId,
			calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].calloutId,
			flowContextLocal);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "flow associate context failed %!STATUS!, callout Id %lu", status, calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].calloutId);

			classifyOut->actionType = FWP_ACTION_CONTINUE;

			freeFlowContext((FLOW_DATA *)flowContextLocal);

			break;
		}

		listQueuePushBack(&g_listQueue, &(((FLOW_DATA *)flowContextLocal)->listEntry));

		flowData->calloutId = calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].calloutId;
		flowData->layerId = calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].layerId;

		classifyOut->actionType = FWP_ACTION_PERMIT;

		if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
		{
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}

	} while (0);

	return ;
}

NTSTATUS NTAPI connectNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, _In_ const GUID* filterKey, _Inout_ FWPS_FILTER1* filter)
{
	switch (notifyType)
	{
		case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
			{
				filter->context = (UINT64)getObjectContext();

				DoTraceMessage(TRACE_EVENT,  "connect add filter  with callout");

				break;
			}

		case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
			{
				filter->context = 0;

				DoTraceMessage(TRACE_EVENT, "connect delete filter with callout");

				break;
			}

		case FWPS_CALLOUT_NOTIFY_ADD_FILTER_POST_COMMIT:
			{
				DoTraceMessage(TRACE_EVENT, "connect add filter post commit");

				break;
			}

		case FWPS_CALLOUT_NOTIFY_TYPE_MAX:
			{
				DoTraceMessage(TRACE_EVENT, "connect add filter type max");

				break;
			}

		default:
			{
				DoTraceMessage(TRACE_EVENT, "default add connect filter");

				break;
			}

	}

	return STATUS_SUCCESS;
}

BOOLEAN connectInstall(void *deviceHandle, UINT32 index, HANDLE enginHandle)
{
	
	BOOLEAN result = TRUE;
	NTSTATUS status = STATUS_SUCCESS;
	FWPS_CALLOUT scallout = {0};
	FWPM_CALLOUT mcallout = { 0 };

	if (index >= sizeof(calloutRegisterArray))
	{
		DoTraceMessage(TRACE_ERROR, L"index  %u out of the array size %u", index, sizeof(calloutRegisterArray));

		return FALSE;
	}

	if (enginHandle == 0)
	{
		DoTraceMessage(TRACE_ERROR, L"initialize driver handle failed index %u", index);

		return FALSE;
	}

	scallout.calloutKey		= *calloutRegisterArray[index].calloutKey;
	scallout.classifyFn		= calloutRegisterArray[index].classfyFunc;
	scallout.flags				= calloutRegisterArray[index].flags;
	scallout.notifyFn			= calloutRegisterArray[index].notifyFunc;
	scallout.flowDeleteFn	= calloutRegisterArray[index].deleteFunc;

	status = FwpsCalloutRegister(deviceHandle, &scallout, &(calloutRegisterArray[index].calloutId));
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"register callout failed callout name %S reason %!STATUS!", calloutRegisterArray[index].calloutName, status);

		return FALSE;
	}

	mcallout.calloutKey = *calloutRegisterArray[index].calloutKey;
	mcallout.displayData.name = calloutRegisterArray[index].calloutName;
	mcallout.displayData.description = calloutRegisterArray[index].calloutDesc;
	mcallout.applicableLayer = *calloutRegisterArray[index].layerGuid;

	do
	{
		status = FwpmTransactionBegin(enginHandle, 0);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"failed to begin transaction %!STATUS! calloutName %S", status, calloutRegisterArray[index].calloutName);

			result = FALSE;

			break;
		}

		status = FwpmCalloutAdd(enginHandle, &mcallout, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"failed to add callout  %!STATUS!, name %S", status, calloutRegisterArray[index].calloutName);

			result = FALSE;

			break;
		}

		status = FwpmTransactionCommit(enginHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "commit transaction failed %!STATUS!, name %S", status, calloutRegisterArray[index].calloutName);

			result = FALSE;

			break;
		}

	} while (0);

	if (!result)
	{
		FwpmTransactionAbort(enginHandle);
		FwpsCalloutUnregisterByKey(calloutRegisterArray[index].calloutKey);
	}
	
	return result;
}

BOOLEAN connectUninstall(UINT32 index, HANDLE enginHandle)
{
	BOOLEAN result = TRUE;
	NTSTATUS status = STATUS_SUCCESS;

	if (index >= sizeof(calloutRegisterArray))
	{
		DoTraceMessage(TRACE_ERROR, L"index  %u out of the array size %u", index, sizeof(calloutRegisterArray));

		return FALSE;
	}

	do
	{
		status = FwpmTransactionBegin(enginHandle, 0);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"begin transaction failed name %S %!STATUS!", calloutRegisterArray[index].calloutName, status);

			result = FALSE;

			break;
		}

		status = FwpmCalloutDeleteByKey(enginHandle, calloutRegisterArray[index].calloutKey);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"delete callout by key failed name %S %!STATUS!", calloutRegisterArray[index].calloutName, status);

			result = FALSE;

			break;
		}

		status = FwpmTransactionCommit(enginHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"commit transaction	 name %S failed  %!STATUS!", calloutRegisterArray[index].calloutName, status);

			result = FALSE;
		}

	} while (0);

	if (!result)
	{
		FwpmTransactionAbort(enginHandle);
	}

	if (calloutRegisterArray[index].calloutId != 0)
	{
		status = FwpsCalloutUnregisterByKey(calloutRegisterArray[index].calloutKey);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"unregister callout by key failed name %S", calloutRegisterArray[index].calloutName);
		}
	}


	return result;
}

//connect redirect

UINT64 getConnectRedirectFlowContext(_In_ const FWPS_INCOMING_VALUES* inFixedValues, _In_ const FWPS_INCOMING_METADATA_VALUES* inMetaValues)
{
	UINT32 processPathSize = 0;
	FLOW_DATA*     flowContext = NULL;
	NTSTATUS       status;
	FWP_BYTE_BLOB* processPath;
	UINT32         index;

	do
	{
		if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_PATH))
		{
			status = STATUS_NOT_FOUND;

			DoTraceMessage(TRACE_ERROR, "redirect process path is not exit %p", inMetaValues->processPath);

			processPathSize = 0;

			processPath = NULL;
		}
		else
		{
			processPathSize = inMetaValues->processPath->size;

			processPath = inMetaValues->processPath;
		}
		

		status = allocateFlowContext(processPathSize, &flowContext);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "allocate flow context failed");

			break;
		}

		//  Flow context is always created at the Flow established layer.

		// flowContext gets deleted in MonitorCoCleanupFlowContext 

		flowContext->deleting = FALSE;
		flowContext->flowHandle = inMetaValues->flowHandle;

		index = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_ADDRESS;
		flowContext->localAddressV4 = inFixedValues->incomingValue[index].value.uint32;


		index = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT;
		flowContext->localPort = inFixedValues->incomingValue[index].value.uint16;

		index = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS;
		flowContext->remoteAddressV4 = inFixedValues->incomingValue[index].value.uint32;

		index = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT;
		flowContext->remotePort = inFixedValues->incomingValue[index].value.uint16;

		index = FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL;
		flowContext->ipProto = inFixedValues->incomingValue[index].value.uint16;
		
		if (NULL != processPath)
		{
			memcpy(flowContext->processPath, processPath->data, processPath->size);
		}

		//WCHAR srcAddress[20] = { 0 };
		//WCHAR dstAddress[20] = { 0 };

		//convertIpAddress(flowContext->localAddressV4, srcAddress, sizeof(srcAddress));
		//convertIpAddress(flowContext->remoteAddressV4, dstAddress, sizeof(dstAddress));
		//DoTraceMessage(TRACE_EVENT, L"connect redirect trace package local address %S local port %u remote address %S remote port %u, protocol %u", srcAddress, flowContext->localPort, dstAddress, flowContext->remotePort, flowContext->ipProto);


	} while (0);

	if (!NT_SUCCESS(status))
	{
		flowContext = NULL;
	}

	return (UINT64)flowContext;
}

VOID NTAPI connectRedirectClassify(_In_ const FWPS_INCOMING_VALUES0* inFixedValues, _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, _Inout_opt_ void* layerData, _In_opt_ const void* classifyContext, _In_ const FWPS_FILTER1* filter, _In_ UINT64 flowContext, _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
	NTSTATUS status = STATUS_SUCCESS;

	do
	{

		UINT64   flowContextLocal = getConnectRedirectFlowContext(inFixedValues, inMetaValues);
		if (0 == flowContextLocal)
		{
			DoTraceMessage(TRACE_ERROR, "redirect allocate connect flow context failed");

			classifyOut->actionType = FWP_ACTION_CONTINUE;

			break;
		}

		FLOW_DATA * flowData = (FLOW_DATA *)flowContextLocal;
		UINT64 flowHandle = inMetaValues->flowHandle;

		status = FwpsFlowAssociateContext(flowHandle,
			calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].layerId,
			calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].calloutId,
			flowContextLocal);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "flow associate context failed %!STATUS!, callout Id %lu", status, calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].calloutId);

			classifyOut->actionType = FWP_ACTION_CONTINUE;

			freeFlowContext((FLOW_DATA *)flowContextLocal);

			break;
		}

		listQueuePushBack(&g_listQueue, &(((FLOW_DATA *)flowContextLocal)->listEntry));

		flowData->calloutId = calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].calloutId;
		flowData->layerId = calloutRegisterArray[ASSOCIATE_CALLOUT_INDEX].layerId;

		classifyOut->actionType = FWP_ACTION_PERMIT;

		if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
		{
			classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		}

	} while (0);

	/*DoTraceMessage(TRACE_EVENT, L"trace event connect redirect begin length %lu", listQueueLength(&g_listQueue));*/

	return;
}

NTSTATUS NTAPI connectRedirectNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, _In_ const GUID* filterKey, _Inout_ FWPS_FILTER1* filter)
{
	switch (notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
	{
		filter->context = (UINT64)getObjectContext();

		DoTraceMessage(TRACE_EVENT, "connect redirect  add filter  with callout");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
	{
		filter->context = 0;

		DoTraceMessage(TRACE_EVENT, "connect redirect  delete filter with callout");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_ADD_FILTER_POST_COMMIT:
	{
		DoTraceMessage(TRACE_EVENT, "connect redirect  add filter post commit");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_TYPE_MAX:
	{
		DoTraceMessage(TRACE_EVENT, "connect redirect add filter type max");

		break;
	}

	default:
	{
		DoTraceMessage(TRACE_EVENT, "default add connect redirect  filter");

		break;
	}

	}

	return STATUS_SUCCESS;
}
//================transport layer==================

NTSTATUS NTAPI transportNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, _In_ const GUID* filterKey, _Inout_ FWPS_FILTER1* filter)
{
	switch (notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
	{
		filter->context = (UINT64)getObjectContext();

		DoTraceMessage(TRACE_EVENT, "transport add filter  with callout");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
	{
		filter->context = 0;

		DoTraceMessage(TRACE_EVENT, "transport delete filter with callout");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_ADD_FILTER_POST_COMMIT:
	{
		DoTraceMessage(TRACE_EVENT, "transport add filter post commit");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_TYPE_MAX:
	{
		DoTraceMessage(TRACE_EVENT, "transport add filter type max");

		break;
	}

	default:
	{
		DoTraceMessage(TRACE_EVENT, "default add transport filter");

		break;
	}

	}

	return STATUS_SUCCESS;
}


VOID NTAPI transportClassify(_In_ const FWPS_INCOMING_VALUES0* inFixedValues, _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, _Inout_opt_ void* layerData, _In_opt_ const void* classifyContext, _In_ const FWPS_FILTER1* filter, _In_ UINT64 flowContext, _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
	_Analysis_assume_(packet != NULL);
	_Analysis_assume_(flowContext != NULL);

	HRESULT result = S_OK;
	FLOW_DATA* flowData = NULL;
	UINT32 ipHeaderSize = sizeof(QEEYOU_IPHDR);

	flowData = (FLOW_DATA*)flowContext;
	
	WCHAR srcAddress[20] = { 0 };
	WCHAR dstAddress[20] = { 0 };

	
	//if (getCurrentTimeMs() - g_currentTime >= 1000)
	//{
	//	DoTraceMessage(TRACE_ERROR, L"start time %llu current time %llu package bytes %llu", g_currentTime, getCurrentTimeMs(), g_bytesCount);

	//	g_bytesCount = 0;

	//	g_currentTime = getCurrentTimeMs();
	//}

	convertIpAddress(flowData->localAddressV4, srcAddress, sizeof(srcAddress));
	convertIpAddress(flowData->remoteAddressV4, dstAddress, sizeof(dstAddress));

	if (inMetaValues->ipHeaderSize)
	{
		ipHeaderSize = inMetaValues->ipHeaderSize;
	}

	//DoTraceMessage(TRACE_ERROR, L"transport src ip address %S src port %u dest ip address %S dest port %u ip header size %u,  protocol %u", srcAddress, flowData->localPort, dstAddress, flowData->remotePort, ipHeaderSize, flowData->ipProto);
	

	POBJECT_CONTEXT context = getObjectContext();

	if (NULL == context)
	{
		return;
	}

	PNET_BUFFER buffer;
	PNET_BUFFER_LIST buffers;

	buffers = (PNET_BUFFER_LIST)layerData;
	buffer = NET_BUFFER_LIST_FIRST_NB(buffers);

	//g_bytesCount += NET_BUFFER_DATA_LENGTH(buffer) * 8 + 160;
	
	transportPreClassifyPacket(
							QEEYOU_DIRECTION_OUTBOUND,
							inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_INTERFACE_INDEX].value.uint32, 
							inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX].value.uint32, 
							(inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_FLAGS].value.uint32&FWP_CONDITION_FLAG_IS_LOOPBACK),
							ipHeaderSize,
							layerData,
							flowContext,
							classifyOut
							);
							

	return ;
}


VOID NTAPI transportDelete(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
	)
{
	_Analysis_assume_(flowContext != NULL);

	HRESULT result = S_OK;
	FLOW_DATA* flowData = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;

	flowData = (FLOW_DATA*)flowContext;
	ASSERT(result == S_OK);


	KeAcquireInStackQueuedSpinLock(&(g_listQueue.m_lockContext), &lockHandle);


	if (!flowData->deleting)
	{
		listQueueEraseAtWithoutLock(&g_listQueue, &flowData->listEntry);

	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	freeFlowContext(flowData);
	
	return ;
}

//=====================out bound ip package layer======================
VOID NTAPI outBoundClassify(_In_ const FWPS_INCOMING_VALUES0* inFixedValues, _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, _Inout_opt_ void* layerData, _In_opt_ const void* classifyContext, _In_ const FWPS_FILTER1* filter, _In_ UINT64 flowContext, _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
	_Analysis_assume_(packet != NULL);
	_Analysis_assume_(flowContext != NULL);

	HRESULT result = S_OK;
	FLOW_DATA* flowData = NULL;

	flowData = (FLOW_DATA*)flowContext;

	WCHAR srcAddress[20] = { 0 };
	WCHAR dstAddress[20] = { 0 };

	convertIpAddress(flowData->localAddressV4, srcAddress, sizeof(srcAddress));
	convertIpAddress(flowData->remoteAddressV4, dstAddress, sizeof(dstAddress));

	DoTraceMessage(TRACE_ERROR, L"out bound src ip address %S src port %u dest ip address %S dest port %u ip header size %u", srcAddress, flowData->localPort, dstAddress, flowData->remotePort, inMetaValues->ipHeaderSize);

	POBJECT_CONTEXT context = getObjectContext();
	if (NULL == context)
	{
		return;
	}

	transportPreClassifyPacket(
		QEEYOU_DIRECTION_OUTBOUND,
		inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_INTERFACE_INDEX].value.uint32,
		inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_SUB_INTERFACE_INDEX].value.uint32,
		(inFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_FLAGS].value.uint32&FWP_CONDITION_FLAG_IS_LOOPBACK),
		inMetaValues->ipHeaderSize,
		layerData,
		flowContext,
		classifyOut
		);


	return;
}
NTSTATUS NTAPI outBoundNotify(_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, _In_ const GUID* filterKey, _Inout_ FWPS_FILTER1* filter)
{
	switch (notifyType)
	{
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
	{
		filter->context = (UINT64)getObjectContext();

		DoTraceMessage(TRACE_EVENT, "out bound add filter  with callout");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
	{
		filter->context = 0;

		DoTraceMessage(TRACE_EVENT, "out bound delete filter with callout");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_ADD_FILTER_POST_COMMIT:
	{
		DoTraceMessage(TRACE_EVENT, "out bound add filter post commit");

		break;
	}

	case FWPS_CALLOUT_NOTIFY_TYPE_MAX:
	{
		DoTraceMessage(TRACE_EVENT, "out bound add filter type max");

		break;
	}

	default:
	{
		DoTraceMessage(TRACE_EVENT, "default add out bound filter");

		break;
	}

	}

	return STATUS_SUCCESS;
}

VOID NTAPI outBoundDelete(
	_In_ UINT16 layerId,
	_In_ UINT32 calloutId,
	_In_ UINT64 flowContext
	)
{
	_Analysis_assume_(flowContext != NULL);

	HRESULT result = S_OK;
	FLOW_DATA* flowData = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;

	flowData = (FLOW_DATA*)flowContext;
	ASSERT(result == S_OK);

	DoTraceMessage(TRACE_EVENT, L"enter out bound delete function");

	KeAcquireInStackQueuedSpinLock(&(g_listQueue.m_lockContext), &lockHandle);


	if (!flowData->deleting)
	{
		listQueueEraseAtWithoutLock(&g_listQueue, &flowData->listEntry);

	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	freeFlowContext(flowData);

	return;
}

static  CalloutInfoStruct calloutRegisterArray[REGISTER_ARRAY_SIZE] =
{
	{ L"auth connect", L"send a connect package", &FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0, FWPS_LAYER_ALE_AUTH_CONNECT_V4, 0, &QEEYOU_FILTER_CONNECT_CALLOUT, connectInstall, connectUninstall, connectClassify, connectNotify, NULL },
	{ L"redirect connect", L"send redirect connect package", &FWPM_LAYER_ALE_AUTH_CONNECT_V4, 0, FWPS_LAYER_ALE_AUTH_CONNECT_V4, 0, &QEEYOU_FILTER_CONNECT_DNS_LAYER, connectInstall, connectUninstall, connectRedirectClassify, connectRedirectNotify, NULL },
	{ L"redirect connect", L"send redirect connect package", &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, 0, FWPS_LAYER_ALE_CONNECT_REDIRECT_V4, 0, &QEEYOU_FILTER_CONNECT_REDIRECT_CALLOUT, NULL, NULL, connectRedirectClassify, connectRedirectNotify, NULL },
	{ L"establish", L"flow establish state", &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4, 0, FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4, 0, &QEEYOU_FILTER_ESTABLISHED_CALLOUT, NULL, NULL, NULL, NULL, NULL },
	{ L"accept", L"flow recv messge", &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, 0, FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4, 0, &QEEYOU_FILTER_RECV_CALLOUT, NULL, NULL, NULL, NULL, NULL },
	{ L"transport", L"flow transport message", &FWPM_LAYER_OUTBOUND_TRANSPORT_V4, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW, FWPS_LAYER_OUTBOUND_TRANSPORT_V4, 0, &QEEYOU_FILTER_TRANS_CALLOUT, connectInstall, connectUninstall, transportClassify, transportNotify, transportDelete },
	{ L"filter inbound", L"filter inbound package", &FWPM_LAYER_INBOUND_IPPACKET_V4, 0, FWPS_LAYER_INBOUND_IPPACKET_V4, 0, &QEEYOU_FILTER_INBOUNT_IPPACKAGE_CALLOUT, NULL, NULL, NULL, NULL, NULL },
	{ L"filter outbound", L"filter outbound package", &FWPM_LAYER_OUTBOUND_IPPACKET_V4, FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW, 0, FWPS_LAYER_OUTBOUND_IPPACKET_V4, &QEEYOU_FILTER_OUTBOUNT_IPPACKAGE_CALLOUT, connectInstall, connectUninstall, outBoundClassify, outBoundNotify, outBoundDelete }
};

VOID clearContextList()
{
	ListQueue tempList;
	KLOCK_QUEUE_HANDLE lockHandle;

	initListQueue(&tempList);

	KeAcquireInStackQueuedSpinLock(&(g_listQueue.m_lockContext), &lockHandle);

	while (!listQueueEmptyWithoutLock(&g_listQueue))
	{
		FLOW_DATA* flowContext;
		LIST_ENTRY* entry;

		entry = listQueueEraseHeaderWithoutLock(&g_listQueue);

		flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);
		flowContext->deleting = TRUE; 

		DoTraceMessage(TRACE_EVENT, L"first length is %lu", listQueueLengthWithoutLock(&g_listQueue));

		listQueuePushFront(&tempList, entry);

	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	while (!listQueueEmpty(&tempList))
	{
		FLOW_DATA* flowContext;
		LIST_ENTRY* entry;
		NTSTATUS status;

		entry = listQueueEraseHeader(&tempList);

		flowContext = CONTAINING_RECORD(entry, FLOW_DATA, listEntry);

		DoTraceMessage(TRACE_EVENT, L" second length is %lu", listQueueLength(&tempList));
		//call callouts deletefunction
		status = FwpsFlowRemoveContext(flowContext->flowHandle, flowContext->layerId, flowContext->calloutId);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"remove an associate context with flow failed error number %!STATUS!, layer id %u, callout id %lu", status, flowContext->layerId, flowContext->calloutId);
		}

	}
}

DWORD initSession()
{
	DWORD result = S_OK;

	RtlZeroMemory(&engineSession, sizeof(FWPM_SESSION));

	engineSession.session.txnWaitTimeoutInMSec = UINT_MAX;
	engineSession.session.displayData.name = KENERL_SESSION_NAME;
	engineSession.session.displayData.description = KENERL_SESSION_NAME;

	result = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&engineSession.session,
		&engineSession.sessionHandle
		);

	if (result != S_OK)
	{
		DoTraceMessage(TRACE_ERROR, L"open session failed error number %u", result);
	}

	return result;
}

VOID DeinitSession()
{
	if (engineSession.sessionHandle != 0)
	{
		FwpmEngineClose(engineSession.sessionHandle);
	}
} 

VOID initCalloutLayer(void *deviceHandle)
{

	if (deviceHandle == NULL)
	{
		DoTraceMessage(TRACE_ERROR, L"input device handle is null");

		return;
	}

	initSession();
	injectInitial();
	//thread kernel initial must after inject initial
	initialKenerlThread(classifyCalloutHook, NULL);
	initListQueue(&g_listQueue);

	for (int index = 0; index < REGISTER_ARRAY_SIZE; index++)
	{
		if (calloutRegisterArray[index].installHook)
		{ 
			if (!calloutRegisterArray[index].installHook(deviceHandle, index, engineSession.sessionHandle))
			{ 
				DoTraceMessage(TRACE_ERROR, L"install callout %S failed", calloutRegisterArray[index].calloutName);
			}
			else
			{
				DoTraceMessage(TRACE_EVENT, L"install callout %S success, callout id %lu", calloutRegisterArray[index].calloutName, calloutRegisterArray[index].calloutId);
			}
		}
	}
}

VOID deInitCalloutLayer()
{
	clearAllFilter();

	clearContextList();
	
	//thread kernel deinitial must before inject deinitial
	deInitialkenerlThread();
	injectDeinitial();

	for (int index = 0; index < REGISTER_ARRAY_SIZE; index++)
	{
		if (calloutRegisterArray[index].uninstallHook)
		{
			if (!calloutRegisterArray[index].uninstallHook( index, engineSession.sessionHandle))
			{
				DoTraceMessage(TRACE_ERROR, L"uninstall callout %S failed", calloutRegisterArray[index].calloutName);
			}
			else
			{
				DoTraceMessage(TRACE_EVENT, L"uninstall callout %S success", calloutRegisterArray[index].calloutName);
			}
		}
	}

	DeinitSession();
	//deinitialize list need modify
}