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
#include "packageInject.h"
#include "filterManager.h"
#include "fileOperation.tmh"

#include "requestOperation.h"

static POBJECT_CONTEXT g_pObjectContext = NULL;

PVOID getObjectContext()
{
	return g_pObjectContext;
}

PCHAR getShareBufferAddressFromRequestWithoutLock(WDFREQUEST request, UINT32 index, UINT32 sectionLength)
{
	PCHAR result = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;
	POBJECT_CONTEXT context = NULL;

	context = ObjectGetContext(WdfRequestGetFileObject(request));

	if (context->state != QEEYOU_CONTEXT_STATE_OPEN || NULL == context->pMapMdlAddress)
	{

		DoTraceMessage(TRACE_ERROR, L"context is not opening or context mdl address is null");
	}
	else
	{
		result = (PCHAR)MmGetSystemAddressForMdlSafe(context->pMapMdlAddress, NormalPagePriority) + index * sectionLength;
	}

	return result;
}

PCHAR getShareBufferAddressFromRequest(WDFREQUEST request, UINT32 index, UINT32 sectionLength)
{
	PCHAR result = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;
	POBJECT_CONTEXT context = NULL;

	context = ObjectGetContext(WdfRequestGetFileObject(request));

	KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);
	if (context->state != QEEYOU_CONTEXT_STATE_OPEN || NULL == context->pMapMdlAddress)
	{

		DoTraceMessage(TRACE_ERROR, L"context is not opening or context mdl address is null");
	}
	else
	{
		result = (PCHAR)MmGetSystemAddressForMdlSafe(context->pMapMdlAddress, NormalPagePriority) + index * sectionLength;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}

NTSTATUS CopyDataFormWriteRequest(WDFREQUEST request, PVOID *buffer)
{
	NTSTATUS status;
	PCHAR result = NULL;
	PVOID  inBuffer = NULL;
	UINT32 inLength = 0;
	PQEEYOU_RW_S writeStruct = NULL;

	status = WdfRequestRetrieveInputBuffer(request, (size_t)sizeof(QEEYOU_RW_S), &inBuffer, (size_t *)&inLength);
	if (!NT_SUCCESS(status)){

		DoTraceMessage(TRACE_ERROR, "WdfRequestRetrieveOutputMemory failed, status is: %!STATUS!", status);

		return status;
	}

	writeStruct = (PQEEYOU_RW_S)inBuffer;

	*buffer = malloc(writeStruct->dataLength, FALSE);
	if (NULL == *buffer)
	{
		DoTraceMessage(TRACE_ERROR, "allocate data copy failed");

		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{

		result = getShareBufferAddressFromRequestWithoutLock(request, writeStruct->index, writeStruct->sectionSize);
		if (NULL == result)
		{
			DoTraceMessage(TRACE_ERROR, "map address is null");

			free(*buffer);

			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		else
		{
			RtlCopyMemory(*buffer, result, writeStruct->dataLength);
		}
	}

	return status;
}

// 将数据拷贝到读的缓冲区里面去
NTSTATUS CopyDataForReadRequest(WDFREQUEST request, PVOID buffer, size_t length)
{
	NTSTATUS status;
	PCHAR result = NULL;
	PVOID  outBuffer = NULL;
	UINT32 outLength = 0;
	PQEEYOU_RW_S readStruct = NULL;

	status = WdfRequestRetrieveOutputBuffer(request, sizeof(QEEYOU_RW_S), &outBuffer, (size_t *)&outLength);
	if (!NT_SUCCESS(status)){

		DoTraceMessage(TRACE_ERROR, "WdfRequestRetrieveOutputMemory failed, status is: %!STATUS!", status);

		return status;
	}

	readStruct = (PQEEYOU_RW_S)outBuffer;

	if (length > readStruct->sectionSize)
	{
		DoTraceMessage(TRACE_ERROR, "data length %u bigger than section size %u", length, readStruct->sectionSize);

		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{
		result = getShareBufferAddressFromRequest(request, readStruct->index, readStruct->sectionSize);
		if (NULL == result)
		{
			DoTraceMessage(TRACE_ERROR, "map address is null");

			status = STATUS_INSUFFICIENT_RESOURCES;
		}
		else
		{

			RtlCopyMemory(result, buffer, length);
		}
	}

	return status;
}

void ProcessNextReadRequest(POBJECT_CONTEXT context)
{
	WDFREQUEST request;
	PPACKET_S work = NULL;
	PLIST_ENTRY entry = NULL;
	LONGLONG timeStamp = 0;
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	WDF_REQUEST_PARAMETERS parameters;


	timeStamp = getCurrentTimeMs();

	while (!listQueueEmpty(&context->DataQueue))
	{
		entry = listQueueEraseHeader(&context->DataQueue);
		if (NULL == entry)
		{
			//DoTraceMessage(TRACE_ERROR, L"get data queue entry is null");

			break;
		}

		work = CONTAINING_RECORD(entry, PACKET_S, entry);

		if (QEEYOU_TIMEOUT(context, work->timestamp, timeStamp))
		{
			free(work);

			continue;
		}

		KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

		if (context->state != QEEYOU_CONTEXT_STATE_OPEN)
		{
			free(work);

			KeReleaseInStackQueuedSpinLock(&lockHandle);

			DoTraceMessage(TRACE_ERROR, L"context is not opening");

			break;
		}

		status = WdfIoQueueRetrieveNextRequest(context->ReadQueue, &request);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"get queue I/O request failed %!STATUS!", status);

			listQueuePushFront(&context->DataQueue, &work->entry);

			KeReleaseInStackQueuedSpinLock(&lockHandle);

			break;
		}

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		WDF_REQUEST_PARAMETERS_INIT(&parameters);
		WdfRequestGetParameters(request, &parameters);

		if (parameters.Type != WdfRequestTypeRead)
		{
			DoTraceMessage(TRACE_ERROR, L"current request type %u is read type", parameters.Type);

			free(work);

			WdfRequestComplete(request, STATUS_ALERTED);

			continue;
		}

		size_t packageLength = GET_PACK_PACKET_LENGTH(work->data_len, PACKET_S);

		status = CopyDataForReadRequest(request, &work->direction, packageLength - sizeof(LIST_ENTRY));
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"copy read request failed");

			WdfRequestComplete(request, status);
		}
		else
		{
			WdfRequestCompleteWithInformation(request, status, packageLength - sizeof(LIST_ENTRY));
		}

		free(work);
	};


	return;
}

NTSTATUS MyQueueInitialize(WDFDEVICE hDevice)
{
	WDFQUEUE queue;
	NTSTATUS status;
	WDF_IO_QUEUE_CONFIG queueConfig;
	WDF_OBJECT_ATTRIBUTES attributes;

	//
	// Configure a default queue so that requests that are not
	// configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
	// other queues get dispatched here.
	//
	WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);

	queueConfig.EvtIoRead = MyEvtIoRead;
	queueConfig.EvtIoWrite = MyEvtIoWrite;
	queueConfig.EvtIoDeviceControl = MyEvtIoDeviceControl;
	//
	// Fill in a callback for destroy, and our QUEUE_CONTEXT size
	//

	WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
	attributes.EvtDestroyCallback = MyEvtIoQueueContextDestroy;
	attributes.ExecutionLevel = WdfExecutionLevelPassive;
	attributes.SynchronizationScope = WdfSynchronizationScopeNone;
	status = WdfIoQueueCreate(hDevice, &queueConfig, &attributes, &queue);

	if (!NT_SUCCESS(status)) {

		DoTraceMessage(TRACE_ERROR, "WdfIoQueueCreate failed %!STATUS!", status);

	}

	return status;
}

VOID workDeinit(WDFWORKITEM *workerList, UINT32 length)
{
	for (UINT32 index = 0; index < length; index++)
	{
		if (workerList[index])
		{
			WdfWorkItemFlush(workerList[index]);
			WdfObjectDelete(workerList[index]);
			
			workerList[index] = NULL;
		}
	}

	return;
}

VOID MyDeviceFileClose(IN WDFFILEOBJECT object)
{
	
	DoTraceMessage(TRACE_INIT, "enter close file");
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	POBJECT_CONTEXT context = NULL;
	context = ObjectGetContext(object);

	if (context && context->state == QEEYOU_CONTEXT_STATE_CLOSING)
	{
		KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);
		
		context->state = QEEYOU_CONTEXT_STATE_CLOSED;
		g_pObjectContext = NULL;

		KeReleaseInStackQueuedSpinLock(&lockHandle);
	}

	return ;
}

VOID MyDeviceFileCleanup(IN WDFFILEOBJECT object)
{
	DoTraceMessage(TRACE_INIT, "enter clean up file");
	PLIST_ENTRY entry = NULL;
	PPACKET_S work = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_CONTEXT context = NULL;
	
	context = ObjectGetContext(object);

	clearFilter();

	if (context && context->state == QEEYOU_CONTEXT_STATE_OPEN)
	{
		KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

		context->state = QEEYOU_CONTEXT_STATE_CLOSING;


		if (NULL != context->ReadQueue)
		{
			WdfIoQueuePurge(context->ReadQueue, NULL, NULL);
			WdfObjectDelete(context->ReadQueue);
		}

		workDeinit(context->workers, QEEYOU_MAXWORKERS);


		while(!listQueueEmpty(&context->DataQueue))
		{
			entry = listQueueEraseHeader(&context->DataQueue);
			if (NULL == entry)
			{
				DoTraceMessage(TRACE_ERROR, L"get data queue entry is null");

				continue;
			}

			work = CONTAINING_RECORD(entry, PACKET_S, entry);
			
			
			free(work);
		}

		UnMapAndFreeMemory(context->pMapMdlAddress, context->pUserSpaceAddress);

		context->pMapMdlAddress = NULL;
		context->pUserSpaceAddress = NULL;

		KeReleaseInStackQueuedSpinLock(&lockHandle);
	}

	return;
}

VOID workRouting(IN WDFWORKITEM item)
{
	WDFREQUEST request;
	PPACKET_S work = NULL;
	PLIST_ENTRY entry = NULL;
	LONGLONG timeStamp = 0;
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	WDFFILEOBJECT object = (WDFFILEOBJECT)WdfWorkItemGetParentObject(item);
	POBJECT_CONTEXT context = ObjectGetContext(object);
	WDF_REQUEST_PARAMETERS parameters;

	timeStamp = getCurrentTimeMs();

	WdfObjectReference(object);
	
	while (!listQueueEmpty(&context->DataQueue))
	{
		entry = listQueueEraseHeader(&context->DataQueue);
		if (NULL == entry)
		{
			//DoTraceMessage(TRACE_ERROR, L"get data queue entry is null");

			break;
		}

		work = CONTAINING_RECORD(entry, PACKET_S, entry);

		if (QEEYOU_TIMEOUT(context, work->timestamp, timeStamp))
		{
			DoTraceMessage(TRACE_ERROR, L"time out free work current time %llu create time %llu, work ptr %p", work->timestamp, timeStamp, work);

			free(work);

			continue;
		}

		KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

		if (context->state != QEEYOU_CONTEXT_STATE_OPEN)
		{
			free(work);

			KeReleaseInStackQueuedSpinLock(&lockHandle);

			DoTraceMessage(TRACE_ERROR, L"context is not opening");

			break;
		}

		status = WdfIoQueueRetrieveNextRequest(context->ReadQueue, &request);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"get queue I/O request failed %!STATUS!", status);

			listQueuePushFront(&context->DataQueue, &work->entry);

			KeReleaseInStackQueuedSpinLock(&lockHandle);

			break;
		}

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		WDF_REQUEST_PARAMETERS_INIT(&parameters);
		WdfRequestGetParameters(request, &parameters);

		if (parameters.Type != WdfRequestTypeRead)
		{
			DoTraceMessage(TRACE_ERROR, L"current request type %u is read type", parameters.Type);

			free(work);

			WdfRequestComplete(request, STATUS_ALERTED);

			continue;
		}

		size_t packageLength = GET_PACK_PACKET_LENGTH(work->data_len, PACKET_S);

		status = CopyDataForReadRequest(request, &work->direction, packageLength - sizeof(LIST_ENTRY));
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"copy read request failed");

			WdfRequestComplete(request, status);
		}
		else
		{

			WdfRequestCompleteWithInformation(request, status, packageLength - sizeof(LIST_ENTRY));
		}

		free(work);
	};
	
	WdfObjectDereference(object);

	return;
}

NTSTATUS workInit(WDFWORKITEM *workerList, UINT32 length, WDFFILEOBJECT object)
{
	NTSTATUS status = STATUS_SUCCESS;
	WDF_WORKITEM_CONFIG itemConfig;
	WDF_OBJECT_ATTRIBUTES objAttrs;

	WDF_WORKITEM_CONFIG_INIT(&itemConfig, workRouting);
	itemConfig.AutomaticSerialization = FALSE;

	WDF_OBJECT_ATTRIBUTES_INIT(&objAttrs);
	objAttrs.ParentObject = (WDFOBJECT)object;

	for (UINT32 index = 0; index < length; index++)
	{
		workerList[index] = NULL;
	}

	for (UINT32 index = 0; index < length; index++)
	{
		status = WdfWorkItemCreate(&itemConfig, &objAttrs, workerList + index);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"create work item failed");

			workerList[index] = NULL;

			break;
		}
	}

	return status;
}

VOID MyDeviceFileCreate(IN WDFDEVICE device, IN WDFREQUEST request, IN WDFFILEOBJECT object)
{
	DoTraceMessage(TRACE_INIT, "Enter MyDeviceFileCreate");
	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_CONTEXT context = NULL;

	context = ObjectGetContext(object);

	DoTraceMessage(TRACE_INIT, "Enter MyDeviceFileCreate %u", context->state);
	if (context && context->state != QEEYOU_CONTEXT_STATE_OPEN)
	{
		KeInitializeSpinLock(&context->lock);

		KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

		WDF_IO_QUEUE_CONFIG queue_config;
		// 在文件句柄被创建以后，我们创建一个Read Queue
		WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
		queue_config.EvtIoCanceledOnQueue = MyEvtIoCanceledOnQueue;
		status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES, &context->ReadQueue);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "failed to create I/O read queue");
		}

		// 初始化
		context->device = device;

		context->object = object;
		
		context->pMapMdlAddress = NULL;

		context->pUserSpaceAddress = NULL;

		context->workIndex = 0;

		context->priority = 0;

		context->maxDataQueueLenth = WORK_QUEUE_LEN_MAX;

		context->queueOldTime = PARAM_QUEUE_TIME_DEFAULT;

		status = workInit(context->workers, QEEYOU_MAXWORKERS, context->object);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "failed create worker context");
		}

		initListQueue(&context->DataQueue);

		context->state = QEEYOU_CONTEXT_STATE_OPEN;

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		g_pObjectContext = context;

	}

	WdfRequestComplete(request, status);
}

VOID MyIoPreProcessCallback(IN WDFDEVICE device, IN WDFREQUEST request)
{
	NTSTATUS status = STATUS_SUCCESS;

	
	if (checkRequestIsCanceled(request))
	{
		cancelRequest(request);

		DoTraceMessage(TRACE_ERROR, " current request is canceled don't need deal with it");
	}
	else
	{
		WdfDeviceEnqueueRequest(device, request);
	}
	
	return;
}

//input  output operation
VOID MyEvtIoRead(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t Length)
{

	KLOCK_QUEUE_HANDLE lockHandle;
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_CONTEXT context;

	context = ObjectGetContext(WdfRequestGetFileObject(Request));

	if (context == NULL)
	{
		DoTraceMessage(TRACE_EVENT, "MyEvtIoRead QueueGetContext is NULL");

		WdfRequestCompleteWithInformation(Request, status, (ULONG_PTR)0L);

		return;
	}

	KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

	if (context->ReadQueue == NULL)
	{
		DoTraceMessage(TRACE_EVENT, "MyEvtIoRead ReadQueue is NULL");
		
		WdfRequestCompleteWithInformation(Request, STATUS_ABANDONED, (ULONG_PTR)0L);

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		return;
	}

	// 读的话，拿到请求直接丢给读队列
	status = WdfRequestForwardToIoQueue(Request, context->ReadQueue);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_EVENT, "WdfRequestForwardToIoQueue failed, status is %!STATUS!", status);
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	// 尝试走一下看看能不能发送数据
	ProcessNextReadRequest(context);

	return;
}

VOID MyEvtIoWrite(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t Length)
{
	NTSTATUS status = STATUS_SUCCESS;
	POBJECT_CONTEXT context;
	context = ObjectGetContext(WdfRequestGetFileObject(Request));

	//防止对象过早释放
	if (checkRequestIsCanceled(Request))
	{
		DoTraceMessage(TRACE_ERROR, L"request is cancel in write I/O");

		cancelRequest(Request);
	}
	else
	{
		referenceRequestObject(Request);

		setRequestCancelable(Request, defaultRequestCancelRouting);

		status = injectDataInStack(context, Request);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_EVENT, L"inject package into net stack failed %!STATUS!", status);

			completeRequestWithInformation(Request, status, 0);

			dereferenceRequestObject(Request);
		}
	}


	return ;
}

VOID MyEvtIoDeviceControl(IN WDFQUEUE queue, IN WDFREQUEST request, IN size_t out_length, IN size_t in_length, IN ULONG code)
{
	PVOID  inBuffer = NULL;
	UINT32 inLength = 0;
	PVOID  outBuffer = NULL;
	UINT32 outLength = 0;
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	PQEEYOU_IO_CONTROLL_S pIoContext = NULL;
	POBJECT_CONTEXT context = NULL;

	context = ObjectGetContext(WdfRequestGetFileObject(request));

	DoTraceMessage(TRACE_INIT, "controlIo code %lu", code);

	switch (code)
	{
		case ALLOCATE_SHARE_MEMORY_T:
		{
			if (out_length != sizeof(QEEYOU_IO_CONTROLL_S))
			{
				DoTraceMessage(TRACE_ERROR, L"input parameter length illegal in length %u out length %u struct length %u", in_length, out_length, sizeof(QEEYOU_IO_CONTROLL_S));

				status = STATUS_INVALID_PARAMETER;

				break;
			}


			status = WdfRequestRetrieveOutputBuffer(request, out_length, &outBuffer, (size_t *)&outLength);
			if (!NT_SUCCESS(status))
			{
				DoTraceMessage(TRACE_ERROR, L"retrieve out buffer failed %!STATUS!", status);

				break;
			}

			pIoContext = (PQEEYOU_IO_CONTROLL_S)outBuffer;
			KeAcquireInStackQueuedSpinLock(&context->lock, &lockHandle);

			if (QEEYOU_CONTEXT_STATE_OPEN != context->state)
			{
				DoTraceMessage(TRACE_EVENT, "current context state is not open");

				KeReleaseInStackQueuedSpinLock(&lockHandle);

				break;
			}

			status = createAndMapMemory((PMDL*)&context->pMapMdlAddress, (PVOID *)&context->pUserSpaceAddress, &pIoContext->totalAllocSize);
			if (!NT_SUCCESS(status))
			{
				DoTraceMessage(TRACE_ERROR, L"create map memory failed %!STATUS!", status);
				
				KeReleaseInStackQueuedSpinLock(&lockHandle);

				break;
			}

			pIoContext->pUserAddress = (UINT64)context->pUserSpaceAddress;

			KeReleaseInStackQueuedSpinLock(&lockHandle);

			break;
		}

		default:
		{
			DoTraceMessage(TRACE_EVENT, L"unrecognise I/O controll code %lu", code);

			break;
		}
	}

	if (!NT_SUCCESS(status))
	{
		WdfRequestCompleteWithInformation(request, status, 0);
	}
	else
	{
		WdfRequestCompleteWithInformation(request, status, out_length);
	}

	return ;
}

VOID MyEvtIoQueueContextDestroy(IN WDFOBJECT object)
{
	DoTraceMessage(TRACE_EVENT, "MyEvtIoQueueContextDestroy");

	return ;
}

VOID MyEvtIoCanceledOnQueue(IN WDFQUEUE Queue, IN WDFREQUEST Request)
{
	DoTraceMessage(TRACE_EVENT, "MyEvtIoCanceledOnQueue");

	WdfRequestCompleteWithInformation(Request, STATUS_CANCELLED, 0L);
}