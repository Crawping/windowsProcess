#include "macroDefine.h"


#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include "common.h"
#include "fileOperation.h"

#include "requestOperation.tmh"


static KSPIN_LOCK g_requestSpinLock;

VOID initialRequestOp()
{
	KeInitializeSpinLock(&g_requestSpinLock);
}

VOID setRequestCancelable(WDFREQUEST Request, PFN_WDF_REQUEST_CANCEL EvtRequestCancel)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;


	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	PREQUEST_CONTEXT context = getRequestContext(Request);
	if (NULL == context)
	{
		DoTraceMessage(TRACE_ERROR, L"request context is null");

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		return;
	}

	context->isCanceled = FALSE;

	BOOLEAN result = WdfRequestIsCanceled(Request);
	if (result)
	{
		DoTraceMessage(TRACE_ERROR, L"the request is marked canceled");
		
		KeReleaseInStackQueuedSpinLock(&lockHandle);

		return;
	}

	status = WdfRequestMarkCancelableEx(Request, EvtRequestCancel);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"mark request cancelable failed %!STATUS!", status);
	}


	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return;
}

VOID defaultRequestCancelRouting(WDFREQUEST Request)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	
	DoTraceMessage(TRACE_EVENT, L"enter default I/O cancel");

	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	PREQUEST_CONTEXT context = getRequestContext(Request);

	if (NULL == context)
	{
		DoTraceMessage(TRACE_ERROR, L"request context is null");

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		WdfRequestComplete(Request, STATUS_CANCELLED);

		return;
	}

	if (!context->isCanceled)
	{
		context->isCanceled = TRUE;

		WdfRequestComplete(Request, STATUS_CANCELLED);
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

BOOLEAN checkRequestIsCanceledEx(WDFREQUEST Request)
{
	BOOLEAN result = FALSE;

	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	PREQUEST_CONTEXT context = getRequestContext(Request);

	if (NULL == context)
	{
		DoTraceMessage(TRACE_ERROR, L"request context is null");

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		return FALSE;
	}

	if (!context->isCanceled)//current request is canceled
	{
		result = WdfRequestIsCanceled(Request);
	}
	else
	{
		result = context->isCanceled;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}

BOOLEAN checkRequestIsCanceled(WDFREQUEST Request)
{
	BOOLEAN result = FALSE;

	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	result = WdfRequestIsCanceled(Request);

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}

VOID cancelRequest(WDFREQUEST Request)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	PREQUEST_CONTEXT context = getRequestContext(Request);

	if (NULL == context)
	{
		DoTraceMessage(TRACE_ERROR, L"request context is null");

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		WdfRequestComplete(Request, STATUS_CANCELLED);

		return;
	}

	if (!context->isCanceled)
	{
		context->isCanceled = TRUE;

		WdfRequestComplete(Request, STATUS_CANCELLED);
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

VOID completeRequestWithInformation( WDFREQUEST Request, NTSTATUS Status, ULONG_PTR Information)
{
	NTSTATUS status = STATUS_SUCCESS;
	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	PREQUEST_CONTEXT context = getRequestContext(Request);

	if (NULL == context)
	{
		DoTraceMessage(TRACE_ERROR, L"request context is null");


		status = WdfRequestUnmarkCancelable(Request);
		if (STATUS_CANCELLED != status)
		{
			WdfRequestCompleteWithInformation(Request, Status, Information);
		}

		KeReleaseInStackQueuedSpinLock(&lockHandle);

		return;
	}

	if (!context->isCanceled)
	{
		status = WdfRequestUnmarkCancelable(Request);
		if (STATUS_CANCELLED != status)
		{
			WdfRequestCompleteWithInformation(Request, Status, Information);
		}

		context->isCanceled = TRUE;
	}
	else//由于请求的cancel已经调用，所以该处只会手动将request cancellable 取消
	{
		DoTraceMessage(TRACE_ERROR, L"system already call cancelable function");
		WdfRequestUnmarkCancelable(Request);
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

VOID referenceRequestObject(WDFREQUEST Request)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);

	WdfObjectReference(Request);

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}

VOID dereferenceRequestObject(WDFREQUEST Request)
{
	KLOCK_QUEUE_HANDLE lockHandle;
	KeAcquireInStackQueuedSpinLock(&g_requestSpinLock, &lockHandle);
	
	WdfObjectDereference(Request);

	KeReleaseInStackQueuedSpinLock(&lockHandle);
}