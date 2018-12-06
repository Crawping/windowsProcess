#include "macroDefine.h"

#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <intsafe.h>

#include "customGuiddef.h"
#include "userGuidDef.h"

#include "filterManager.tmh"


HANDLE openFilterManagerSession(PWCHAR sessionName)
{

	HANDLE engineHandle = NULL;
	FWPM_SESSION session = { 0 };
	NTSTATUS status = STATUS_SUCCESS;

	session.txnWaitTimeoutInMSec = 0xFFFFFFFF; //infinite
	session.displayData.name = sessionName;
	session.displayData.description = sessionName;

	status = FwpmEngineOpen(
		NULL,
		RPC_C_AUTHN_DEFAULT,
		NULL,
		&session,
		&engineHandle
		);

	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"session open failed error number %!STATUS!", status);

		engineHandle = NULL;
	}

	return engineHandle;
}

VOID closeFilterManagerSession(HANDLE sessionHandle)
{
	if (sessionHandle)
	{
		FwpmEngineClose(sessionHandle);
	}
}

NTSTATUS deleteProviderByKey(const GUID* key, HANDLE sessionHandle)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = FwpmTransactionBegin(sessionHandle, 0);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"session action begin failed %!STATUS!", status);

		return status;
	}

	do
	{
		status = FwpmProviderDeleteByKey(sessionHandle, key);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"delete provider by key failed %!STATUS!", status);

			break;
		}

		status = FwpmTransactionCommit(sessionHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"commit provider transaction failed %!STATUS!", status);

			break;
		}

	} while (0);

	if (status)
	{
		FwpmTransactionAbort(sessionHandle);

	}

	return status;
}

NTSTATUS deleteSublayerByKey(const GUID* key, HANDLE sessionHandle)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = FwpmTransactionBegin(sessionHandle, 0);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"begin transaction failed %!STATUS!", status);

		return status;
	}

	do
	{
		status = FwpmSubLayerDeleteByKey(sessionHandle, key);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"delete sublayer by key failed %!STATUS!", status);

			break;
		}

		status = FwpmTransactionCommit(sessionHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"commit tranaction failed %!STATUS!", status);

			break;
		}

	} while (0);

	if (status)
	{
		FwpmTransactionAbort(sessionHandle);
	}

	return status;
}

NTSTATUS deleteFilterByKey(const GUID* filterKey, HANDLE sessionHandle)
{
	NTSTATUS status = STATUS_SUCCESS;

	status = FwpmTransactionBegin(sessionHandle, 0);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"begin transaction failed %!STATUS!", status);

		return status;
	}

	do
	{
		status = FwpmFilterDeleteByKey(sessionHandle, filterKey);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"delete filter by key failed %!STATUS!", status);

			break;
		}

		status = FwpmTransactionCommit(sessionHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"commit tranaction failed %!STATUS!", status);

			break;
		}
	} while (0);

	if (status)
	{
		FwpmTransactionAbort(sessionHandle);
	}

	return status;
}

NTSTATUS clearFilterConfigBySubLayer(const GUID* sublayKey, const GUID* providerKey, HANDLE sessionHandle)
{
	HANDLE enumHandle;
	NTSTATUS status = STATUS_SUCCESS;
	UINT32  numEntriesRequested = 40;
	UINT32  numEntriesReturned = 40;
	FWPM_FILTER0** matchingFwpFilter = NULL;
	FWPM_FILTER_ENUM_TEMPLATE filterTemplate;
	const GUID *array[] = {
		&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		&FWPM_LAYER_ALE_CONNECT_REDIRECT_V4,
		&FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
		&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		&FWPM_LAYER_OUTBOUND_TRANSPORT_V4,
		&FWPM_LAYER_INBOUND_IPPACKET_V4,
		&FWPM_LAYER_OUTBOUND_IPPACKET_V4
	};

	for (int index = 0; index < sizeof(array) / sizeof(GUID *); index++)
	{
		RtlZeroMemory(&filterTemplate, sizeof(FWPM_FILTER_ENUM_TEMPLATE));
		filterTemplate.actionMask = MAXUINT32;
		filterTemplate.enumType = FWP_FILTER_ENUM_OVERLAPPING;
		filterTemplate.flags = FWP_FILTER_ENUM_FLAG_SORTED;
		filterTemplate.providerKey = (GUID *)providerKey;
		filterTemplate.layerKey = *array[index];
		status = FwpmFilterCreateEnumHandle0(sessionHandle, &filterTemplate, &enumHandle);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"create filter enum handle failed %!STATUS!", status);

			return status;
		}
		//reset ״̬
		numEntriesRequested = 40;
		numEntriesReturned = 40;

		while (numEntriesRequested == numEntriesReturned)
		{

			status = FwpmFilterEnum(sessionHandle, enumHandle, numEntriesRequested, &matchingFwpFilter, &numEntriesReturned);
			if (!NT_SUCCESS(status))
			{
				DoTraceMessage(TRACE_ERROR, L"enum filter number failed %!STATUS!", status);

				break;
			}

			if (matchingFwpFilter)
			{
				for (UINT32 index = 0; index < numEntriesReturned; index++)
				{
					if (!memcmp(&(matchingFwpFilter[index]->subLayerKey), sublayKey, sizeof(GUID)))
					{
						status = deleteFilterByKey(&matchingFwpFilter[index]->filterKey, sessionHandle);
						if (NT_SUCCESS(status))
						{
							DoTraceMessage(TRACE_ERROR, L"delete filter display name success %S", matchingFwpFilter[index]->displayData.name);
						}
						else
						{
							DoTraceMessage(TRACE_ERROR, L"delete filter display name failed %S , error number %!STATUS!", matchingFwpFilter[index]->displayData.name, status);
						}
					}
				}

				FwpmFreeMemory0((void **)&matchingFwpFilter);

				matchingFwpFilter = NULL;
			}

		};


		FwpmFilterDestroyEnumHandle(sessionHandle, enumHandle);
	}

	return status;
}

VOID clearFilter()
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE sessionHandle = openFilterManagerSession(KENERL_FILTER_SESSION_NAME);
	if (NULL == sessionHandle)
	{
		DoTraceMessage(TRACE_ERROR, L"open session handle failed");

		return;
	}

	status = clearFilterConfigBySubLayer(&QEEYOU_FILTER_SUBLAYER, &QEEYOU_FILTER_PROVIDER, sessionHandle);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"clear filter failed %!STATUS!", status);
	}

	closeFilterManagerSession(sessionHandle);
}

VOID clearAllFilter()
{
	NTSTATUS status = STATUS_SUCCESS;
	HANDLE sessionHandle = openFilterManagerSession(KENERL_FILTER_SESSION_NAME);
	if (NULL == sessionHandle)
	{
		DoTraceMessage(TRACE_ERROR, L"open session handle failed");

		return;
	}

	status = clearFilterConfigBySubLayer(&QEEYOU_FILTER_SUBLAYER, &QEEYOU_FILTER_PROVIDER, sessionHandle);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"clear filter failed %!STATUS!", status);
	}

	status = deleteSublayerByKey(&QEEYOU_FILTER_SUBLAYER, sessionHandle);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"clear sublayer  failed %!STATUS!", status);
	}

	status = deleteProviderByKey(&QEEYOU_FILTER_PROVIDER, sessionHandle);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, L"clear provider  failed %!STATUS!", status);
	}

	closeFilterManagerSession(sessionHandle);
}