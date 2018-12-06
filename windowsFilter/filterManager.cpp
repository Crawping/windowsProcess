#include <iostream>
#include <windows.h>
#include <fwpmu.h>
#include "filterManager.h"
#include "DriverDefine.h"

#include "userGuidDef.h"
#include "QeeYouWfpLogger.h"
#include <filesystem>

filterManager& filterManager::getInstance()
{
	static filterManager filterInstance;

	return filterInstance;
}

filterManager::filterManager() :m_engineHandle(0), m_sublayerKey(QEEYOU_FILTER_SUBLAYER)
{
	m_providerKey = const_cast<GUID *>(&QEEYOU_FILTER_PROVIDER);

	initialManager();
}

filterManager::~filterManager()
{
	deinitialManager();
}

filterManager::filterManager(const filterManager& filterHandle)
{
	;
}

filterManager& filterManager::operator= (const filterManager &filterHandle)
{
	return *this;
}

void filterManager::initialManager()
{
	DWORD result = ERROR_SUCCESS;

	RtlZeroMemory(&m_session, sizeof(FWPM_SESSION));
	
	m_session.txnWaitTimeoutInMSec		= INFINITE;
	m_session.displayData.name				= USER_SESSION_NAME;
	m_session.displayData.description		= USER_SESSION_NAME;
	
	result = FwpmEngineOpen(
			NULL,
			RPC_C_AUTHN_DEFAULT,
			NULL,
			&m_session,
			&m_engineHandle
			);

	if (ERROR_SUCCESS != result)
	{
		LOGINFO("open filter engine handle failed result %u", result);
	}
	else
	{
		LOGINFO("open filter engine handle success");
	}
}

void filterManager::deinitialManager()
{
	if (m_engineHandle)
	{
		FwpmEngineClose(m_engineHandle);
	}

	m_engineHandle = nullptr;

	RtlZeroMemory(&m_session, sizeof(FWPM_SESSION));
}

DWORD filterManager::addProvider(const GUID* key, const std::wstring &providerName)
{
	DWORD result = ERROR_SUCCESS;
	FWPM_PROVIDER provider;

	m_providerKey = const_cast<GUID *>(key);

	RtlZeroMemory(&provider, sizeof(FWPM_PROVIDER));

	provider.providerKey = *key;
	provider.displayData.name = (PWSTR)providerName.c_str();
	provider.displayData.description = (PWSTR)providerName.c_str();
	provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

	result = FwpmTransactionBegin(m_engineHandle, 0);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("begin transaction failed result %u", result);

		return result;
	}

	do
	{

		result = FwpmProviderAdd(m_engineHandle, &provider, NULL);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("add provider failed result %u", result);

			break;
		}

		result = FwpmTransactionCommit(m_engineHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("commit  tranaction failed result %u", result);

			break;
		}

	}while(0);

	if (result)
	{
		FwpmTransactionAbort(m_engineHandle);
	}

	return result;
}

DWORD filterManager::addSublayer(const GUID* key, const std::wstring &sublayerName)
{
	DWORD result = ERROR_SUCCESS;
	FWPM_SUBLAYER subLayer;

	RtlZeroMemory(&subLayer, sizeof(FWPM_SUBLAYER));

	m_sublayerKey = *key;

	subLayer.weight = 0x8000;
	subLayer.subLayerKey = m_sublayerKey;
	subLayer.providerKey  = m_providerKey;
	subLayer.displayData.name = (PWSTR)sublayerName.c_str();
	subLayer.displayData.description = (PWSTR)sublayerName.c_str();

	result = FwpmTransactionBegin(m_engineHandle, 0);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("begin transaction failed result %u", result);

		return result;
	}

	do
	{
		result = FwpmSubLayerAdd(m_engineHandle, &subLayer, NULL);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("add sublayer failed result %u", result);

			break;
		}

		result = FwpmTransactionCommit(m_engineHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("add sublayer failed result %u", result);

			break;
		}

	} while (0);

	if (result)
	{
		FwpmTransactionAbort(m_engineHandle);
	}

	return result;
}

DWORD filterManager::deleteProvider(const GUID* key)
{
	DWORD result = ERROR_SUCCESS;

	result = FwpmTransactionBegin(m_engineHandle, 0);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("begin transaction failed result %u", result);

		return result;
	}

	do
	{
		result = FwpmProviderDeleteByKey(m_engineHandle, key);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("delete sublayer failed result %u", result);

			break;
		}

		result = FwpmTransactionCommit(m_engineHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("commit transaction failed result %u", result);

			break;
		}

	} while (0);

	if (result)
	{
		FwpmTransactionAbort(m_engineHandle);
		
		if (FWP_E_PROVIDER_NOT_FOUND == result)
		{
			result = ERROR_SUCCESS;
		}
	}

	return result;
}

DWORD filterManager::deleteSublayer(const GUID* key)
{
	DWORD result = ERROR_SUCCESS;

	result = FwpmTransactionBegin(m_engineHandle, 0);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("begin transaction failed result %u", result);

		return result;
	}

	do
	{
		result = FwpmSubLayerDeleteByKey(m_engineHandle, key);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("delete provider failed result %u", result);

			break;
		}

		result = FwpmTransactionCommit(m_engineHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("commit transaction failed result %u", result);

			break;
		}

	} while (0);

	if (result)
	{
		FwpmTransactionAbort(m_engineHandle);

		if (FWP_E_SUBLAYER_NOT_FOUND == result)
		{
			result = ERROR_SUCCESS;
		}

	}

	return result;
}

DWORD filterManager::addFilter(FWPM_FILTER *filter)
{
	DWORD result = ERROR_SUCCESS;

	filter->providerKey = m_providerKey;
	filter->subLayerKey = m_sublayerKey;
	filter->weight.type = FWP_EMPTY;

	result = FwpmTransactionBegin(m_engineHandle, 0);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("begin transaction failed result %u", result);

		return result;
	}

	do
	{
		result = FwpmFilterAdd(m_engineHandle, filter, NULL, NULL);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("add filter failed result %u", result);

			break;
		}

		result = FwpmTransactionCommit(m_engineHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("commit transaction failed result %u", result);

			break;
		}
	} while (0);

	if (result)
	{
		FwpmTransactionAbort(m_engineHandle);
	}

	return result;
}

DWORD filterManager::deleteFilter(const GUID* filterKey)
{
	DWORD result = ERROR_SUCCESS;

	result = FwpmTransactionBegin(m_engineHandle, 0);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("begin transaction failed result %u", result);

		return result;
	}

	do
	{
		result = FwpmFilterDeleteByKey(m_engineHandle, filterKey);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("delete filter failed result %u", result);

			break;
		}

		result = FwpmTransactionCommit(m_engineHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("commit transaction failed result %u", result);

			break;
		}
	} while (0);

	if (result)
	{
		FwpmTransactionAbort(m_engineHandle);
	}

	return result;
}

bool filterManager::getAppIdFromPath(const std::wstring &fileName, FWP_BYTE_BLOB **appId)
{
	DWORD result = NO_ERROR;
	std::experimental::filesystem::path file(fileName);

	result = ::FwpmGetAppIdFromFileName(fileName.c_str(), appId);

	if (result != NO_ERROR)
	{
		LOGINFO("get appId from file %s failed", file.generic_string().c_str());

		return false;

	}
	else
	{
		LOGINFO("get appId from file %s success", file.generic_string().c_str());

		return true;
	}
}

DWORD filterManager::clearFilterConfig()
{
	HANDLE enumHandle;
	DWORD result = ERROR_SUCCESS;
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
		filterTemplate.providerKey = m_providerKey;
		filterTemplate.layerKey = *array[index];
		result = FwpmFilterCreateEnumHandle0(m_engineHandle, &filterTemplate, &enumHandle);
		if (ERROR_SUCCESS != result)
		{
			LOGINFO("create enumerate handle failed result %u", result);

			return result;
		}
		//reset ״̬
		numEntriesRequested = 40;
		numEntriesReturned = 40;

		while (numEntriesRequested == numEntriesReturned)
		{

			result = FwpmFilterEnum(m_engineHandle, enumHandle, numEntriesRequested, &matchingFwpFilter, &numEntriesReturned);
			if (ERROR_SUCCESS != result)
			{
				LOGINFO("enum filter number failed result %u", result);

				break;
			}

			if (matchingFwpFilter)
			{
				for (UINT32 index = 0; index < numEntriesReturned; index++)
				{
					if (!memcmp(&(matchingFwpFilter[index]->subLayerKey), &m_sublayerKey, sizeof(GUID)))
					{
						std::experimental::filesystem::path name(matchingFwpFilter[index]->displayData.name);
						if (deleteFilter(&matchingFwpFilter[index]->filterKey))
						{
							LOGINFO("delete filter failed filter name %s", name.generic_string().c_str());
						}
						else
						{
							LOGINFO("delete filter success filter name %s", name.generic_string().c_str());
						}
					}
				}

				FwpmFreeMemory0((void **)&matchingFwpFilter);

				matchingFwpFilter = nullptr;
			}

		};


		FwpmFilterDestroyEnumHandle(m_engineHandle, enumHandle);
	}

	return result;
}

void filterManager::deinitialize()
{
	clearFilterConfig();
	deleteSublayer(&m_sublayerKey);
	deleteProvider(m_providerKey);
}