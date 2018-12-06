#include <iostream>
#include <string.h>
#include <windows.h>
#include <fwpmu.h>


#include "filterManager.h"
#include "processConfig.h"
#include "serviceManager.h"

#include "sys/macroDefine.h"

#include "sys/customGuiddef.h"

#define INITGUID
#include <guiddef.h>
#include "userGuidDef.h"


ProcessConfig::ProcessConfig(const std::wstring &serviceName) :m_serviceName(serviceName)
{

}

ProcessConfig::~ProcessConfig()
{

} 

DWORD ProcessConfig::addFilterToProcess(const std::wstring &fileName)
{
	DWORD result = ERROR_SUCCESS;
	FWPM_FILTER filter = { 0 };
	FWP_BYTE_BLOB* applicationBlob = nullptr;
	FWPM_FILTER_CONDITION filterConditions[2] = { 0 };
	filterManager& filterHandle = filterManager::getInstance();

	if (!filterHandle.getAppIdFromPath(fileName, &applicationBlob))
	{
		std::wcout << L"connect get application id from filename" << fileName << L"failed" << std::endl;

		return ERROR_WRITE_FAULT;
	}

	do
	{
		filter.weight.type = FWP_EMPTY;
		filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		filter.displayData.name = (WCHAR *)fileName.c_str();
		filter.displayData.description = (WCHAR *)fileName.c_str();
		filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
		filter.action.calloutKey = QEEYOU_FILTER_CONNECT_CALLOUT;
		filter.numFilterConditions = 1;
		filter.filterCondition = filterConditions;

		filterConditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
		filterConditions[0].matchType = FWP_MATCH_EQUAL;
		filterConditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
		filterConditions[0].conditionValue.byteBlob = applicationBlob;

		result = filterHandle.addFilter(&filter);
		if (ERROR_SUCCESS != result)
		{
			std::wcout << L"add filter failed result" << result << L"name" << fileName << std::endl;

			break;
		}

		std::cout.precision(2);
		std::cout  << std::hex << (UINT32)applicationBlob->data[applicationBlob->size - 1] << (UINT32)applicationBlob->data[0] << (UINT32)applicationBlob->data[applicationBlob->size / 2] << std::endl;

		RtlZeroMemory(&filter, sizeof(FWPM_FILTER));

		filter.weight.type = FWP_EMPTY;
		filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
		filter.displayData.name = (WCHAR *)fileName.c_str();
		filter.displayData.description = (WCHAR *)fileName.c_str();
		filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
		filter.action.calloutKey = QEEYOU_FILTER_CONNECT_DNS_LAYER;
		filter.numFilterConditions = 1;
		filter.filterCondition = filterConditions;

		filterConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
		filterConditions[0].matchType = FWP_MATCH_EQUAL;
		filterConditions[0].conditionValue.type = FWP_UINT16;
		filterConditions[0].conditionValue.uint16 = 53;


		result = filterHandle.addFilter(&filter);
		if (ERROR_SUCCESS != result)
		{
			std::wcout << L"add filter failed result" << result << L"name" << fileName << std::endl;

			break;
		}

		RtlZeroMemory(&filter, sizeof(FWPM_FILTER));

		filter.weight.type = FWP_EMPTY;
		filter.displayData.name = (WCHAR *)fileName.c_str();
		filter.displayData.description = (WCHAR *)fileName.c_str();
		filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
		filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
		filter.action.calloutKey = QEEYOU_FILTER_TRANS_CALLOUT;
		filter.numFilterConditions = 0;
		result = filterHandle.addFilter(&filter);
		if (ERROR_SUCCESS != result)
		{
			std::wcout << L"add filter failed result" << result << L"name" << fileName << std::endl;

			break;
		}

	} while (0);

	if (applicationBlob)
	{
		FwpmFreeMemory((void**)&applicationBlob);

		applicationBlob = NULL;
	}

	return result;
}

void ProcessConfig::UninstallService()
{

	if (Service::checkServiceExist(m_serviceName))
	{
		if (Service::checkServiceIsRuning(m_serviceName))
		{
			Service::stopService(m_serviceName);
		}
	}

	Service::serviceUninstall(m_serviceName);
}

bool ProcessConfig::installService(const std::wstring &kenerlFile)
{
	bool result = false;

	if (_waccess(kenerlFile.c_str(), 0) == -1)
	{
		std::wcout << L"file name" << kenerlFile << L"not exist" << std::endl;

		return false;
	}

	UninstallService();

	Service::serviceInstall(m_serviceName, kenerlFile);

	Service::startService(m_serviceName);

	result = Service::checkServiceIsRuning(m_serviceName);

	return result;
}

DWORD ProcessConfig::initFilter()
{
	DWORD result = ERROR_SUCCESS;
	filterManager& filterHandle = filterManager::getInstance();

	result = filterHandle.addProvider(&QEEYOU_FILTER_PROVIDER, FILTER_PROVIDER_NAME);
	if (ERROR_SUCCESS != result)
	{
		std::cout << "add filter provider failed result " << result << std::endl;

		return result;
	}

	result = filterHandle.addSublayer(&QEEYOU_FILTER_SUBLAYER, FILTER_SUBLAYER_NAME);
	if (ERROR_SUCCESS != result)
	{
		std::cout << "add filter sublayer failed result " << result << std::endl;

		return result;
	}

	return result;
}

void ProcessConfig::deinitFilter()
{

	filterManager& filterHandle = filterManager::getInstance();

	filterHandle.deinitialize();
}