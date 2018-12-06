#include <iostream>
#include <string.h>
#include <windows.h>
#include <fwpmu.h>
#include <filesystem>
#include <tlhelp32.h>
#include <Psapi.h>

#include "filterManager.h"
#include "processConfig.h"
#include "serviceManager.h"

#include "DriverDefine.h"

#include "customGuiddef.h"

#define INITGUID
#include <guiddef.h>
#include "userGuidDef.h"

#include "QeeYouWfpLogger.h"


ProcessConfig::ProcessConfig(const std::wstring &serviceName) :m_serviceName(serviceName)
{
	m_evHandle = CreateEvent(NULL, TRUE, TRUE, NULL);
	m_scanprocessThread.reset();
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

	std::experimental::filesystem::path file(fileName);
	filterManager& filterHandle = filterManager::getInstance();

	if (!filterHandle.getAppIdFromPath(fileName, &applicationBlob))
	{
		LOGINFO("get application id from filename connect %s failed", file.generic_string().c_str());

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
			LOGINFO("add filter failed result %u filename %s", result, file.generic_string().c_str());

			break;
		}

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
			LOGINFO("add filter failed result %u filename %s", result, file.generic_string().c_str());

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
			LOGINFO("add filter failed result %u filename %s", result, file.generic_string().c_str());

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

	while (Service::checkServiceExist(m_serviceName))
	{
		Sleep(10);
	}
}

bool ProcessConfig::installService(const std::wstring &kenerlFile)
{
	bool result = false;

	std::experimental::filesystem::path file(kenerlFile);

	if (_waccess(kenerlFile.c_str(), 0) == -1)
	{
		LOGINFO("file name %s not exist", file.generic_string().c_str());

		return false;
	}

	//UninstallService();

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
		LOGINFO("add filter provider failed result %u", result);

		return result;
	}

	result = filterHandle.addSublayer(&QEEYOU_FILTER_SUBLAYER, FILTER_SUBLAYER_NAME);
	if (ERROR_SUCCESS != result)
	{
		LOGINFO("add filter sublayer failed result %u", result);

		return result;
	}

	return result;
}

void ProcessConfig::clearFilterConfig()
{
	if (m_scanprocessThread)
	{
		SetEvent(m_evHandle);
		try
		{
			m_scanprocessThread->join();
		}
		catch (...)
		{
		}
		m_scanprocessThread.reset();
	}
	filterManager& filterHandle = filterManager::getInstance();
	filterHandle.clearFilterConfig();
}

void ProcessConfig::deinitFilter()
{

	filterManager& filterHandle = filterManager::getInstance();

	filterHandle.deinitialize();
}

void ProcessConfig::setFileterProcess(std::vector<std::wstring> processfileter, void* fEventCallBack, unsigned long dwUser, unsigned int eventId, int mode)
{
	clearFilterConfig();
	ResetEvent(m_evHandle);
	m_EventCallBack_pro = (QeeYouEventCallback)fEventCallBack;
	m_handle_upevent = dwUser;
	m_eventId = eventId;
	m_mode = mode;
	m_scanprocessThread.reset(new std::thread(enumProcess_run, this, processfileter));
}


void  ProcessConfig::enumProcess_run(ProcessConfig* pconfig, std::vector<std::wstring> processfileter)
{
	ProcessConfig* _pconfig = pconfig;
	std::vector<std::wstring> _processfileter = processfileter;
	do 
	{
		HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (procSnap == INVALID_HANDLE_VALUE)
		{
			LOGINFO("CreateToolhelp32Snapshot failed, %d ", GetLastError());
			return;
		}
		PROCESSENTRY32 procEntry = { 0 };
		procEntry.dwSize = sizeof(PROCESSENTRY32);
		BOOL bRet = Process32First(procSnap, &procEntry);

		while (bRet && (::WaitForSingleObject(_pconfig->m_evHandle, 0) == WAIT_TIMEOUT))
		{
			int index = 0;
			
			for each (std::wstring var in _processfileter)
			{
				if (lstrcmp(procEntry.szExeFile, var.c_str()) == 0)
				{
					HANDLE h_Process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procEntry.th32ProcessID);
					if (h_Process != NULL)
					{
						TCHAR strPath[MAX_PATH];
						DWORD strLength = sizeof(strPath);
						if (QueryFullProcessImageNameW(h_Process, 0, strPath, &strLength))
						{
						
							DWORD re = _pconfig->addFilterToProcess(strPath);

							if (re != ERROR_SUCCESS)
							{
								//添加失败----通知上层
								QeeYouVpnEvent event;
								event.fatal = true;
								event.mode = _pconfig->m_mode;
								event.eventId = _pconfig->m_eventId;
								event.info = "addFilter failed----";
								event.code = ADD_PROCESS_FILTER_ERROR;
								event.name = "DISCONNECTED";
								if (_pconfig->m_EventCallBack_pro)
									_pconfig->m_EventCallBack_pro(event, _pconfig->m_handle_upevent);
								wprintf(L"------------------game over----------------- \n");
								return;

							}
						}
						else
						{
							//添加失败----通知上层
							QeeYouVpnEvent event;
							event.fatal = true;
							event.mode = _pconfig->m_mode;
							event.eventId = _pconfig->m_eventId;
							event.info = "addFilter failed----GetModuleFileNameEx";
							event.code = ADD_PROCESS_FILTER_ERROR;
							event.name = "DISCONNECTED";
							if (_pconfig->m_EventCallBack_pro)
								_pconfig->m_EventCallBack_pro(event, _pconfig->m_handle_upevent);
							return;
						}
					}
					else
					{
						//添加失败----通知上层
						QeeYouVpnEvent event;
						event.fatal = true;
						event.mode = _pconfig->m_mode;
						event.eventId = _pconfig->m_eventId;
						event.info = "addFilter failed----OpenProcess";
						event.code = ADD_PROCESS_FILTER_ERROR;
						event.name = "DISCONNECTED";
						if (_pconfig->m_EventCallBack_pro)
							_pconfig->m_EventCallBack_pro(event, _pconfig->m_handle_upevent);

						LOGINFO("open process failed error number %u", GetLastError());

						return;
					}
					//移除
					std::vector<std::wstring>::iterator del = _processfileter.begin() + index;
					_processfileter.erase(del);
					break;
				}
				index++;
			}
			if (_processfileter.size() == 0) break;
			bRet = Process32Next(procSnap, &procEntry);
		}
		CloseHandle(procSnap);
		/*for each (std::wstring var in _processfileter)
		{
			LOGINFO("_processfileter-----%S", var.c_str());
		}
		wprintf(L"--------------------------------------------------\n");*/
		if (_processfileter.size() == 0)
		{
			LOGINFO("FilterToProcessfile is all successfull");
			return;
		}
	} while (::WaitForSingleObject(_pconfig->m_evHandle, 5000) == WAIT_TIMEOUT);
}

std::wstring ProcessConfig::GetLocalAppDataPath()
{
	wchar_t m_lpszDefaultDir[MAX_PATH];
	wchar_t szDocument[MAX_PATH] = { 0 };
	memset(m_lpszDefaultDir, 0, _MAX_PATH);

	LPITEMIDLIST pidl = NULL;
	SHGetSpecialFolderLocation(NULL, CSIDL_LOCAL_APPDATA, &pidl);
	if (pidl && SHGetPathFromIDList(pidl, szDocument))
	{
		GetShortPathName(szDocument, m_lpszDefaultDir, _MAX_PATH);
	}

	std::wstring wsR = m_lpszDefaultDir;

	return wsR;
}

std::wstring ProcessConfig::updatekenerlFile(std::wstring winFilterDriverPath)
{
	std::wstring updateFilterDrivername = L"";
	std::wstring winFilterDriverFile = winFilterDriverPath + L"\\"+ WINFILTER_DRIVER_FILENAME; 
	std::wstring test = winFilterDriverPath + L"\\" + WINFILTER_DRIVER_FILENAME_BAK;
	std::wstring apppath = GetLocalAppDataPath()+L"\\"+ WINFILTER_DRIVER_FILENAME;
	std::wstring apppathbak = GetLocalAppDataPath() + L"\\" + WINFILTER_DRIVER_FILENAME_BAK;
	DeleteFile(apppathbak.c_str());   //删除上次的

	if (_waccess(apppath.c_str(), 0) == -1)
	{
		//不存在直接拷贝
		if (CopyFile(winFilterDriverFile.c_str(), apppath.c_str(), true))
			updateFilterDrivername = apppath;
	}
	else
	{
		//int tt = _trename(winFilterDriverFile.c_str(), test.c_str());
		//比较是否相同，不相同则拷贝
		HANDLE hFile1 = CreateFile(winFilterDriverFile.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		HANDLE hFile2 = CreateFile(apppath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile1 != INVALID_HANDLE_VALUE && hFile2 != INVALID_HANDLE_VALUE)
		{
			FILETIME fCreateTime1, fAccessTime1, fWriteTime1;
			FILETIME fCreateTime2, fAccessTime2, fWriteTime2;
			bool re1= GetFileTime(hFile1, &fCreateTime1, &fAccessTime1, &fWriteTime1);
			bool re2 = GetFileTime(hFile2, &fCreateTime2, &fAccessTime2, &fWriteTime2);
			CloseHandle(hFile1);
			CloseHandle(hFile2);

			if (fWriteTime1.dwHighDateTime == fWriteTime2.dwHighDateTime && fWriteTime1.dwLowDateTime == fWriteTime2.dwLowDateTime)
			{
				updateFilterDrivername = apppath;
			}
			else
			{
				if (DeleteFile(apppath.c_str()))  //删除成功
				{
					if (CopyFile(winFilterDriverFile.c_str(), apppath.c_str(), true))
						updateFilterDrivername = apppath;
				}
				else
				{
					int errnumber = _trename(apppath.c_str(), apppathbak.c_str());
					if (errnumber==0)  //重命名
					{
						if (CopyFile(winFilterDriverFile.c_str(), apppath.c_str(), true))
							updateFilterDrivername = apppath;
					}
				}
			}
	
		}
	}
	return  updateFilterDrivername;
}
