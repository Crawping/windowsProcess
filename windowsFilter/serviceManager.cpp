#include <windows.h>
#include <winsvc.h>
#include <iostream>
#include <filesystem>

#include "serviceManager.h"

#include "QeeYouWfpLogger.h"

namespace Service{

	bool checkServiceExist(const std::wstring &serviceName)
	{
		bool result = false;
		SC_HANDLE scManager	= nullptr;
		SC_HANDLE scService		= nullptr;

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); 
		if (nullptr == scManager)
		{
			LOGINFO("open service manager failed");
		}
		else
		{
			scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
			if (nullptr == scService)
			{
				LOGINFO("open service name failed reason %u", GetLastError());

				CloseServiceHandle(scManager);
			}
			else
			{
				result = true;

				CloseServiceHandle(scManager);
				CloseServiceHandle(scService);
			}

		}

		return result;
	}

	bool checkServiceIsRuning(const std::wstring &serviceName)
	{
		bool result = true;
		BOOL returnValue = FALSE;
		SC_HANDLE scManager = nullptr;
		SC_HANDLE scService = nullptr;
		SERVICE_STATUS serviceStatus = { 0 };

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (nullptr == scManager)
		{
			LOGINFO("open service manager failed");

			result = false;
		}

		scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
		if (nullptr == scService)
		{
			LOGINFO("open service name failed reason %u", GetLastError());

			CloseServiceHandle(scManager);

			result = false;

			return result;
		}

		returnValue = QueryServiceStatus(scService, &serviceStatus);
		if (!returnValue)
		{
			LOGINFO("query service failed errno number %u", GetLastError());

			result = false;
				
			CloseServiceHandle(scManager);
			CloseServiceHandle(scService);

			return result;
		}

		CloseServiceHandle(scManager);
		CloseServiceHandle(scService);

		if (SERVICE_RUNNING == serviceStatus.dwCurrentState)
		{
			result = true;
		}
		else
		{
			result = false;
		}


		return result;
	}

	bool is64BitSystem()
	{
		bool result = false;
		BOOL isWow64 = FALSE;

		if (sizeof(VOID *) == sizeof(UINT64))
		{
			result = true;
		}
		else
		{
			if (IsWow64Process(GetCurrentProcess(), &isWow64))
			{
				result = isWow64 ? true: false;
			}
		}

		return result;
	}

	bool startService(const std::wstring &serviceName)
	{
		bool result = true;
		SC_HANDLE scManager = nullptr;
		SC_HANDLE scService = nullptr;

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (nullptr == scManager)
		{
			LOGINFO("open service manager failed");

			result = false;
		}


			scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
			if (nullptr == scService)
			{
				LOGINFO("open service failed error number %u", GetLastError());

				CloseServiceHandle(scManager);

				result = false;

			}
			else
			{
				if (!StartService(scService, 0, NULL))
				{
					LOGINFO("start service failed error number %u", GetLastError());

					result = false;
				}

				CloseServiceHandle(scManager);
				CloseServiceHandle(scService);
			}


		return result;
	}

	bool stopService(const std::wstring &serviceName)
	{
		bool result = true;
		BOOL returnValue = FALSE;
		SC_HANDLE scManager	= nullptr;
		SC_HANDLE scService		= nullptr;
		SERVICE_STATUS_PROCESS ssp = { 0 };
		SERVICE_STATUS serviceStatus = { 0 };

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (nullptr == scManager)
		{
			LOGINFO("open service manager failed");

			result = false;
		}

		scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
		if (nullptr == scService)
		{
			LOGINFO("open service failed error number %u", GetLastError());

			CloseServiceHandle(scManager);

			result = false;
		}

		returnValue = QueryServiceStatus(scService, &serviceStatus);
		if (!returnValue)
		{
			LOGINFO("query service failed return value: %u", GetLastError());
		}
		else
		{
			if (SERVICE_STOPPED == serviceStatus.dwCurrentState)
			{
				result = true;
			}
			else
			{
				if (ControlService(scService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
				{
					result = true;

				}
				else
				{
					LOGINFO("stop service failed result %u", GetLastError());

					result = false;
				}
			}
		}

		CloseServiceHandle(scManager);
		CloseServiceHandle(scService);


		return result;
	}

	bool serviceInstall(const std::wstring &serviceName, const std::wstring &kenerlDriverFile)
	{
		bool result = true;
		SC_HANDLE scManager = nullptr;
		SC_HANDLE scService = nullptr;

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (nullptr == scManager)
		{
			LOGINFO("open service manager failed");

			result = false;
		}

		scService = CreateService( 
							scManager,
							serviceName.c_str(),
							serviceName.c_str(),
							SERVICE_ALL_ACCESS,
							SERVICE_KERNEL_DRIVER,
							SERVICE_DEMAND_START, 
							SERVICE_ERROR_NORMAL,
							kenerlDriverFile.c_str(),
							NULL, 
							NULL,
							NULL,
							NULL,
							NULL); 
		if (NULL == scService)
		{
			LOGINFO("create service handle failed result %u", GetLastError());

			result = false;

			CloseServiceHandle(scManager);
		}
		else
		{
			CloseServiceHandle(scManager);
			CloseServiceHandle(scService);
		}


		return result;
	}

	bool serviceUninstall(const std::wstring &serviceName)
	{
		bool result = true;
		SC_HANDLE scManager = nullptr;
		SC_HANDLE scService = nullptr;

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (nullptr == scManager)
		{
			LOGINFO("open service manager failed");

			result = false;
		}

		scService = OpenService(scManager, serviceName.c_str(), DELETE);
		if (nullptr == scService)
		{
			LOGINFO("open service failed result %u", GetLastError());

			result = false;

			CloseServiceHandle(scManager);
		}
		else
		{
			if (!DeleteService(scService))
			{
				LOGINFO("delete service failed result %u", GetLastError());

				result = false;
			}

			CloseServiceHandle(scManager);
			CloseServiceHandle(scService);
		}

		return result;
	}
}