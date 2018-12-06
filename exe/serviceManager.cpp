#include <windows.h>
#include <winsvc.h>
#include <iostream>

#include "serviceManager.h"

namespace Service{

	bool checkServiceExist(const std::wstring &serviceName)
	{
		bool result = false;
		SC_HANDLE scManager	= nullptr;
		SC_HANDLE scService		= nullptr;

		scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS); 
		if (nullptr == scManager)
		{
			std::cout << "open service manager failed" << std::endl;
		}
		else
		{
			scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
			if (nullptr == scService)
			{
				std::cout << "open service name failed reason " << GetLastError() << std::endl;

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
			std::cout << "open service manager failed" << std::endl;

			result = false;
		}

		scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
		if (nullptr == scService)
		{
			std::cout << "open service name failed reason " << GetLastError() << std::endl;

			CloseServiceHandle(scManager);

			result = false;

			return result;
		}

		returnValue = QueryServiceStatus(scService, &serviceStatus);
		if (!returnValue)
		{
			std::cout << "query service failed errno number" << GetLastError() << std::endl;

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
			std::cout << "open service manager failed" << std::endl;

			result = false;
		}


			scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
			if (nullptr == scService)
			{
				std::cout << "open service failed error number" << GetLastError() << std::endl;

				CloseServiceHandle(scManager);

				result = false;

			}
			else
			{
				if (!StartService(scService, 0, NULL))
				{
					std::cout << "start service failed error number" << GetLastError() << std::endl;

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
			std::cout << "open service manager failed" << std::endl;

			result = false;
		}

		scService = OpenService(scManager, serviceName.c_str(), SERVICE_ALL_ACCESS);
		if (nullptr == scService)
		{
			std::cout << "open service failed error number" << GetLastError() << std::endl;

			CloseServiceHandle(scManager);

			result = false;
		}

		returnValue = QueryServiceStatus(scService, &serviceStatus);
		if (!returnValue)
		{
			std::cout << "query service failed return value:" << GetLastError() << std::endl;
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
					std::cout << "stop service failed result" << GetLastError() << std::endl;

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
			std::cout << "open service manager failed" << std::endl;

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
			std::cout << "create service handle failed result" << GetLastError() << std::endl;

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
			std::cout << "open service manager failed" << std::endl;

			result = false;
		}

		scService = OpenService(scManager, serviceName.c_str(), DELETE);
		if (nullptr == scService)
		{
			std::cout << "open service failed result " << GetLastError()  << std::endl;

			result = false;

			CloseServiceHandle(scManager);
		}
		else
		{
			if (!DeleteService(scService))
			{
				std::cout << "delete service failed result" << GetLastError() << std::endl;

				result = false;
			}

			CloseServiceHandle(scManager);
			CloseServiceHandle(scService);
		}

		return result;
	}
}