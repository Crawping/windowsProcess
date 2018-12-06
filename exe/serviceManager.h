#ifndef SERVICEMANAGER_H
#define SERVICEMANAGER_H

#include <string>

namespace Service{

	bool is64BitSystem();

	bool startService(const std::wstring &serviceName);
	bool stopService(const std::wstring &serviceName);

	bool checkServiceExist(const std::wstring &serviceName);
	bool checkServiceIsRuning(const std::wstring &serviceName);

	bool serviceUninstall(const std::wstring &serviceName);
	bool serviceInstall(const std::wstring &serviceName, const std::wstring &kenerlDriverFile);
};

#endif