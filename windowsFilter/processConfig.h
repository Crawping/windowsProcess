#ifndef PROCESSCONFIG_H
#define PROCESSCONFIG_H
#include <thread>
#include "comment.h"
#include "QeeYouError.h"
#include "win.h"
#include "comment.h"

#define WINFILTER_DRIVER_FILENAME L"processFilter.sys"
#define WINFILTER_DRIVER_FILENAME_BAK L"processFilter_bak.sys"

class ProcessConfig
{
public:
	ProcessConfig(const std::wstring &serviceName);
	DWORD initFilter();
	void deinitFilter();
	void clearFilterConfig();
	void UninstallService();
	bool installService(const std::wstring &kenerlFile);
	DWORD addFilterToProcess(const std::wstring &fileName);
	static void enumProcess_run(ProcessConfig* pconfig,std::vector<std::wstring> processfileter);
	void setFileterProcess(std::vector<std::wstring> processfileter, void* fEventCallBack, unsigned long dwUser, unsigned int eventId, int mode);
	std::wstring updatekenerlFile(std::wstring winFilterDriverPath);
	std::wstring GetLocalAppDataPath();
	~ProcessConfig();

protected:

private:
	std::wstring m_serviceName;
	std::vector<std::wstring> m_processfileter;
	std::unique_ptr<std::thread> m_scanprocessThread;
	HANDLE m_evHandle;
	QeeYouEventCallback m_EventCallBack_pro;
	unsigned long m_handle_upevent;
	unsigned int m_eventId;
	int m_mode;
};

#endif