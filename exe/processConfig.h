#ifndef PROCESSCONFIG_H
#define PROCESSCONFIG_H

class ProcessConfig
{
public:
	ProcessConfig(const std::wstring &serviceName);
	DWORD initFilter();
	void deinitFilter();
	void UninstallService();
	bool installService(const std::wstring &kenerlFile);
	DWORD addFilterToProcess(const std::wstring &fileName);
	~ProcessConfig();

protected:

private:
	std::wstring m_serviceName;
};

#endif