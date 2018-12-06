#ifndef FILTERMANAGER_H
#define FILTERMANAGER_H

#include <fwpmu.h>
#include <string.h>

class filterManager{

public:
	static filterManager& getInstance();
	~filterManager();

/*
* modify filter weight
* add sublayer to the filter
* 
*/

	DWORD addFilter(FWPM_FILTER *filter);
	DWORD deleteFilter(const GUID* filterKey);
	DWORD addProvider(const GUID* key, const std::wstring &providerName);
	DWORD addSublayer(const GUID* key, const std::wstring &sublayerName);
	DWORD deleteProvider(const GUID* key);
	DWORD deleteSublayer(const GUID* key);

	DWORD clearFilterConfig();

	/*
	* get filter blob from filename
	* caller need to release application blob block
	*/
	bool getAppIdFromPath(const std::wstring &fileName, FWP_BYTE_BLOB **appId);

	void deinitialize();

protected:
	filterManager(const filterManager& filterHandle);
	filterManager& operator=(const filterManager &filterHandle);

	filterManager();
	void initialManager();
	void deinitialManager();

private:
	GUID* m_providerKey;
	GUID m_sublayerKey;
	HANDLE m_engineHandle;
	FWPM_SESSION m_session;
};

#endif