#ifndef QEEYOUWFPLOGGER_H
#define QEEYOUWFPLOGGER_H

#include <string>

namespace LOG
{
	typedef void(*LOGHANDLE)(const std::string& message);

	void setLogHandle(LOGHANDLE handle);
	void clearLogHandle();

	void logInfo(const char* filename, const int lineNo, const char* pchFormat, ...);
}

#ifdef WIN32
#define FILENAME(x) strrchr(x,'\\')?strrchr(x,'\\')+1:x
#else
#define FILENAME(x) strrchr(x,'/')?strrchr(x,'/')+1:x
#endif

#ifndef LOGINFO
#define LOGINFO(format, ...)		LOG::logInfo(FILENAME(__FILE__), __LINE__, format, ##__VA_ARGS__)
#endif

#endif
