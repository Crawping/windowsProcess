#include <windows.h>
#include "QeeYouWfpLogger.h"

#define MAX_LOG_RECORD_LEN    2048*2

static LOG::LOGHANDLE g_logHandle = nullptr;

void LOG::setLogHandle(LOGHANDLE handle)
{
	if (nullptr != handle)
	{
		g_logHandle = handle;
	}
}

void LOG::clearLogHandle()
{
	g_logHandle = nullptr;
}

void LOG::logInfo(const char* filename, const int lineNo, const char* pchFormat, ...)
{
	char logBuf[MAX_LOG_RECORD_LEN] = { 0 };
	int strLen = 0;
	// 日志信息
	va_list list;
	va_start(list, pchFormat);
	strLen += vsnprintf(logBuf + strLen, MAX_LOG_RECORD_LEN, pchFormat, list);
	va_end(list);
	if (g_logHandle)
	{
		g_logHandle(logBuf);
	}
	else
	{
		printf("%s", logBuf);
	}
}