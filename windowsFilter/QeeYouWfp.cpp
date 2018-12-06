#include "QeeYouWfp.h"
#include "QeeYouWfpClientWrapper.h"
#include "QeeYouWfpLogger.h"
//QeeYouVpnClientWraper m_QeeYouVpnClientWraper;

void* QeeYouWfp_Init(const std::wstring &kenerlFile, QeeYouWfpLogHandle handle)
{
	LOG::setLogHandle(handle);
	return new QeeYouWfpClientWraper(kenerlFile);
}
void  QeeYouWfp_Deinit(void* param)
{
	LOG::clearLogHandle();
	if (param != NULL) {
		delete reinterpret_cast<QeeYouWfpClientWraper*>(param);
	}
}

void addFilter(void* param, std::vector<std::wstring>& processfileter, void* fQeeYouOpenVpnClientEventCallback, unsigned long dwUser, unsigned int eventId, int mode)
{
	QeeYouWfpClientWraper* client = (QeeYouWfpClientWraper*)param;
	client->addProcessFilter(processfileter, fQeeYouOpenVpnClientEventCallback, dwUser, eventId, mode);
}

void StartQeeYouWfpClient(std::string config_text, std::string username, std::string password, void* fQeeYouOpenVpnClientEventCallback, unsigned long dwUser, void* param, unsigned int eventId, int mode)
{
	if (param != NULL)
	{
		QeeYouWfpClientWraper* client = (QeeYouWfpClientWraper*)param;
		client->setParame(config_text, username, password, fQeeYouOpenVpnClientEventCallback, dwUser, eventId, mode);
	}
	else
	{
		printf("empty\n");
	}
}

void StopQeeYouWfpClient(void* param)
{
	if (param != NULL)
	{
		QeeYouWfpClientWraper* client = (QeeYouWfpClientWraper*)param;
		client->stopVPN();
	}
}


QeeYouVpnConnectionInfo GetQeeYouWfpConnectionInfo(void* param)
{
	if (param != NULL)
	{
		QeeYouWfpClientWraper* client = (QeeYouWfpClientWraper*)param;
		return client->get_connectionInfo();
	}
	else
	{
		QeeYouVpnConnectionInfo ret;
		return ret;
	}
}

bool checkQeeYouWfpOnline(void* param)
{
	if (param != NULL)
	{
		QeeYouWfpClientWraper* client = (QeeYouWfpClientWraper*)param;
		return client->checkOnline();
	}
	else
	{
		return false;
	}
}