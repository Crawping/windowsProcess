#ifndef QUEYOUWFPCLIENTWRAPPER_H
#define QUEYOUWFPCLIENTWRAPPER_H


#include <stdlib.h> // for atoi
#include <stdio.h>
#include <string>
#include <iostream>
#include <thread>
#include <memory>
#include <mutex>
#include <atomic>
#include <winfilter/common/platform.hpp>

// don't export core symbols
#define OPENVPN_CORE_API_VISIBILITY_HIDDEN

// should be included before other openvpn includes,
// with the exception of openvpn/log includes
#include <client/ovpncli.hpp>

#ifndef OPENVPN_LOG
// log thread settings
#define OPENVPN_LOG_CLASS winfilter::ClientAPI::LogReceiver
#define OPENVPN_LOG_INFO  winfilter::ClientAPI::LogInfo
#include <winfilter/log/logthread.hpp>    // should be included early
#endif

#include <winfilter/common/exception.hpp>
#include <winfilter/common/string.hpp>
#include <winfilter/common/signal.hpp>
#include <winfilter/common/file.hpp>
#include <winfilter/common/getopt.hpp>
#include <winfilter/common/getpw.hpp>
#include <winfilter/common/cleanup.hpp>
#include <winfilter/options/merge.hpp>
#include <winfilter/ssl/peerinfo.hpp>
#include <winfilter/ssl/sslchoose.hpp>
#include <winfilter/client/cliopthelper.hpp>
#if defined(USE_MBEDTLS)
#include <winfilter/mbedtls/util/pkcs1.hpp>
#endif

#if defined(OPENVPN_PLATFORM_WIN)
#include <winfilter/win/console.hpp>
#endif

#include "QeeYouWfp.h"
#include "DriverService.h"
#include "processConfig.h"
#include "DriverDefine.h"
#include "QeeYouWfpLogger.h"

class QeeYouWfpClient : public winfilter::ClientAPI::OpenVPNClient
{
public:
	QeeYouWfpClient(int mode, DWORD eventId) :m_fEventCallBack(nullptr), m_isConnected(false)
													,m_mode(mode), m_eventId(eventId), service_(nullptr){
		init_process();
	}
	~QeeYouWfpClient()
	{
		uninit_process();
	}
	void print_stats()
	{
		const int n = stats_n();
		std::vector<long long> stats = stats_bundle();

		std::cout << "STATS:" << std::endl;
		for (int i = 0; i < n; ++i)
		{
			const long long value = stats[i];
			if (value)
				std::cout << "  " << stats_name(i) << " : " << value << std::endl;
		}
	}

public:
	virtual bool socket_protect(int socket) override
	{
		std::cout << "*** socket_protect " << socket << std::endl;
		return true;
	}

	virtual void event(const winfilter::ClientAPI::Event& ev) override
	{
		
		if (m_fEventCallBack)
		{
			QeeYouVpnEvent event;
			event.mode = m_mode;
			event.code = ev.code;
			event.eventId = m_eventId;
			event.error = ev.error;
			event.fatal = ev.fatal;
			event.info = ev.info;
			event.name = ev.name;
			
			//�ײ�����������ɵײ���Լ�����
			if (!ev.name.compare("CONNECTING")&&!m_isConnected)
			{
				m_fEventCallBack(event, m_dwUser);
			}
			else if (!ev.name.compare("CONNECTED")&&!m_isConnected)
			{
				m_isConnected = true;
				bool success = StartDriverService();
				if (!success) {
					m_isConnected = false;
					event.name = "DISCONNECTED";
					event.fatal = true;
					event.error = true;
					event.code = PROCESS_SERVER_INSTALL_FAILED;
				}
				m_fEventCallBack(event, m_dwUser);
			}
			else if (ev.name.compare("DISCONNECTED") == 0)
			{	//disconnected up load lastest error
				m_fEventCallBack(event, m_dwUser);
			}
			else if(event.fatal)
			{
				m_fEventCallBack(event, m_dwUser);
			}
			else
			{
				std::string message = "receive event " + event.name + "but not upload";
				LOGINFO("%s", message.c_str());
			}
			
			
		}		
	}

	virtual void log(const winfilter::ClientAPI::LogInfo& log) override
	{
		std::lock_guard<std::mutex> lock(log_mutex);

		LOGINFO("%s",log.text.c_str());
	}

	virtual void clock_tick() override
	{

	}

	virtual void external_pki_cert_request(winfilter::ClientAPI::ExternalPKICertRequest& certreq) override
	{

	}

	virtual void external_pki_sign_request(winfilter::ClientAPI::ExternalPKISignRequest& signreq) override
	{

	}



	virtual bool pause_on_connection_timeout() override
	{
		return false;
	}
	void setEventCallback(void* fEventCallBack, unsigned long dwUser)
	{
		m_fEventCallBack = (QeeYouEventCallback)fEventCallBack;
		m_dwUser = dwUser;
	}

	bool CheckIsConnected()
	{
		return m_isConnected;
	}

	bool StartDriverService()
	{
		service_ = new DriverService(this);
		return service_->Start();
	}

	void StopDriverService()
	{
		if (service_ != nullptr) {
			service_->Stop();
			delete service_;
			service_ = nullptr;
		}
	}
private:
	int m_mode;
	DWORD m_eventId;
	std::mutex log_mutex;
	QeeYouEventCallback m_fEventCallBack;
	unsigned long m_dwUser;
	bool m_isConnected;
	DriverService* service_;
};




class QeeYouWfpClientWraper
{
public:
	enum OptionAction {
		CT_UNDEF,
		CT_SET,
		CT_CONNECT,
		CT_STOP,
	};
public:
	QeeYouWfpClientWraper(const std::wstring &kenerlFile) :
		listenThread_exit(false), wfpConfig(_T(PACKAGE_NAME)),
		m_option(CT_UNDEF)
	{
		wfpConfig.UninstallService();
		m_listenThread.reset(new std::thread(ListenClient, this));
		m_clientThread.reset();
		m_client.reset();
		//驱动文件更新
		m_kenerlFile = wfpConfig.updatekenerlFile(kenerlFile);
		if (m_kenerlFile != L"")
		{
			wfpConfig.installService(m_kenerlFile);
			wfpConfig.initFilter();
		}
	}
public:
	~QeeYouWfpClientWraper()
	{
		StopClientWraper();
		wfpConfig.deinitFilter();
		wfpConfig.UninstallService();
	}

	void StopClientWraper()
	{
		listenThread_exit = true;

		if (m_listenThread) {
			try {
				m_listenThread->join();
			} catch(...) {
			}

			m_listenThread.reset();
		}
	}
	static void ListenClient(QeeYouWfpClientWraper* clientWrapper)
	{
		QeeYouWfpClientWraper* p = clientWrapper;
		if (nullptr == p)
			return;
		while (!p->listenThread_exit)
		{
			switch (p->m_option)
			{
			case QeeYouWfpClientWraper::CT_SET:
				break;
			case QeeYouWfpClientWraper::CT_CONNECT:
			{
				p->connectClient();
				p->m_option = QeeYouWfpClientWraper::CT_UNDEF;
				break;
			}				
			case QeeYouWfpClientWraper::CT_STOP:
			{
				p->deleteClient();
				p->m_option = QeeYouWfpClientWraper::CT_UNDEF;
				break;
			}			
			default:
				break;
			}
			Sleep(10);
		}
		if (p->m_clientThread)
		{
			if(p->m_client)
				p->m_client->stop();
			while (p->m_clientThread->joinable())
			{
				try
				{
					p->m_clientThread->join();
				}
				catch (...)
				{
				}
				p->m_clientThread.reset();
			}
			p->m_client.reset();
		}

	}
	static void ClientOption(QeeYouWfpClientWraper* clientWrapper)
	{
		QeeYouWfpClientWraper* p = clientWrapper;
		if (nullptr == p)
			return;
		try {
			std::cout << "Thread starting..." << std::endl;
			winfilter::ClientAPI::Status connect_status = p->m_client->connect();
			if (connect_status.error)
			{
				std::cout << "connect error: ";
				if (!connect_status.status.empty())
					std::cout << connect_status.status << ": ";
				std::cout << connect_status.message << std::endl;
			}
		}
		catch (const std::exception& e)
		{
			std::cout << "Connect thread exception: " << e.what() << std::endl;
		}
		std::cout << "Thread finished" << std::endl;
	}
	std::string read_profile(const char *fn, const std::string* profile_content,bool &isTrue)
	{
		isTrue = true;
		if (!winfilter::string::strcasecmp(fn, "http") && profile_content && !profile_content->empty())
			return *profile_content;
		else
		{
			winfilter::ProfileMerge pm(fn, "ovpn", "", winfilter::ProfileMerge::FOLLOW_FULL,
				winfilter::ProfileParseLimits::MAX_LINE_SIZE, winfilter::ProfileParseLimits::MAX_PROFILE_SIZE);
			if (pm.status() != winfilter::ProfileMerge::MERGE_SUCCESS)
			{
				isTrue = false;
				printf("merge config error: %s   %s\n", pm.status_string(),pm.error().c_str());
				//OPENVPN_THROW_EXCEPTION("merge config error: " << pm.status_string() << " : " << pm.error());
				
			}
			return pm.profile_content();
		}
	}

	void addProcessFilter(std::vector<std::wstring>& processfileter, void* fEventCallBack,unsigned long dwUser,unsigned int eventId, int mode)
	{
		wfpConfig.setFileterProcess(processfileter, fEventCallBack,dwUser,eventId,mode);
	}

	
	void setParame(std::string config_text, std::string username, std::string password, void* fEventCallBack, unsigned long dwUser, unsigned int eventId, int mode)
	{
		deleteClient();
		m_client.reset(new QeeYouWfpClient(mode, eventId));
		m_client->setEventCallback(fEventCallBack, dwUser);

		bool readFile = true;
		winfilter::ClientAPI::Config config;
		config.content = read_profile(config_text.c_str(), nullptr, readFile);
		if (!readFile)
		{
			m_client->stop();
			QeeYouVpnEvent event;
			event.fatal = true;
			event.mode = mode;
			event.eventId = eventId;
			event.info = "read profile fail";
			event.name = "DISCONNECTED";
			QeeYouEventCallback m_fEventCallBack = (QeeYouEventCallback)fEventCallBack;
			if(m_fEventCallBack)
				m_fEventCallBack(event, dwUser);
			return;
		}
		config.disableClientCert = true;
		winfilter::ClientAPI::EvalConfig eval = m_client->eval_config(config);
		if (eval.error)
		{
			printf("eval config error:%s\n ", eval.message.c_str());
			m_client->stop();
			QeeYouVpnEvent event;
			event.mode = mode;
			event.eventId = eventId;
			event.fatal = true;
			event.info = std::string("eval config error ")+ eval.message.c_str();
			event.name = "DISCONNECTED";
			QeeYouEventCallback m_fEventCallBack = (QeeYouEventCallback)fEventCallBack;
			if (m_fEventCallBack)
				m_fEventCallBack(event, dwUser);
			return;
		}

		winfilter::ClientAPI::ProvideCreds creds;
		creds.username = username;
		creds.password = password;
		creds.replacePasswordWithSessionID = true;
		winfilter::ClientAPI::Status creds_status = m_client->provide_creds(creds);
		if (creds_status.error)
		{
			printf("creds error: %s\n",creds_status.message.c_str());
			m_client->stop();
			QeeYouVpnEvent event;
			event.mode = mode;
			event.eventId = eventId;
			event.fatal = true;
			event.info = std::string("creds error: ") + creds_status.message.c_str();
			event.name = "DISCONNECTED";
			QeeYouEventCallback m_fEventCallBack = (QeeYouEventCallback)fEventCallBack;
			if (m_fEventCallBack)
				m_fEventCallBack(event, dwUser);
			return;
		}
		m_option = CT_CONNECT;
	}
	void stopVPN()
	{
		m_option = CT_STOP;
	}
	bool checkOnline()
	{
		if (m_client)
		{
			return m_client->CheckIsConnected();
		}
		else
		{
			return false;
		}
	}
	QeeYouVpnConnectionInfo get_connectionInfo()
	{
		QeeYouVpnConnectionInfo ret;
		ret.succeeded = false;
		if (m_client)
		{
			if (m_client->CheckIsConnected())
			{
				winfilter::ClientAPI::ConnectionInfo info = m_client->connection_info();
				ret.succeeded = true;
				ret.clientIp = info.clientIp;
				ret.user = info.user;
				ret.serverHost = info.serverHost;
				ret.serverPort = info.serverPort;
				ret.serverProto = info.serverProto;
				ret.vpnIp4 = info.vpnIp4;
				ret.vpnIp6 = info.vpnIp6;
				ret.gw4 = info.gw4;
				ret.gw6 = info.gw6;
				ret.tunName = info.tunName;
			}
		}
		return ret;
	}
private:
	bool connectClient()
	{
		bool ret = stopClient();
		if (ret)
		{
			if (!m_clientThread)
			{
				m_clientThread.reset(new std::thread(ClientOption, this));
			}
		}
		return true;
	}

	bool deleteClient()
	{
		bool ret = stopClient();
		wfpConfig.clearFilterConfig();

		return ret;
	}
	bool stopClient()
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		if (m_clientThread)
		{
			if (m_client)
			{
				m_client->stop();
				m_client->StopDriverService();
			}
			try
			{
				m_clientThread->join();
			}
			catch (...)
			{
			}
			m_clientThread.reset();
		}
		return true;
	}
private:
	OptionAction m_option;
	std::unique_ptr<QeeYouWfpClient> m_client;
	volatile bool listenThread_exit;
	std::unique_ptr<std::thread> m_listenThread;
	std::unique_ptr<std::thread> m_clientThread;
	std::mutex m_mutex;
	std::wstring m_kenerlFile;
	ProcessConfig wfpConfig;

};

#endif
