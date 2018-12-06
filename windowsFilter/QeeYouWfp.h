#ifndef QEEYOUWFP_H
#define QEEYOUWFP_H

#include <string>
#include <iostream>
#include <stdlib.h> // for atoi
#include <stdio.h>
#include "comment.h"
#include <vector>

typedef void(*QeeYouWfpLogHandle)(
	const std::string& message
	);

void* QeeYouWfp_Init(const std::wstring &kenerlFile, QeeYouWfpLogHandle handle=nullptr);
void  QeeYouWfp_Deinit(void* param);
void StartQeeYouWfpClient(std::string config_text, std::string username, std::string password, void* fQeeYouEventCallback, unsigned long dwUser,void* param, unsigned int eventId, int mode);

void StopQeeYouWfpClient(void* param);

bool checkQeeYouWfpOnline(void* param);

void addFilter(void* param, std::vector<std::wstring>& processfileter, void* fQeeYouEventCallback, unsigned long dwUser,unsigned int eventId, int mode);

QeeYouVpnConnectionInfo GetQeeYouWfpConnectionInfo(void* param);

#endif
