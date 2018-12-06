// processFilter.cpp : 定义控制台应用程序的入口点。
//
#include <conio.h>
#include <iostream>
#include <windows.h>

#include "NATService.h"
#include "serviceManager.h"
#include "processConfig.h"
#include "protocolParser.h"
#include "sys/macroDefine.h"

VOID Usage()
{
	std::cout << "[first value]   driver service name" << std::endl;
	std::cout << "[second value]  driver file name" << std::endl;
	std::cout << "[third value] need to filter process name value" << std::endl;
}

typedef struct _OVERLAPPEDEX {
	OVERLAPPED over;
	char buffer[2000];
} OVERLAPPEDEX;

void DoDriverLoop()
{
	std::cout << "=================" << std::endl;
	/*
	auto iocp_handle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (iocp_handle == INVALID_HANDLE_VALUE) {
		std::cout << "CreateIoCompletionPort failed, last error is " << ::GetLastError() << std::endl;
		return;
	}*/

	HANDLE file = ::CreateFile(DOS_NAME, GENERIC_WRITE | GENERIC_READ, 
		0, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		std::cout << "Create File failed, last error is " << ::GetLastError() << std::endl;
		return;
	} else {
		std::cout << "Create file succeed." << std::endl;
	}

	//::CreateIoCompletionPort(file, iocp_handle, NULL, 1);

	BOOL ret = FALSE;

	/*OVERLAPPED overlapped = { 0 };
	DWORD writed_bytes = 0;
	
	ret = ::WriteFile(file, "123456", 6, &writed_bytes, &overlapped);
	if (ret == FALSE) {
		DWORD e = ::GetLastError();
		if (e == ERROR_IO_PENDING) {
			std::cout << "Write File IO Pending" << std::endl;
		}
		else {
			std::cout << "Write File failed, last error is " << ::GetLastError() << std::endl;
		}
	}
	else {
		std::cout << "Write File succeed. buffer: writed bytes is " << writed_bytes << std::endl;
	}*/

	DWORD byteReturn = 0;
	QEEYOU_IO_CONTROLL_S wcontroll = { 0 };
	QEEYOU_IO_CONTROLL_S rcontroll = { 0 };
	rcontroll.totalAllocSize = 8192;
	rcontroll.pUserAddress = NULL;

	if (!::DeviceIoControl(file, ALLOCATE_SHARE_MEMORY_T, &rcontroll, sizeof(QEEYOU_IO_CONTROLL_S), (LPVOID)&wcontroll, sizeof(QEEYOU_IO_CONTROLL_S), &byteReturn, NULL))
	{
		std::cout << "io control file failed" << std::endl;
	}
	else
	{
		std::cout << "puser address " << wcontroll.pUserAddress << std::endl;
	}

	do
	{
		DWORD readed_bytes = 0;
		QEEYOU_RW_S readStruct = { 0 };
		readStruct.index = 1;
		readStruct.sectionSize = 2000;

		DWORD natAddress = 0x5b2832B9;//"185.50.40.91"

		ret = ::ReadFile(file, &readStruct, sizeof(QEEYOU_RW_S), &readed_bytes, NULL);
		if (ret == FALSE) {
			DWORD e = ::GetLastError();
			if (e == ERROR_IO_PENDING) {
				std::cout << "Read File IO Pending" << std::endl;
			}
			else {
				std::cout << "Read File failed, last error is " << ::GetLastError() << std::endl;
			}
		}
		else {
			std::cout << "Read file succeed. buffer: " << readed_bytes << std::endl;
		}

		PACKET_S mypackage = { 0 };
		PPACKET_S package = (PPACKET_S)((PCHAR)wcontroll.pUserAddress + readStruct.index * readStruct.sectionSize);
		mypackage = *package;

		protocolParse parser(package->buff, package->data_len);
		parser.parseProtocol();
		parser.printfProtocol();
		parser.calcPackageCheckSum();
		parser.parseProtocol();
		parser.printfProtocol();
		
		NATService natService;
		natService.SetGatewayIP(natAddress);
		natService.ModifyUploadPacket((uint8_t *)package->buff, package->data_len, package);
		/*
		parser.resetBuffer(package->buff, package->data_len);
		parser.parseProtocol();
		parser.printfProtocol();
		parser.calcPackageCheckSum();
		parser.parseProtocol();
		parser.printfProtocol();*/

		natService.revertPackage((uint8_t *)package->buff, package->data_len);
	/*	parser.resetBuffer(package->buff, package->data_len);
		parser.parseProtocol();
		parser.printfProtocol();
		parser.calcPackageCheckSum();
		parser.parseProtocol();
		parser.printfProtocol();*/


		natService.ModifyDnloadPacket((uint8_t *)package->buff, package->data_len, &mypackage);
	/*	parser.resetBuffer(package->buff, package->data_len);
		parser.parseProtocol();
		parser.printfProtocol();
		parser.calcPackageCheckSum();
		parser.parseProtocol();
		parser.printfProtocol();*/

		natService.revertPackage((uint8_t *)package->buff, package->data_len);
		parser.resetBuffer(package->buff, package->data_len);
		parser.parseProtocol();
		parser.printfProtocol();
		parser.calcPackageCheckSum();
		parser.parseProtocol();
		parser.printfProtocol();

		UINT32 dataLength = GET_PACK_PACKET_LENGTH(parser.getPackageLength(), INJECT_BUFF);
		PINJECT_BUFF injectBuffer = (PINJECT_BUFF) new CHAR[dataLength];
		injectBuffer->Length = parser.getPackageLength();

		memcpy(injectBuffer->buffer, parser.getPackageBuffer(), injectBuffer->Length);

		injectBuffer->PseudoIPChecksum = 1;
		injectBuffer->PseudoTCPChecksum = 1;
		injectBuffer->PseudoUDPChecksum = 1;
		injectBuffer->IfIdx = mypackage.if_idx;
		injectBuffer->SubIfIdx = mypackage.sub_if_idx;
		injectBuffer->Impostor = 0;
		injectBuffer->Loopback = 0;
		injectBuffer->Direction = mypackage.direction;
		injectBuffer->Timestamp = 0;
		
		DWORD writed_bytes = 0;

		std::cout << "write data length :" << injectBuffer->Length << std::endl;
		
		QEEYOU_RW_S writeStruct = { 0 };
		writeStruct.index = 0;
		writeStruct.sectionSize = 2000;
		writeStruct.dataLength = dataLength;

		memcpy((PCHAR)wcontroll.pUserAddress + writeStruct.index * writeStruct.sectionSize, injectBuffer, dataLength);
		
		ret = ::WriteFile(file, &writeStruct, sizeof(QEEYOU_RW_S), &writed_bytes, NULL);
		if (ret == FALSE) {
			DWORD e = ::GetLastError();
			if (e == ERROR_IO_PENDING) {
				std::cout << "Write File IO Pending" << std::endl;
			}
			else {
				std::cout << "Write File failed, last error is " << ::GetLastError() << std::endl;
			}
		}
		else {
			std::cout << "Write File succeed. buffer: writed bytes is " << writed_bytes << "total length :" << dataLength << std::endl;
		}
	} while (true);

	/*
	ULONG_PTR key = 0;
	LPOVERLAPPED over = NULL;
	ret = ::GetQueuedCompletionStatus(iocp_handle, &readed_bytes, &key, &over, INFINITE);
	if (ret == FALSE) {
		std::cout << "GetQueuedCompletionStatus failed, last error is " << ::GetLastError() << std::endl;
	}
	else {
		OVERLAPPEDEX* over_ex = reinterpret_cast<OVERLAPPEDEX*>(over);
		PPACKET_S package = (PPACKET_S)(over_ex->buffer);
		std::cout << "buffer size" << sizeof(PACKET_S) << std::endl;
		std::cout << "total read bytes" << sizeof(PACKET_S) + package->data_len << "total readbytes:" << readed_bytes << std::endl;
		std::cout << "if index:" << package->if_idx << std::endl;
		std::cout << "sub index:" << package->sub_if_idx << std::endl;
		std::cout << "timestamp:" << package->timestamp << std::endl;
		std::cout << "direction:" << package->direction << std::endl;
		std::cout << "data_len:" << package->data_len << std::endl;

		protocolParse parser(package->buff, package->data_len);
		parser.parseProtocol();
		parser.printfProtocol();
		parser.calcPackageCheckSum();
		parser.parseProtocol();
		parser.printfProtocol();
	}*/


	CancelIo(file);

	CloseHandle(file);

	//CloseHandle(iocp_handle);
}

int __cdecl wmain(_In_ int argc, _In_reads_(argc) PCWSTR argv[])
{
	std::locale loc(std::locale(), "", std::locale::ctype);
	std::cout.imbue(loc);
	std::wcout.imbue(loc);
	
	if (argc < 4)
	{
		std::cout << "input argument number " << argc << " illegal" << std::endl;

		Usage();

		::ExitProcess(-1);
	}

	std::wcout << L"input argument number" << argc << std::endl;

	for (int index = 0; index < argc; index++)
	{
		std::wcout << argv[index] << std::endl;
	}

	ProcessConfig config(argv[1]);
	//clear current configuration
	config.deinitFilter();
	config.UninstallService();
	//install new configuration
	config.installService(argv[2]);
	config.initFilter();
	
	for (int index = 3; index < argc; index++)
	{
		config.addFilterToProcess(argv[index]);
	}

	DoDriverLoop();

#pragma prefast(push)
#pragma prefast(disable:6031, "by design the return value of _getch() is ignored here")
	_getch();
#pragma prefast(pop)

	config.deinitFilter();
	config.UninstallService();

	return 0;
}

