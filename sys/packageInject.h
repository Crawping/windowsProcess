#ifndef PACKAGEINJECT_H
#define PACKAGEINJECT_H


VOID injectInitial();
VOID injectDeinitial();

/*
* 错误需要调用者自己 对请求进行处理
* 成功过后有异步调用过程处理请求
*/
PNET_BUFFER_LIST cloneNetBufferList(PNET_BUFFER_LIST netBuffList);
NTSTATUS injectDataInStack(POBJECT_CONTEXT context, WDFREQUEST request);
FWPS_PACKET_INJECTION_STATE getPacketInjectState(PNET_BUFFER_LIST netBuffers, PHANDLE packetPriority);

#endif