#ifndef PACKAGEINJECT_H
#define PACKAGEINJECT_H


VOID injectInitial();
VOID injectDeinitial();

/*
* ������Ҫ�������Լ� ��������д���
* �ɹ��������첽���ù��̴�������
*/
PNET_BUFFER_LIST cloneNetBufferList(PNET_BUFFER_LIST netBuffList);
NTSTATUS injectDataInStack(POBJECT_CONTEXT context, WDFREQUEST request);
FWPS_PACKET_INJECTION_STATE getPacketInjectState(PNET_BUFFER_LIST netBuffers, PHANDLE packetPriority);

#endif