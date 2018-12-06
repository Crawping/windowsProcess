#ifndef FILEOPERATION_H
#define FILEOPERATION_H

#include "list.h"
#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>
#include "common.h"

// 这个表示数据缓冲区
typedef struct _BYTE_BUFFER {
	// Windows LIST_ENTRY header.
	LIST_ENTRY Entry;

	PVOID DataBuffer;

	size_t DataLength;
} BYTE_BUFFER, *PBYTE_BUFFER;

typedef enum
{
	QEEYOU_CONTEXT_STATE_OPEN = 0xB1,     // Context is open.
	QEEYOU_CONTEXT_STATE_CLOSING = 0xC2,     // Context is closing.
	QEEYOU_CONTEXT_STATE_CLOSED = 0xD3,     // Context is closed.
	QEEYOU_CONTEXT_STATE_INVALID = 0xE4      // Context is invalid.
} CONTEXT_STATE;

#ifndef QEEYOU_MAXWORKERS
#define QEEYOU_MAXWORKERS 4
#endif

//
// This is the context that can be placed per queue
// and would contain per queue information.
//
typedef struct _OBJECT_CONTEXT {

	KSPIN_LOCK lock;                            // Context-wide lock.
    WDFDEVICE device;                           // Context's device.
    WDFFILEOBJECT object;                       // Context's parent object.

	LONGLONG queueOldTime;					//queue data old time (ms)

	UINT64 maxDataQueueLenth;
	// Here we allocate a buffer from a test write so it can be read back
	ListQueue   DataQueue;

	// Read queue.
	WDFQUEUE   ReadQueue;

	CONTEXT_STATE state;

	UINT32 priority;

	UINT8 workIndex;
	WDFWORKITEM workers[QEEYOU_MAXWORKERS];
	
	PVOID pMapMdlAddress;
	PVOID pUserSpaceAddress;

} OBJECT_CONTEXT, *POBJECT_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OBJECT_CONTEXT, ObjectGetContext)

#ifndef WORK_QUEUE_LEN_MAX
#define WORK_QUEUE_LEN_MAX (3000)
#endif

#ifndef PARAM_QUEUE_TIME_DEFAULT
#define PARAM_QUEUE_TIME_DEFAULT    (3000) //1s
#endif

#ifndef QEEYOU_TIMEOUT
#define QEEYOU_TIMEOUT(context, t0, t1)                                  \
    (((t1) >= (t0)? (t1) - (t0): (t0) - (t1)) > (context)->queueOldTime)
#endif 

typedef struct _REQUEST_CONTEXT {
	BOOLEAN isCanceled;
} REQUEST_CONTEXT, *PREQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(REQUEST_CONTEXT, getRequestContext);

PBYTE_BUFFER CreateByteBuffer(PVOID data, size_t length, BOOLEAN copy_memory);
void ReleaseByteBuffer(PBYTE_BUFFER buffer);

NTSTATUS MyQueueInitialize(WDFDEVICE hDevice);

VOID MyIoPreProcessCallback(IN WDFDEVICE device, IN WDFREQUEST request);

VOID MyDeviceFileClose(IN WDFFILEOBJECT object);
VOID MyDeviceFileCleanup(IN WDFFILEOBJECT object);
VOID MyDeviceFileCreate(IN WDFDEVICE device, IN WDFREQUEST request, IN WDFFILEOBJECT object);

//input output operation
VOID MyEvtIoRead(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t Length);
VOID MyEvtIoWrite(IN WDFQUEUE Queue, IN WDFREQUEST Request, IN size_t Length);
VOID MyEvtIoDeviceControl(IN WDFQUEUE queue, IN WDFREQUEST request, IN size_t out_length, IN size_t in_length, IN ULONG code);

VOID MyEvtIoQueueContextDestroy(IN WDFOBJECT object);

void ProcessNextReadRequest(POBJECT_CONTEXT context);

VOID MyEvtIoCanceledOnQueue(IN WDFQUEUE Queue, IN WDFREQUEST Request);

NTSTATUS CopyDataFormWriteRequest(WDFREQUEST request, PVOID *buffer);

#endif