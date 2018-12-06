#ifndef LSIT_H
#define LSIT_H

#include <wdm.h>


typedef struct listQueue{
	//list modification
	UINT32 m_length;
	LIST_ENTRY m_flowListHeader;
	//list lock
	KSPIN_LOCK m_lockContext;
}ListQueue;

extern VOID initListQueue(ListQueue *list);
extern UINT32 listQueueLength(ListQueue *list);
extern BOOLEAN listQueueEmpty(ListQueue *list);
extern LIST_ENTRY* listQueueEraseTail(ListQueue *list);
extern LIST_ENTRY* listQueueEraseHeader(ListQueue *list);
extern VOID listQueuePushBack(ListQueue *list, LIST_ENTRY *entry);
extern VOID listQueuePushFront(ListQueue *list, LIST_ENTRY *entry);
extern BOOLEAN listQueueEraseAt(ListQueue *list, LIST_ENTRY *entry);
extern BOOLEAN listQueueEraseAtWithoutLock(ListQueue *list, LIST_ENTRY *entry);

extern BOOLEAN listQueueEmptyWithoutLock(ListQueue *list);
extern UINT32 listQueueLengthWithoutLock(ListQueue *list);
extern LIST_ENTRY* listQueueEraseHeaderWithoutLock(ListQueue *list);
extern VOID listQueuePushFrontWithoutLock(ListQueue *list, LIST_ENTRY *entry);

#endif