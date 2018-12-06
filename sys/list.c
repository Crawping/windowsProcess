#include "macroDefine.h"

#include "list.h"


VOID initListQueue(ListQueue *list)
{
	memset(list, 0, sizeof(ListQueue));

	KeInitializeSpinLock(&(list->m_lockContext));

	InitializeListHead(&(list->m_flowListHeader));
}

BOOLEAN listQueueEmpty(ListQueue *list)
{
	BOOLEAN result = FALSE;
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);
	if (IsListEmpty(&(list->m_flowListHeader)))
	{
		result =  TRUE;
	}
	else
	{
		result =  FALSE;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}

BOOLEAN listQueueEmptyWithoutLock(ListQueue *list)
{
	BOOLEAN result = FALSE;
	if (IsListEmpty(&(list->m_flowListHeader)))
	{
		result = TRUE;
	}
	else
	{
		result = FALSE;
	}

	return result;
}

UINT32 listQueueLength(ListQueue *list)
{
	UINT32 length = 0;
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);

	length = list->m_length;

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return length;
}

UINT32 listQueueLengthWithoutLock(ListQueue *list)
{
	UINT32 length = 0;

	length = list->m_length;

	return length;
}

VOID listQueuePushBack(ListQueue *list, LIST_ENTRY *entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);

	if (entry)
	{
		InsertTailList(&(list->m_flowListHeader), entry);

		list->m_length++;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return;
}

VOID listQueuePushFront(ListQueue *list, LIST_ENTRY *entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);

	if (entry)
	{
		InsertHeadList(&(list->m_flowListHeader), entry);

		list->m_length++;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return;
}

VOID listQueuePushFrontWithoutLock(ListQueue *list, LIST_ENTRY *entry)
{
	if (entry)
	{
		InsertHeadList(&(list->m_flowListHeader), entry);

		list->m_length++;
	}

	return;
}

BOOLEAN listQueueEraseAtWithoutLock(ListQueue *list, LIST_ENTRY *entry)
{
	BOOLEAN result = FALSE;
	if (list->m_length)
	{
		if (RemoveEntryList(entry))
		{
			list->m_length--;

			result = TRUE;

		}
	}

	return result;
}

BOOLEAN listQueueEraseAt(ListQueue *list, LIST_ENTRY *entry)
{
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);
	BOOLEAN result = FALSE;
	
	if (list->m_length)
	{
		if (RemoveEntryList(entry))
		{
			list->m_length--;

			result = TRUE;

		}
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return result;
}

LIST_ENTRY* listQueueEraseHeader(ListQueue *list)
{
	LIST_ENTRY* entry = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);

	if (list->m_length)
	{
		entry = RemoveHeadList(&(list->m_flowListHeader));

		list->m_length--;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return entry;
}

LIST_ENTRY* listQueueEraseHeaderWithoutLock(ListQueue *list)
{
	LIST_ENTRY* entry = NULL;
	
	if (list->m_length)
	{
		entry = RemoveHeadList(&(list->m_flowListHeader));

		list->m_length--;
	}

	return entry;
}

LIST_ENTRY* listQueueEraseTail(ListQueue *list)
{
	LIST_ENTRY* entry = NULL;
	KLOCK_QUEUE_HANDLE lockHandle;

	KeAcquireInStackQueuedSpinLock(&(list->m_lockContext), &lockHandle);
	
	if (list->m_length)
	{
		entry = RemoveTailList(&(list->m_flowListHeader));

		list->m_length--;
	}

	KeReleaseInStackQueuedSpinLock(&lockHandle);

	return entry;
}