#ifndef REQUESTOPERATION_H
#define REQUESTOPERATION_H

VOID initialRequestOp();
VOID cancelRequest(WDFREQUEST Request);
VOID referenceRequestObject(WDFREQUEST Request);
VOID dereferenceRequestObject(WDFREQUEST Request);
BOOLEAN checkRequestIsCanceled(WDFREQUEST Request);
BOOLEAN checkRequestIsCanceledEx(WDFREQUEST Request);
VOID defaultRequestCancelRouting(WDFREQUEST Request);
VOID setRequestCancelable(WDFREQUEST Request, PFN_WDF_REQUEST_CANCEL EvtRequestCancel);
VOID completeRequestWithInformation(WDFREQUEST Request, NTSTATUS Status, ULONG_PTR Information);

#endif