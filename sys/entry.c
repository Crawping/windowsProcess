#include "macroDefine.h"


#include <ndis.h>
#include <ntddk.h>
#include <wdf.h>

#include "entry.tmh"


#include "common.h"
#include "fileOperation.h"
#include "filterCallout.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD QeeYouDriverUnload;

extern VOID QeeYouDriverUnload(_In_ WDFDRIVER Driver);
extern NTSTATUS QeeYouInitDevice(_In_ DRIVER_OBJECT* driverObject, _In_ UNICODE_STRING* registryPath);

NTSTATUS DriverEntry(_In_ DRIVER_OBJECT* driverObject, _In_ UNICODE_STRING* registryPath)
{

	NTSTATUS status = STATUS_SUCCESS;

	wppInitial(driverObject, registryPath);

	DoTraceMessage(TRACE_INIT, L"enter dirver entry version %S%S", PACKAGE_NAME, PACKAGE_VERSION);

	status = QeeYouInitDevice(driverObject, registryPath);
	if (!NT_SUCCESS(status))
	{
		DoTraceMessage(TRACE_ERROR, "init driver failed");
	}
	else
	{

	}

	return status;
}


NTSTATUS QeeYouInitDevice(_In_ DRIVER_OBJECT* driverObject, _In_ UNICODE_STRING* registryPath)
{
	WDFDRIVER driver = { 0 };
	WDFDEVICE device = { 0 };
	WDFQUEUE queue = { 0 };
	NTSTATUS status = STATUS_SUCCESS;
	PWDFDEVICE_INIT pdeviceInit = NULL;
	WDF_DRIVER_CONFIG config = {0};
	WDF_FILEOBJECT_CONFIG fileConfig = {0};
	WDF_OBJECT_ATTRIBUTES  requestAttributes = {0};
	WDF_OBJECT_ATTRIBUTES objAttributes = {0};
	WDF_IO_QUEUE_CONFIG queueConfig = {0};

	DoTraceMessage(TRACE_INIT, "enter initial device");
	do
	{
		// Request NX Non-Paged Pool when available
		ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
		//config myself as an non-pnp device
		WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
		config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
		config.EvtDriverUnload = QeeYouDriverUnload;
		status = WdfDriverCreate(
			driverObject,
			registryPath,
			WDF_NO_OBJECT_ATTRIBUTES,
			&config,
			&driver
			);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "driver create failed %!STATUS!", status);

			break;
		}

		//allocate init device struct
		DECLARE_CONST_UNICODE_STRING(deviceName, SYS_SYMBLE_NAME);
		DECLARE_CONST_UNICODE_STRING(symbolicName, SYS_DEVICE_NAME);
		pdeviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
		if (NULL == pdeviceInit)
		{
			DoTraceMessage(TRACE_ERROR, "allocate device init failed");

			status = STATUS_INSUFFICIENT_RESOURCES;

			break;
		}
		WdfDeviceInitSetDeviceType(pdeviceInit, FILE_DEVICE_NETWORK);
		//network transport without cache buffer
		WdfDeviceInitSetIoType(pdeviceInit, WdfDeviceIoDirect);
		WdfDeviceInitSetCharacteristics(pdeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
		status = WdfDeviceInitAssignName(pdeviceInit, &deviceName);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, L"assign device init name %S failed", SYS_DEVICE_NAME);

			break;
		}

		WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, MyDeviceFileCreate, MyDeviceFileClose, MyDeviceFileCleanup);
		WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&objAttributes, OBJECT_CONTEXT);
		objAttributes.ExecutionLevel = WdfExecutionLevelPassive;
		objAttributes.SynchronizationScope = WdfSynchronizationScopeNone;
		objAttributes.EvtDestroyCallback = MyEvtIoQueueContextDestroy;
		WdfDeviceInitSetFileObjectConfig(pdeviceInit, &fileConfig, &objAttributes);

		//set request attribute
		WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&requestAttributes, REQUEST_CONTEXT);
		WdfDeviceInitSetRequestAttributes(pdeviceInit, &requestAttributes);

		WdfDeviceInitSetIoInCallerContextCallback(pdeviceInit, MyIoPreProcessCallback);

		WDF_OBJECT_ATTRIBUTES_INIT(&objAttributes);
		status = WdfDeviceCreate(&pdeviceInit, &objAttributes, &device);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "create device object failed");

			break;
		}

		status = WdfDeviceCreateSymbolicLink(device, &symbolicName);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "create symbol link failed");

			break;
		}

		// Initialize our queue.
		status = MyQueueInitialize(device);
		if (!NT_SUCCESS(status))
		{
			DoTraceMessage(TRACE_ERROR, "create io queue failed");
			break;
		}


		DoTraceMessage(TRACE_INIT, "initialize callout in the filter callout");

		initCalloutLayer(WdfDeviceWdmGetDeviceObject(device));

		DoTraceMessage(TRACE_INIT, "finish driver initialize");
		
		WdfControlFinishInitializing(device);

	} while (0);

	// If WdfDeviceCreate was successful, it will set pInit to NULL.
	if (NULL != pdeviceInit)
	{
		WdfDeviceInitFree(pdeviceInit);
	}

	return status;
}

VOID QeeYouDriverUnload(_In_ WDFDRIVER Driver)
{
	DRIVER_OBJECT* driverObject = NULL;

	DoTraceMessage(TRACE_SHUTDOWN, "enter driver unload");

	driverObject = WdfDriverWdmGetDriverObject(Driver);

	deInitCalloutLayer();

	wppDeinit(driverObject);

	return ;
}