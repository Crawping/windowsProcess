#ifndef DRIVER_DEFINE_H
#define DRIVER_DEFINE_H

#include <tchar.h>

#define PACKAGE_NAME "QeeYouPacket"

#define SYS_SYMBLE_NAME     _T("\\??\\")PACKAGE_NAME

#define SYS_DEVICE_NAME   _T("\\Device\\")PACKAGE_NAME

#define DOS_NAME   _T("\\\\.\\")PACKAGE_NAME

#define PACKAGE_VERSION _T("1.0.0")

#define PACKAGE_ALLOCATE_TAG 'QYou'


#define KENERL_SESSION_NAME _T("kenerl filter session")

#define USER_SESSION_NAME _T("user filter session")

#define FILTER_PROVIDER_NAME _T(" Provider_")PACKAGE_NAME

#define FILTER_SUBLAYER_NAME _T("Sublayer_")PACKAGE_NAME

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(QeeYouPacket,(e7db16bb, 41be, 4c05, b73e, 5feca06f8207),  \
        WPP_DEFINE_BIT(TRACE_INIT)   \
		WPP_DEFINE_BIT(TRACE_ERROR)   \
		WPP_DEFINE_BIT(TRACE_EVENT) \
        WPP_DEFINE_BIT(TRACE_SHUTDOWN) )

#endif  // DRIVER_DEFINE_H