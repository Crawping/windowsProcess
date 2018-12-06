#ifndef MACRODEFINE_H
#define MACRODEFINE_H

#define PACKAGE_NAME L"QeeYouPacket"

#define SYS_SYMBLE_NAME     L"\\??\\"PACKAGE_NAME

#define SYS_DEVICE_NAME   L"\\Device\\"PACKAGE_NAME

#define DOS_NAME   L"\\\\.\\"PACKAGE_NAME

#define PACKAGE_VERSION L"1.0.0"

#define PACKAGE_ALLOCATE_TAG 'QYou'


#define KENERL_SESSION_NAME L"kenerl filter session"

#define KENERL_FILTER_SESSION_NAME L"kenerl clear filter session"

#define USER_SESSION_NAME L"user filter session"

#define FILTER_PROVIDER_NAME L" Provider_"PACKAGE_NAME

#define FILTER_SUBLAYER_NAME L"Sublayer_"PACKAGE_NAME

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID(QeeYouPacket,(e7db16bb, 41be, 4c05, b73e, 5feca06f8207),  \
        WPP_DEFINE_BIT(TRACE_INIT)   \
		WPP_DEFINE_BIT(TRACE_ERROR)   \
		WPP_DEFINE_BIT(TRACE_EVENT) \
        WPP_DEFINE_BIT(TRACE_SHUTDOWN) )

enum IO_CONTROL_TYPE
{
	ALLOCATE_SHARE_MEMORY_T,
	IO_CONTROL_END,
};

#endif