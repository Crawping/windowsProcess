//    OpenVPN -- An application to securely tunnel IP networks
//               over a single port, with support for SSL/TLS-based
//               session authentication and key exchange,
//               packet encryption, packet authentication, and
//               packet compression.
//
//    Copyright (C) 2012-2017 OpenVPN Technologies, Inc.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License Version 3
//    as published by the Free Software Foundation.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program in the COPYING file.
//    If not, see <http://www.gnu.org/licenses/>.

// define stuff like ntohl, ntohs, htonl, htons, etc. in a platform-independent way

#ifndef OPENVPN_COMMON_SOCKTYPES_H
#define OPENVPN_COMMON_SOCKTYPES_H

#include <winfilter/common/platform.hpp>

#ifdef OPENVPN_PLATFORM_WIN
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#endif // OPENVPN_COMMON_SOCKTYPES_H