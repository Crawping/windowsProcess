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

// Client tun setup base class for unix

#ifndef OPENVPN_TUN_BUILDER_SETUP_H
#define OPENVPN_TUN_BUILDER_SETUP_H

#ifdef HAVE_JSONCPP
#include "json/json.h"
#endif

#include <winfilter/common/destruct.hpp>
#include <winfilter/common/stop.hpp>
#include <winfilter/tun/builder/capture.hpp>

namespace winfilter {
  namespace TunBuilderSetup {
    struct Config
    {
#ifdef HAVE_JSONCPP
      virtual Json::Value to_json() = 0;
      virtual void from_json(const Json::Value& root, const std::string& title) = 0;
#endif
      virtual ~Config() {}
    };

    struct Base : public DestructorBase
    {
      typedef RCPtr<Base> Ptr;

      virtual int establish(const TunBuilderCapture& pull,
			    Config* config,
			    Stop* stop,
			    std::ostream& os) = 0;
    };

    struct Factory : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Factory> Ptr;

      virtual Base::Ptr new_setup_obj() = 0;
    };
  }
}

#endif
