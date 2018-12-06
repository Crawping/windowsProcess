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

#ifndef OPENVPN_TRANSPORT_DCO_H
#define OPENVPN_TRANSPORT_DCO_H

#include <string>

#include <winfilter/common/rc.hpp>
#include <winfilter/common/options.hpp>
#include <winfilter/common/stop.hpp>
#include <winfilter/client/remotelist.hpp>
#include <winfilter/frame/frame.hpp>
#include <winfilter/log/sessionstats.hpp>
#include <winfilter/transport/protocol.hpp>
#include <winfilter/transport/client/transbase.hpp>
#include <winfilter/tun/layer.hpp>
#include <winfilter/tun/client/tunbase.hpp>
#include <winfilter/tun/client/tunprop.hpp>

namespace winfilter {
  struct DCO : public virtual RC<thread_unsafe_refcount>
  {
    typedef RCPtr<DCO> Ptr;

    struct TransportConfig
    {
      TransportConfig()
	: server_addr_float(false)
      {
      }

      Protocol protocol;
      RemoteList::Ptr remote_list;
      bool server_addr_float;
      Frame::Ptr frame;
      SessionStats::Ptr stats;
    };

    struct TunConfig
    {
      TunConfig()
      {
      }

      TunProp::Config tun_prop;
      Stop* stop = nullptr;
    };

    virtual TunClientFactory::Ptr new_tun_factory(const TunConfig& conf, const OptionList& opt) = 0;
    virtual TransportClientFactory::Ptr new_transport_factory(const TransportConfig& conf) = 0;
  };
}

#endif
