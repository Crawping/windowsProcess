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

#ifndef OPENVPN_SERVER_PEERADDR_H
#define OPENVPN_SERVER_PEERADDR_H

#include <cstdint> // for std::uint32_t, uint64_t, etc.

#include <winfilter/common/rc.hpp>
#include <winfilter/common/to_string.hpp>
#include <winfilter/addr/ip.hpp>

namespace winfilter {
  struct AddrPort
  {
    AddrPort() : port(0) {}

    std::string to_string() const
    {
      return addr.to_string_bracket_ipv6() + ':' + openvpn::to_string(port);
    }

    IP::Addr addr;
    std::uint16_t port;
  };

  struct PeerAddr : public RC<thread_unsafe_refcount>
  {
    typedef RCPtr<PeerAddr> Ptr;

    PeerAddr()
      : tcp(false)
    {
    }

    std::string to_string() const
    {
      std::string proto;
      if (tcp)
	proto = "TCP ";
      else
	proto = "UDP ";
      return proto + remote.to_string() + " -> " + local.to_string();
    }

    AddrPort remote;
    AddrPort local;
    bool tcp;
  };
}

#endif
