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

#ifndef OPENVPN_ADDR_ROUTE_H
#define OPENVPN_ADDR_ROUTE_H

#include <string>
#include <sstream>
#include <vector>
#include <cstdint> // for std::uint32_t

#include <winfilter/common/size.hpp>
#include <winfilter/common/exception.hpp>
#include <winfilter/common/number.hpp>
#include <winfilter/common/to_string.hpp>
#include <winfilter/common/split.hpp>
#include <winfilter/common/hash.hpp>
#include <winfilter/addr/ip.hpp>

namespace winfilter {
  namespace IP {
    // Basic route object
    template <typename ADDR>
    struct RouteType
    {
      typedef ADDR Addr;

      ADDR addr;
      unsigned int prefix_len;

      OPENVPN_EXCEPTION(route_error);

      RouteType()
	: prefix_len(0)
      {
      }

      RouteType(const std::string& rtstr, const char *title = nullptr)
	: RouteType(RouteType::from_string(rtstr, title))
      {
      }

      RouteType(const std::string& rtstr, const std::string& title)
	: RouteType(RouteType::from_string(rtstr, title.c_str()))
      {
      }

      RouteType(const ADDR& addr_arg,
		const unsigned int prefix_len_arg)
	: addr(addr_arg),
	  prefix_len(prefix_len_arg)
      {
      }

      static RouteType from_string(const std::string& rtstr, const char *title = nullptr)
      {
	RouteType r;
	std::vector<std::string> pair;
	pair.reserve(2);
	Split::by_char_void<std::vector<std::string>, NullLex, Split::NullLimit>(pair, rtstr, '/', 0, 1);
	r.addr = ADDR::from_string(pair[0], title);
	if (pair.size() >= 2)
	  {
	    r.prefix_len = parse_number_throw<unsigned int>(pair[1], "prefix length");
	    if (r.prefix_len > r.addr.size())
	      OPENVPN_THROW(route_error, (title ? title : "route") << " : bad prefix length : " << rtstr);
	  }
	else
	  r.prefix_len = r.addr.size();
	return r;
      }

      IP::Addr::Version version() const
      {
	return addr.version();
      }

      IP::Addr::VersionMask version_mask() const
      {
	return addr.version_mask();
      }

      ADDR netmask() const
      {
	return ADDR::netmask_from_prefix_len(version(), prefix_len);
      }

      size_t extent() const
      {
	return netmask().extent_from_netmask().to_ulong();
      }

      bool is_canonical() const
      {
	return (addr & netmask()) == addr;
      }

      void force_canonical()
      {
	addr = addr & netmask();
      }

      bool is_host() const
      {
	return addr.defined() && prefix_len == addr.size();
      }

      unsigned int host_bits() const
      {
	if (prefix_len < addr.size())
	  return addr.size() - prefix_len;
	else
	  return 0;
      }

      bool contains(const ADDR& a) const // assumes canonical address/routes
      {
	if (addr.defined() && addr.version() == a.version())
	  return (a & netmask()) == addr;
	else
	  return false;
      }

      bool contains(const RouteType& r) const // assumes canonical routes
      {
	return contains(r.addr) && r.prefix_len >= prefix_len;
      }

      bool split(RouteType& r1, RouteType& r2) const // assumes we are canonical
      {
	if (!is_host())
	  {
	    const unsigned int newpl = prefix_len + 1;
	    r1.addr = addr;
	    r1.prefix_len = newpl;

	    r2.addr = addr + ADDR::netmask_from_prefix_len(addr.version(), newpl).extent_from_netmask();
	    r2.prefix_len = newpl;

	    return true;
	  }
	return false;
      }

      std::string to_string() const
      {
	return addr.to_string() + '/' + winfilter::to_string(prefix_len);
      }

      std::string to_string_by_netmask() const
      {
	return addr.to_string() + ' ' + netmask().to_string();
      }

      bool operator==(const RouteType& other) const
      {
	return prefix_len == other.prefix_len && addr == other.addr;
      }

      template <typename HASH>
      void hash(HASH& h) const
      {
	addr.hash(h);
	h(prefix_len);
      }

#ifdef HAVE_CITYHASH
      std::size_t hash_value() const
      {
	HashSizeT h;
	hash(h);
	return h.value();
      }
#endif
    };

    template <typename ADDR>
    struct RouteTypeList : public std::vector<RouteType<ADDR>>
    {
      typedef std::vector< RouteType<ADDR> > Base;

      OPENVPN_EXCEPTION(route_list_error);

      std::string to_string() const
      {
	std::ostringstream os;
	for (auto &r : *this)
	  os << r.to_string() << std::endl;
	return os.str();
      }

      IP::Addr::VersionMask version_mask() const
      {
	IP::Addr::VersionMask mask = 0;
	for (auto &r : *this)
	  mask |= r.version_mask();
	return mask;
      }

      void verify_canonical() const
      {
	for (auto &r : *this)
	  if (!r.is_canonical())
	    throw route_list_error("route not canonical: " + r.to_string());
      }

      template <typename R>
      bool contains(const R& c) const
      {
	for (auto &r : *this)
	  if (r.contains(c))
	    return true;
	return false;
      }
    };

    typedef RouteType<IP::Addr> Route;
    typedef RouteType<IPv4::Addr> Route4;
    typedef RouteType<IPv6::Addr> Route6;

    typedef RouteTypeList<IP::Addr> RouteList;
    typedef RouteTypeList<IPv4::Addr> Route4List;
    typedef RouteTypeList<IPv6::Addr> Route6List;

    OPENVPN_OSTREAM(Route, to_string);
    OPENVPN_OSTREAM(Route4, to_string);
    OPENVPN_OSTREAM(Route6, to_string);

    OPENVPN_OSTREAM(RouteList, to_string);
    OPENVPN_OSTREAM(Route4List, to_string);
    OPENVPN_OSTREAM(Route6List, to_string);

    inline Route route_from_string_prefix(const std::string& addrstr,
					  const unsigned int prefix_len,
					  const std::string& title,
					  const IP::Addr::Version required_version = IP::Addr::UNSPEC)
      {
	Route r;
	r.addr = IP::Addr(addrstr, title, required_version);
	r.prefix_len = prefix_len;
	if (r.prefix_len > r.addr.size())
	  OPENVPN_THROW(Route::route_error, title << " : bad prefix length : " << addrstr);
	return r;
      }

    inline Route route_from_string(const std::string& rtstr,
				   const std::string& title,
				   const IP::Addr::Version required_version = IP::Addr::UNSPEC)
    {
      Route r(rtstr, title);
      r.addr.validate_version(title, required_version);
      return r;
    }
  }
}

#ifdef HAVE_CITYHASH
OPENVPN_HASH_METHOD(openvpn::IP::Route, hash_value);
OPENVPN_HASH_METHOD(openvpn::IP::Route4, hash_value);
OPENVPN_HASH_METHOD(openvpn::IP::Route6, hash_value);
#endif

#endif
