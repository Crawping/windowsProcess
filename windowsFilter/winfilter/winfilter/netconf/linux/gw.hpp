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

// Find default gateways on Linux using ip route command

#ifndef OPENVPN_NETCONF_LINUX_GW_H
#define OPENVPN_NETCONF_LINUX_GW_H

#include <string>
#include <limits>

#include <winfilter/common/exception.hpp>
#include <winfilter/common/number.hpp>
#include <winfilter/common/split.hpp>
#include <winfilter/common/splitlines.hpp>
#include <winfilter/common/process.hpp>
#include <winfilter/addr/route.hpp>

namespace winfilter {
  class LinuxGW
  {
  public:
    OPENVPN_EXCEPTION(linux_gw_error);

    LinuxGW(const std::string& ip_route_show_txt, const bool ignore_errors)
    {
      int best_metric = std::numeric_limits<int>::max();

      SplitLines sl(ip_route_show_txt);
      while (sl())
	{
	  const std::string& line = sl.line_ref();

	  try {
	    // parse an output line generated by "ip [-6] route show"
	    const std::vector<std::string> v = Split::by_space<std::vector<std::string>, NullLex, SpaceMatch, Split::NullLimit>(line);

	    // blank line?
	    if (v.empty())
	      continue;

	    // only interested in default routes
	    if (v[0] != "default")
	      continue;

	    // parse out route information
	    enum RouteInfo {
	      INITIAL,
	      VIA,
	      DEV,
	      METRIC,
	    };

	    std::string d;
	    IP::Addr a;
	    int m = std::numeric_limits<int>::max();

	    RouteInfo ri = INITIAL;
	    for (const auto &term : v)
	      {
		switch (ri)
		  {
		  case INITIAL:
		    if (term == "via")
		      ri = VIA;
		    else if (term == "dev")
		      ri = DEV;
		    else if (term == "metric")
		      ri = METRIC;
		    else
		      ri = INITIAL;
		    break;
		  case VIA:
		    a = IP::Addr(term, "via");
		    ri = INITIAL;
		    break;
		  case DEV:
		    d = validate_dev(term);
		    ri = INITIAL;
		    break;
		  case METRIC:
		    m = parse_number_throw<int>(term, "bad metric");
		    ri = INITIAL;
		    break;
		  }
	      }

	    // best metric?
	    if (m < best_metric || best_metric == std::numeric_limits<int>::max())
	      {
		best_metric = m;
		dev_ = d;
		addr_ = a;
	      }
	  }
	  catch (const std::exception& e)
	    {
	      if (!ignore_errors)
		OPENVPN_THROW(linux_gw_error, "error parsing line: " << line << " : " << e.what());
	    }
	}
    }

    static std::string ip_route_show(const bool ipv6)
    {
      RedirectPipe::InOut pipe;
      Argv argv;
      argv.emplace_back("/sbin/ip");
      if (ipv6)
	argv.emplace_back("-6");
      argv.emplace_back("route");
      argv.emplace_back("show");
      const int status = system_cmd(argv[0], argv, nullptr, pipe, false);
      if (status != 0)
	OPENVPN_THROW(linux_gw_error, "command returned error status " << status << " : " << argv.to_string());
      return pipe.out;
    }

    const std::string& dev() const
    {
      return dev_;
    }

    const IP::Addr& addr() const
    {
      return addr_;
    }

    bool defined() const
    {
      return !dev_.empty() && addr_.defined();
    }

    std::string to_string() const
    {
      return dev_ + '/' + addr_.to_string();
    }

  private:
    std::string validate_dev(const std::string& dev)
    {
      if (dev.empty())
	OPENVPN_THROW_EXCEPTION("dev is empty");
      return dev;
    }

    std::string dev_;
    IP::Addr addr_;
  };

  struct LinuxGW46
  {
    LinuxGW46(const bool ignore_errors)
      : v4(LinuxGW::ip_route_show(false), ignore_errors),
	v6(LinuxGW::ip_route_show(true), ignore_errors)
    {
    }

    std::string to_string() const
    {
      std::string ret = "[";
      if (v4.defined())
	{
	  ret += "4:";
	  ret += v4.to_string();
	}
      if (v6.defined())
	{
	  if (v4.defined())
	    ret += ' ';
	  ret += "6:";
	  ret += v6.to_string();
	}
      ret += "]";
      return ret;
    }

    std::string dev() const
    {
      if (v4.defined())
	return v4.dev();
      else if (v6.defined())
	return v6.dev();
      else
	throw LinuxGW::linux_gw_error("cannot determine gateway interface");
    }

    LinuxGW v4;
    LinuxGW v6;
  };
}

#endif
