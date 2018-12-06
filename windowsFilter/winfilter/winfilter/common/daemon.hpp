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

#ifndef OPENVPN_COMMON_DAEMON_H
#define OPENVPN_COMMON_DAEMON_H

#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <winfilter/common/size.hpp>
#include <winfilter/common/exception.hpp>
#include <winfilter/common/to_string.hpp>
#include <winfilter/common/file.hpp>
#include <winfilter/common/logrotate.hpp>
#include <winfilter/common/redir.hpp>
#include <winfilter/common/usergroup.hpp>

namespace winfilter {

  OPENVPN_EXCEPTION(daemon_err);

  inline void log_setup(const std::string& log_fn,
			const SetUserGroup* user_group,
			const bool log_append,
			const int log_versions,
			const bool stdin_to_dev_null,
			const bool combine_out_err)
  {
    if (!log_append && log_versions >= 1)
      log_rotate(log_fn, log_versions);
    RedirectStd redir(stdin_to_dev_null ? "/dev/null" : "",
		      log_fn,
		      log_append ? RedirectStd::FLAGS_APPEND : RedirectStd::FLAGS_OVERWRITE,
		      RedirectStd::MODE_USER_GROUP,
		      combine_out_err);
    // if user_group specified, do chown on log file
    try {
      if (user_group && redir.out.defined())
	user_group->chown(redir.out(), log_fn);
    }
    catch (const std::exception&)
      {
      }
    redir.redirect();
  }

  inline void daemonize()
  {
    if (daemon(1, 1) < 0)
      throw daemon_err("daemon() failed");
  }

  inline void daemonize(const std::string& log_fn,
			const SetUserGroup* user_group,
			const bool log_append,
			const int log_versions)
  {
    log_setup(log_fn, user_group, log_append, log_versions, true, true);
    daemonize();
  }

  inline void write_pid(const std::string& fn)
  {
    write_string(fn, to_string(::getpid()) + '\n');
  }
}

#endif