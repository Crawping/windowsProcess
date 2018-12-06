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

// General-purpose classes for instantiating a posix process with arguments.

#ifndef OPENVPN_COMMON_PROCESS_H
#define OPENVPN_COMMON_PROCESS_H

#include <stdlib.h>    // exit
#include <unistd.h>    // fork, execve
#include <sys/types.h> // waitpid
#include <sys/wait.h>  // waitpid

#include <string>
#include <memory>
#include <utility>

#include <winfilter/common/action.hpp>
#include <winfilter/common/redir.hpp>
#include <winfilter/common/signal.hpp>
#include <winfilter/common/argv.hpp>
#include <winfilter/common/environ.hpp>

namespace winfilter {

  // low-level fork/exec (async)
  inline pid_t system_cmd_async(const std::string& cmd,
				const Argv& argv,
				const Environ* env,
				RedirectBase* redir)
  {
    ArgvWrapper argv_wrap(argv);
    std::unique_ptr<ArgvWrapper> env_wrap;
    if (env)
      env_wrap.reset(new ArgvWrapper(*env));
    auto fn = cmd.c_str();
    auto av = argv_wrap.c_argv();
    auto ev = env_wrap ? env_wrap->c_argv() : ::environ;
    const pid_t pid = redir ? ::fork() : ::vfork();
    if (pid == pid_t(0)) /* child side */
      {
	if (redir)
	  redir->redirect();
	::execve(fn, av, ev);
	::_exit(127);
      }
    else if (pid < pid_t(0)) /* fork failed */
      return -1;
    else /* parent side */
      {
	if (redir)
	  redir->close();
	return pid;
      }
  }

  // completion for system_cmd_async()
  inline int system_cmd_post(const pid_t pid)
  {
    int status = -1;
    if (::waitpid(pid, &status, 0) == pid)
      {
	if (WIFEXITED(status))
	  return WEXITSTATUS(status);
      }
    return -1;
  }

  // synchronous version of system_cmd_async
  inline int system_cmd(const std::string& cmd,
			const Argv& argv,
			RedirectBase* redir,
			const Environ* env)
  {
    const pid_t pid = system_cmd_async(cmd, argv, env, redir);
    if (pid < pid_t(0))
      return -1;
    return system_cmd_post(pid);
  }

  // simple command execution
  inline int system_cmd(const std::string& cmd, const Argv& argv)
  {
    return system_cmd(cmd, argv, nullptr, nullptr);
  }

  // simple command execution
  inline int system_cmd(const Argv& argv)
  {
    int ret = -1;
    if (argv.size())
      ret = system_cmd(argv[0], argv);
    return ret;
  }

  // command execution with std::strings as
  // input/output/error (uses pipes under the
  // hood)
  inline int system_cmd(const std::string& cmd,
			const Argv& argv,
			const Environ* env,
			RedirectPipe::InOut& inout,
			const bool combine_out_err)
  {
    SignalBlockerPipe sbpipe;
    RedirectPipe remote;
    RedirectPipe local(remote, combine_out_err, !inout.in.empty());
    const pid_t pid = system_cmd_async(cmd, argv, env, &remote);
    if (pid < pid_t(0))
      return -1;
    local.transact(inout);
    return system_cmd_post(pid);
  }

  struct Command : public Action
  {
    typedef RCPtr<Command> Ptr;

    Command() {}

    Command(Argv argv_arg)
      : argv(std::move(argv_arg))
    {
    }

    Command* copy() const
    {
      Command* ret = new Command;
      ret->argv = argv;
      return ret;
    }

    virtual void execute(std::ostream& os) override
    {
      if (!argv.empty())
	{
	  os << to_string() << std::endl;
#ifdef OPENVPN_PROCESS_AVOID_PIPES
	  const int status = system_cmd(argv[0], argv);
	  if (status < 0)
	    os << "Error: command failed to execute" << std::endl;
#else
	  RedirectPipe::InOut inout;
	  const int status = system_cmd(argv[0], argv, nullptr, inout, true);
	  if (status < 0)
	    os << "Error: command failed to execute" << std::endl;
	  os << inout.out;
#endif
	}
      else
	os << "Error: command called with empty argv" << std::endl;
    }

    virtual std::string to_string() const override
    {
      return argv.to_string();
    }

    Argv argv;
  };

}

#endif // OPENVPN_COMMON_PROCESS_H
