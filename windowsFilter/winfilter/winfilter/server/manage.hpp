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

// Server-side client manager

#ifndef OPENVPN_SERVER_MANAGE_H
#define OPENVPN_SERVER_MANAGE_H

#include <string>
#include <vector>

#include <winfilter/common/size.hpp>
#include <winfilter/common/exception.hpp>
#include <winfilter/common/rc.hpp>
#include <winfilter/tun/server/tunbase.hpp>
#include <winfilter/addr/route.hpp>
#include <winfilter/auth/authcreds.hpp>
#include <winfilter/ssl/proto.hpp>
#include <winfilter/server/servhalt.hpp>
#include <winfilter/server/peerstats.hpp>
#include <winfilter/server/peeraddr.hpp>
#include <winfilter/auth/authcert.hpp>

namespace winfilter {
  namespace ManClientInstance {

    // Base class for the per-client-instance state of the ManServer.
    // Each client instance uses this class to send data to the man layer.
    struct Send : public virtual RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Send> Ptr;

      virtual void pre_stop() = 0;
      virtual void stop() = 0;

      virtual void auth_request(const AuthCreds::Ptr& auth_creds,
				const AuthCert::Ptr& auth_cert,
				const PeerAddr::Ptr& peer_addr) = 0;
      virtual void push_request(const ProtoContext::Config::Ptr& pconf) = 0;

      // INFO notification
      virtual void info_request(const std::string& imsg) = 0;

      // bandwidth stats notification
      virtual void stats_notify(const PeerStats& ps, const bool final) = 0;

      // client float notification
      virtual void float_notify(const PeerAddr::Ptr& addr) = 0;

      // ID
      virtual std::string instance_name() const = 0;
      virtual std::uint64_t instance_id() const = 0;

      // return a JSON string describing connected user
      virtual std::string describe_user() = 0;

      // disconnect
      virtual void disconnect_user(const HaltRestart::Type type,
				   const std::string& reason,
				   const bool tell_client) = 0;

      // send control channel message
      virtual void post_info_user(BufferPtr&& info) = 0;

      // set ACL index for user
      virtual void set_acl_index(const int acl_index,
				 const std::string* username,
				 const bool challenge,
				 const bool throw_on_error) = 0;
    };

    // Base class for the client instance receiver.  Note that all
    // client instance receivers (transport, routing, management,
    // etc.) must inherit virtually from RC because the client instance
    // object will inherit from multiple receivers.
    struct Recv : public virtual RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Recv> Ptr;

      virtual void stop() = 0;

      virtual void auth_failed(const std::string& reason,
			       const bool tell_client) = 0;

      virtual void push_reply(std::vector<BufferPtr>&& push_msgs) = 0;

      // push a halt or restart message to client
      virtual void push_halt_restart_msg(const HaltRestart::Type type,
					 const std::string& reason,
					 const bool tell_client) = 0;


      // send control channel message
      virtual void post_cc_msg(BufferPtr&& msg) = 0;

      // set up relay to target
      virtual void relay(const IP::Addr& target, const int port) = 0;

      // get client bandwidth stats
      virtual PeerStats stats_poll() = 0;

      // get native reference to client instance
      virtual TunClientInstance::NativeHandle tun_native_handle() = 0;
    };

    struct Factory : public RC<thread_unsafe_refcount>
    {
      typedef RCPtr<Factory> Ptr;

      virtual void start() = 0;

      virtual Send::Ptr new_obj(Recv* instance) = 0;
    };

  }
}

#endif