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

// TCP transport object specialized for client.

#ifndef OPENVPN_TRANSPORT_CLIENT_TCPCLI_H
#define OPENVPN_TRANSPORT_CLIENT_TCPCLI_H

#include <sstream>

#include <winfilter/io/io.hpp>

#include <winfilter/transport/tcplink.hpp>
#include <winfilter/transport/client/transbase.hpp>
#include <winfilter/transport/socket_protect.hpp>
#include <winfilter/client/remotelist.hpp>

namespace winfilter {
  namespace TCPTransport {

    class ClientConfig : public TransportClientFactory
    {
    public:
      typedef RCPtr<ClientConfig> Ptr;

      RemoteList::Ptr remote_list;
      size_t free_list_max_size;
      Frame::Ptr frame;
      SessionStats::Ptr stats;

      SocketProtect* socket_protect;

#ifdef OPENVPN_GREMLIN
      Gremlin::Config::Ptr gremlin_config;
#endif
	  unsigned int socket_recv_buf_size;
	  unsigned int socket_send_buf_size;

      static Ptr new_obj()
      {
	return new ClientConfig;
      }

      virtual TransportClient::Ptr new_transport_client_obj(openvpn_io::io_context& io_context,
							    TransportClientParent* parent);

    private:
      ClientConfig()
	: free_list_max_size(8),
	  socket_protect(nullptr)
      {}
    };

    class Client : public TransportClient
    {
      typedef RCPtr<Client> Ptr;

      typedef Link<openvpn_io::ip::tcp, Client*, false> LinkImpl;

      friend class ClientConfig;         // calls constructor
      friend LinkImpl;                   // calls tcp_read_handler

    public:
      virtual void transport_start()
      {
	if (!impl)
	  {
	    halt = false;
	    if (config->remote_list->endpoint_available(&server_host, &server_port, nullptr))
	      {
		start_connect_();
	      }
	    else
	      {
		parent->transport_pre_resolve();
		resolver.async_resolve(server_host, server_port,
				       [self=Ptr(this)](const openvpn_io::error_code& error, openvpn_io::ip::tcp::resolver::results_type results)
				       {
					 self->do_resolve_(error, results);
				       });
	      }
	  }
      }

      virtual bool transport_send_const(const Buffer& buf)
      {
	return send_const(buf);
      }

      virtual bool transport_send(BufferAllocated& buf)
      {
	return send(buf);
      }

      virtual bool transport_send_queue_empty()
      {
	if (impl)
	  return impl->send_queue_empty();
	else
	  return false;
      }

      virtual bool transport_has_send_queue()
      {
	return true;
      }

      virtual unsigned int transport_send_queue_size()
      {
	if (impl)
	  return impl->send_queue_size();
	else
	  return 0;
      }

      virtual void reset_align_adjust(const size_t align_adjust)
      {
	if (impl)
	  impl->reset_align_adjust(align_adjust);
      }

      virtual void server_endpoint_info(std::string& host, std::string& port, std::string& proto, std::string& ip_addr) const
      {
	host = server_host;
	port = server_port;
	const IP::Addr addr = server_endpoint_addr();
	proto = "TCP";
	proto += addr.version_string();
	ip_addr = addr.to_string();
      }

      virtual IP::Addr server_endpoint_addr() const
      {
	return IP::Addr::from_asio(server_endpoint.address());
      }

      virtual Protocol transport_protocol() const
      {
	if (server_endpoint.address().is_v4())
	  return Protocol(Protocol::TCPv4);
	else if (server_endpoint.address().is_v6())
	  return Protocol(Protocol::TCPv6);
	else
	  return Protocol();
      }

      virtual void stop() { stop_(); }
      virtual ~Client() { stop_(); }

    private:
      Client(openvpn_io::io_context& io_context_arg,
	     ClientConfig* config_arg,
	     TransportClientParent* parent_arg)
	:  io_context(io_context_arg),
	   socket(io_context_arg),
	   config(config_arg),
	   parent(parent_arg),
	   resolver(io_context_arg),
	   halt(false)
      {
      }

      virtual void transport_reparent(TransportClientParent* parent_arg)
      {
	parent = parent_arg;
      }

      bool send_const(const Buffer& cbuf)
      {
	if (impl)
	  {
	    BufferAllocated buf(cbuf, 0);
	    return impl->send(buf);
	  }
	else
	  return false;
      }

      bool send(BufferAllocated& buf)
      {
	if (impl)
	  return impl->send(buf);
	else
	  return false;
      }

      void tcp_eof_handler() // called by LinkImpl
      {
	config->stats->error(Error::NETWORK_EOF_ERROR);
	tcp_error_handler("NETWORK_EOF_ERROR");
      }

      bool tcp_read_handler(BufferAllocated& buf) // called by LinkImpl
      {
	parent->transport_recv(buf);
	return true;
      }

      void tcp_write_queue_needs_send() // called by LinkImpl
      {
	parent->transport_needs_send();
      }

      void tcp_error_handler(const char *error) // called by LinkImpl
      {
	std::ostringstream os;
	os << "Transport error on '" << server_host << ": " << error;
	stop();
	parent->transport_error(Error::TRANSPORT_ERROR, os.str());
      }

      void stop_()
      {
	if (!halt)
	  {
	    halt = true;
	    if (impl)
	      impl->stop();

	    socket.close();
	    resolver.cancel();
	  }
      }

      // do DNS resolve
      void do_resolve_(const openvpn_io::error_code& error,
		       openvpn_io::ip::tcp::resolver::results_type results)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		// save resolved endpoint list in remote_list
		config->remote_list->set_endpoint_range(results);
		start_connect_();
	      }
	    else
	      {
		std::ostringstream os;
		os << "DNS resolve error on '" << server_host << "' for TCP session: " << error.message();
		config->stats->error(Error::RESOLVE_ERROR);
		stop();
		parent->transport_error(Error::UNDEF, os.str());
	      }
	  }
      }

      // do TCP connect
      void start_connect_()
      {
	config->remote_list->get_endpoint(server_endpoint);
	OPENVPN_LOG("Contacting " << server_endpoint << " via TCP");
	parent->transport_wait();
	parent->ip_hole_punch(server_endpoint_addr());
	socket.open(server_endpoint.protocol());
#ifdef OPENVPN_PLATFORM_TYPE_UNIX
	if (config->socket_protect)
	  {
	    if (!config->socket_protect->socket_protect(socket.native_handle()))
	      {
		config->stats->error(Error::SOCKET_PROTECT_ERROR);
		stop();
		parent->transport_error(Error::UNDEF, "socket_protect error (TCP)");
		return;
	      }
	  }
#endif
	socket.set_option(openvpn_io::ip::tcp::no_delay(true));
	socket.async_connect(server_endpoint, [self=Ptr(this)](const openvpn_io::error_code& error)
                                              {
                                                self->start_impl_(error);
                                              });
      }

      // start I/O on TCP socket
      void start_impl_(const openvpn_io::error_code& error)
      {
	if (!halt)
	  {
	    if (!error)
	      {
		impl.reset(new LinkImpl(this,
					socket,
					0, // // send_queue_max_size is unlimited because we regulate size in cliproto.hpp
					config->free_list_max_size,
					(*config->frame)[Frame::READ_LINK_TCP],
					config->stats));
#ifdef OPENVPN_GREMLIN
		impl->gremlin_config(config->gremlin_config);
#endif
		impl->start();
		if (!parent->transport_is_openvpn_protocol())
		  impl->set_raw_mode(true);
		parent->transport_connecting();
	      }
	    else
	      {
		std::ostringstream os;
		os << "TCP connect error on '" << server_host << ':' << server_port << "' (" << server_endpoint << "): " << error.message();
		config->stats->error(Error::TCP_CONNECT_ERROR);
		stop();
		parent->transport_error(Error::UNDEF, os.str());
	      }
	  }
      }

      std::string server_host;
      std::string server_port;

      openvpn_io::io_context& io_context;
      openvpn_io::ip::tcp::socket socket;
      ClientConfig::Ptr config;
      TransportClientParent* parent;
      LinkImpl::Ptr impl;
      openvpn_io::ip::tcp::resolver resolver;
      LinkImpl::protocol::endpoint server_endpoint;
      bool halt;
    };

    inline TransportClient::Ptr ClientConfig::new_transport_client_obj(openvpn_io::io_context& io_context,
								       TransportClientParent* parent)
    {
      return TransportClient::Ptr(new Client(io_context, this, parent));
    }
  }
} // namespace openvpn

#endif
