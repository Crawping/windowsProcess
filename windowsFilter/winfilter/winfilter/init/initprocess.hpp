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

// Process-wide static initialization

#ifndef OPENVPN_INIT_INITPROCESS_H
#define OPENVPN_INIT_INITPROCESS_H

#include <thread>
#include <mutex>

#include <winfilter/common/size.hpp>
#include <winfilter/common/base64.hpp>
#include <winfilter/common/extern.hpp>
#include <winfilter/time/time.hpp>
#include <winfilter/compress/compress.hpp>
#include <winfilter/init/cryptoinit.hpp>
#include <winfilter/init/engineinit.hpp>

namespace winfilter {
  namespace InitProcess {

    class Init
    {
    public:
      Init()
      {
	// initialize time base
	Time::reset_base();

	// initialize compression
	CompressContext::init_static();

	// init OpenSSL if included
	init_openssl("auto");

	base64_init_static();
      }

      ~Init()
      {
	base64_uninit_static();
      }

    private:
      // initialize SSL library
      crypto_init crypto_init_;
    };

    // process-wide singular instance
    OPENVPN_EXTERN Init* the_instance; // GLOBAL
    OPENVPN_EXTERN std::mutex the_instance_mutex; // GLOBAL

    inline void init()
    {
      std::lock_guard<std::mutex> lock(the_instance_mutex);
      if (!the_instance)
	the_instance = new Init();
    }

    inline void uninit()
    {
      std::lock_guard<std::mutex> lock(the_instance_mutex);
      if (the_instance)
	{
	  delete the_instance;
	  the_instance = nullptr;
	}
    }

  }
}

#endif
