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

// A 64-bit session ID, used by ProtoContext.

#ifndef OPENVPN_SSL_PSID_H
#define OPENVPN_SSL_PSID_H

#include <string>
#include <cstring>

#include <winfilter/buffer/buffer.hpp>
#include <winfilter/common/hexstr.hpp>
#include <winfilter/common/memneq.hpp>

namespace winfilter {

  class ProtoSessionID
  {
  public:
    enum {
      SIZE=8
    };

    ProtoSessionID()
    {
      reset();
    }

    void reset()
    {
      defined_ = false;
      std::memset(id_, 0, SIZE);
    }

    explicit ProtoSessionID(Buffer& buf)
    {
      buf.read(id_, SIZE);
      defined_ = true;
    }

    template <typename PRNG_TYPE>
    void randomize(PRNG_TYPE& prng)
    {
      prng.assert_crypto();
      prng.rand_bytes(id_, SIZE);
      defined_ = true;
    }

    void read(Buffer& buf)
    {
      buf.read(id_, SIZE);
      defined_ = true;
    }

    void write(Buffer& buf) const
    {
      buf.write(id_, SIZE);
    }

    void prepend(Buffer& buf) const
    {
      buf.prepend(id_, SIZE);
    }

    bool defined() const { return defined_; }

    bool match(const ProtoSessionID& other) const
    {
      return defined_ && other.defined_ && !crypto::memneq(id_, other.id_, SIZE);
    }

    std::string str() const
    {
      return render_hex(id_, SIZE);
    }

  protected:
    ProtoSessionID(const unsigned char *data)
    {
      std::memcpy(id_, data, SIZE);
    }

  private:
    bool defined_;
    unsigned char id_[SIZE];
  };
} // namespace openvpn

#endif // OPENVPN_SSL_PSID_H
